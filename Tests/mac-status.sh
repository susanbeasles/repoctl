#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
swift build
bin="$(swift build --show-bin-path)/repoctl"
task_dir=$(mktemp -d)
trap 'rm -rf "$task_dir"' EXIT
cat > "$task_dir/gh" <<'PY'
#!/usr/bin/env python3
import json,os,sys
args=sys.argv[1:];method=args[args.index('--method')+1]
path=next(x for x in args if x=='user' or x.startswith('repos/'))
with open(os.environ['FIXTURE_LOG'],'a') as f:f.write(method+' '+path+'\n')
if method!='GET':sys.exit('Unexpected mutation')
mode=os.environ.get('FIXTURE_MODE','stable'); root='repos/owner/fixture'
metadata={'id':101,'full_name':'owner/fixture','owner':{'id':100,'type':'User'},'default_branch':'main','archived':False,'fork':False}
if path=='user': result={'id':999 if mode=='foreign-owner' else 100}
elif path==root:
 calls=open(os.environ['FIXTURE_LOG']).read().splitlines().count('GET '+root)
 if mode=='identity-drift' and calls>1:metadata['id']=102
 if mode=='wrong-name':metadata['full_name']='other/fixture'
 result=metadata
elif path==root+'/git/ref/heads/main':
 calls=open(os.environ['FIXTURE_LOG']).read().splitlines().count('GET '+path)
 result={'ref':'refs/heads/main','object':{'type':'commit','sha':('b' if mode=='tip-drift' and calls>1 else 'a')*40}}
elif path.startswith(root+'/rulesets?'):
 if mode=='denied':sys.exit('DO_NOT_PRINT_THIS_PROVIDER_SECRET')
 result=[{'id':7,'name':'managed','target':'branch','source_type':'Repository','source':'owner/fixture','enforcement':'active'}]
 if mode=='inventory-limit':result*=100
elif path.startswith(root+'/actions/policies?'): result={'policies':[{'id':8,'name':'managed-actions','source_type':'Repository','source':'owner/fixture','enforcement':'active'}]}
elif path==root+'/actions/permissions':result={'enabled':True,'allowed_actions':'selected'}
elif path==root+'/actions/permissions/workflow':result={'default_workflow_permissions':'read','can_approve_pull_request_reviews':False}
elif path==root+'/immutable-releases':result={'enabled':True}
else:sys.exit('Unexpected fixture path')
print(json.dumps(result))
PY
chmod +x "$task_dir/gh"
export PATH="$task_dir:$PATH" FIXTURE_LOG="$task_dir/calls"
: > "$FIXTURE_LOG"
"$bin" status owner/fixture > "$task_dir/result.json"
python3 - "$task_dir/result.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]));assert r['repository_id']==101 and r['default_tip']=='a'*40
assert r['qualification']=='observed-not-verified' and r['controller_evidence']['state']=='unavailable'
assert r['immutable_releases']['enabled'] and r['rulesets'][0]['id']==7
assert r['actions_permissions']['allowed_actions']=='selected'
PY
printf '{"repository":"owner/fixture"}\n' > "$task_dir/.repoctl.json"
(cd "$task_dir"; "$bin" status > config-result.json)
cmp "$task_dir/result.json" "$task_dir/config-result.json"
for mode in foreign-owner wrong-name identity-drift tip-drift denied inventory-limit; do
 : > "$FIXTURE_LOG"
 if FIXTURE_MODE="$mode" "$bin" status owner/fixture > "$task_dir/failed-result" 2>&1; then echo "Accepted $mode" >&2; exit 1; fi
 if /usr/bin/grep -q DO_NOT_PRINT_THIS_PROVIDER_SECRET "$task_dir/failed-result"; then echo 'Provider stderr leaked' >&2; exit 1; fi
 if /usr/bin/grep -Eq '^(POST|PATCH|PUT|DELETE) ' "$FIXTURE_LOG"; then echo 'Status mutated repository' >&2; exit 1; fi
 echo "PASS: $mode denied without mutation or stderr disclosure"
done
: > "$FIXTURE_LOG"
if "$bin" status owner/fixture extra > "$task_dir/failed-result" 2>&1; then exit 1; fi
[[ ! -s "$FIXTURE_LOG" ]] || { echo 'Invalid args accessed provider' >&2; exit 1; }
echo 'PASS: native status and configured default target; unavailable authority explicitly reported'
