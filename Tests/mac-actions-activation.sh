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
args=sys.argv[1:];method=args[args.index('--method')+1];path=next(x for x in args if x=='user' or x.startswith('repos/')); root='repos/owner/fixture'
body=json.load(sys.stdin) if method!='GET' else None
with open(os.environ['FIXTURE_LOG'],'a') as f:f.write(json.dumps({'method':method,'path':path,'body':body})+'\n')
mode=os.environ.get('FIXTURE_MODE','stable');state=json.load(open(os.environ['FIXTURE_STATE']))
policy={'id':7,'name':'repoctl/v1/actions','enforcement':'active','conditions':{'workflow_path':{'include':['~ALL'],'exclude':[]}},'rules':[{'type':'restrict_actions_actors','parameters':{'allowed_actors':[{'id':100,'type':'User'}]}},{'type':'restrict_action_events','parameters':{'allowed_events':['push','workflow_dispatch','workflow_call']}}]}
if path=='user':result={'id':100}
elif path==root:result={'id':101,'owner':{'id':100,'type':'User'},'permissions':{'admin':True}}
elif path.startswith(root+'/actions/policies?'):result={'policies':[{'id':7,'name':'repoctl/v1/actions','source_type':'Repository','source':'owner/fixture'}]}
elif path==root+'/actions/policies/7':
 result=policy
 if mode=='policy-drift' and state['workflow_written']:result['rules'][0]['parameters']['allowed_actors'].append({'id':999,'type':'User'})
elif path==root+'/actions/permissions/workflow':
 if method=='PUT':
  if mode=='workflow-failure':sys.exit('FIXTURE_PROVIDER_SECRET')
  assert body=={'default_workflow_permissions':'read','can_approve_pull_request_reviews':False}
  state['workflow_written']=True;state['workflow']=body;result={}
 else:
  result=state['workflow']
  if mode=='readback-drift':result={**result,'default_workflow_permissions':'write'}
elif path==root+'/actions/permissions':
 if method=='PUT':
  assert body=={'enabled':True}
  assert state['workflow_written'] and state['workflow']['default_workflow_permissions']=='read' and not state['workflow']['can_approve_pull_request_reviews']
  state['permissions']['enabled']=True;result={}
  if mode=='enable-failure':sys.exit('FIXTURE_PROVIDER_SECRET')
 else:result=state['permissions']
else:sys.exit('Unexpected fixture request')
json.dump(state,open(os.environ['FIXTURE_STATE'],'w'));print(json.dumps(result))
PY
chmod +x "$task_dir/gh"
export PATH="$task_dir:$PATH" FIXTURE_LOG="$task_dir/calls" FIXTURE_STATE="$task_dir/state.json"
for mode in stable workflow-failure readback-drift policy-drift enable-failure; do
 : > "$FIXTURE_LOG"
 printf '{"workflow_written":false,"workflow":{"default_workflow_permissions":"write","can_approve_pull_request_reviews":true},"permissions":{"enabled":false,"allowed_actions":"selected"}}\n' > "$FIXTURE_STATE"
 if FIXTURE_MODE="$mode" "$bin" actions apply owner/fixture > "$task_dir/result" 2>&1; then
  [[ "$mode" == stable ]] || { echo "Accepted $mode" >&2; exit 1; }
 else
  [[ "$mode" != stable ]] || { cat "$task_dir/result" >&2; exit 1; }
 fi
 if /usr/bin/grep -q FIXTURE_PROVIDER_SECRET "$task_dir/result"; then echo 'Provider error disclosed' >&2; exit 1; fi
 python3 - "$FIXTURE_LOG" "$FIXTURE_STATE" "$mode" <<'PY'
import json,sys
calls=[json.loads(s) for s in open(sys.argv[1])];state=json.load(open(sys.argv[2]));mode=sys.argv[3];root='repos/owner/fixture'
writes=[c for c in calls if c['method']!='GET'];assert all(c['method']=='PUT' for c in writes)
workflow=[i for i,c in enumerate(calls) if c['method']=='PUT' and c['path']==root+'/actions/permissions/workflow'];enabled=[i for i,c in enumerate(calls) if c['method']=='PUT' and c['path']==root+'/actions/permissions']
assert len(workflow)==1
if mode in ('stable','enable-failure'):
 assert len(enabled)==1 and workflow[0]<enabled[0]
 between=calls[workflow[0]+1:enabled[0]]
 assert any(c['method']=='GET' and c['path']==root+'/actions/permissions/workflow' for c in between)
 assert any(c['method']=='GET' and c['path']==root+'/actions/policies/7' for c in between)
else:assert not enabled
assert state['permissions']['allowed_actions']=='selected'
if mode=='stable':assert state['permissions']['enabled'] and state['workflow']['default_workflow_permissions']=='read'
PY
 echo "PASS: $mode activation ordering, bounded writes and allowlist preservation"
done
