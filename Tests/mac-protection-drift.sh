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
args=sys.argv[1:]; method=args[args.index('--method')+1]
path=next(x for x in args if x=='user' or x.startswith(('repos/','apps/')))
with open(os.environ['FIXTURE_LOG'],'a') as f:f.write(method+' '+path+'\n')
if method!='GET':sys.exit('Unexpected mutation')
f=json.load(open(os.environ['FIXTURE_DATA']))
if path in f:print(json.dumps(f[path]));sys.exit()
if path.startswith('repos/owner/fixture/rulesets?'):
 print(json.dumps([dict(r,id=i,source_type='Repository',source='owner/fixture') for i,r in enumerate(f['rules'],1)]));sys.exit()
if path.startswith('repos/owner/fixture/rulesets/'):
 print(json.dumps(f['rules'][int(path.rsplit('/',1)[1])-1]));sys.exit()
sys.exit('Unexpected fixture path')
PY
chmod +x "$task_dir/gh"
export PATH="$task_dir:$PATH" FIXTURE_DATA="$task_dir/data.json" FIXTURE_LOG="$task_dir/calls"
python3 - "$FIXTURE_DATA" <<'PY'
import json,sys
repo='repos/owner/fixture'
f={'user':{'id':100},repo:{'id':101,'owner':{'type':'User','id':100},'permissions':{'admin':True},'default_branch':'main','fork':False,'archived':False},'apps/writer':{'id':200,'slug':'writer','permissions':{'contents':'write'}},'apps/runner':{'id':201},repo+'/branches/main':{},repo+'/actions/permissions':{'enabled':True},repo+'/immutable-releases':{'enabled':True},repo+'/actions/permissions/workflow':{'default_workflow_permissions':'read','can_approve_pull_request_reviews':False},repo+'/actions/policies?per_page=100&page=1&has_parents=true':{'policies':[{'id':7,'name':'repoctl/v1/actions','source_type':'Repository','source':'owner/fixture'}]},repo+'/actions/policies/7':{'name':'repoctl/v1/actions','enforcement':'active','conditions':{'workflow_path':{'include':['~ALL'],'exclude':[]}},'rules':[{'type':'restrict_actions_actors','parameters':{'allowed_actors':[{'id':100,'type':'User'}]}},{'type':'restrict_action_events','parameters':{'allowed_events':['push','workflow_dispatch','workflow_call']}}]}}
json.dump(f,open(sys.argv[1],'w'))
PY
"$bin" protect plan owner/fixture --writer-app writer > "$task_dir/plan.json"
python3 - "$FIXTURE_DATA" "$task_dir/plan.json" <<'PY'
import json,sys
f=json.load(open(sys.argv[1]));f['rules']=json.load(open(sys.argv[2]))['rulesets'];json.dump(f,open(sys.argv[1],'w'))
PY
cp "$FIXTURE_DATA" "$task_dir/baseline.json"
"$bin" protect verify owner/fixture --writer-app writer
for mode in events actor workflow inherited duplicate; do
 python3 - "$task_dir/baseline.json" "$FIXTURE_DATA" "$mode" <<'PY'
import json,sys
f=json.load(open(sys.argv[1])); mode=sys.argv[3];base='repos/owner/fixture';p=f[base+'/actions/policies/7'];inventory=f[base+'/actions/policies?per_page=100&page=1&has_parents=true']['policies']
if mode=='events':p['rules'][1]['parameters']['allowed_events'].append('pull_request_target')
if mode=='actor':p['rules'][0]['parameters']['allowed_actors'].append({'id':999,'type':'User'})
if mode=='workflow':f[base+'/actions/permissions/workflow']['default_workflow_permissions']='write'
if mode=='inherited':inventory[0]['source_type']='Organization'
if mode=='duplicate':inventory.append(dict(inventory[0],id=8))
json.dump(f,open(sys.argv[2],'w'))
PY
 : > "$FIXTURE_LOG"
 if "$bin" protect apply owner/fixture --writer-app writer > "$task_dir/result" 2>&1; then echo "Drift accepted: $mode" >&2; exit 1; fi
 if /usr/bin/grep -Eq '^(POST|PATCH|PUT|DELETE) ' "$FIXTURE_LOG"; then echo 'Mutation before drift rejection' >&2; exit 1; fi
 echo "PASS: $mode drift blocked before mutation"
done
python3 - "$task_dir/baseline.json" "$FIXTURE_DATA" <<'PY'
import json,sys
f=json.load(open(sys.argv[1]));f['repos/owner/fixture/actions/policies/7']['rules'][0]['parameters']['allowed_actors'].append({'id':201,'type':'App'});json.dump(f,open(sys.argv[2],'w'))
PY
if "$bin" protect verify owner/fixture --writer-app writer > "$task_dir/result" 2>&1; then echo 'Unselected Actions App accepted' >&2; exit 1; fi
"$bin" protect verify owner/fixture --writer-app writer --actions-app runner
printf 'PASS: explicitly selected Actions App verified; owner-only default enforced\n'
