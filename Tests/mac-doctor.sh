#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
task_dir=$(mktemp -d)
trap 'rm -rf "$task_dir"' EXIT
cat > "$task_dir/main.swift" <<'SWIFT'
import Foundation
import Security
struct Failure: Error, CustomStringConvertible { let description: String; init(_ message: String) { description = message } }
func require(_ condition: Bool, _ message: String) throws { if !condition { throw Failure(message) } }
func account(_ path: String) -> String { path }
// In-memory software enrollment is a fixture, never a production fallback.
var fixtureTrust: Trust?
func readTrust(_ path: String) throws -> Trust? { fixtureTrust }
do {
 let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
 var error: Unmanaged<CFError>?
 let attrs: [String: Any] = [kSecAttrKeyType as String:kSecAttrKeyTypeECSECPrimeRandom,kSecAttrKeySizeInBits as String:256]
 guard let key = SecKeyCreateRandomKey(attrs as CFDictionary,&error), let publicKey = SecKeyCopyPublicKey(key),
       let pub = SecKeyCopyExternalRepresentation(publicKey,&error),
       let signature = SecKeyCreateSignature(key,.ecdsaSignatureMessageX962SHA256,payload(data,revision:1) as CFData,&error) else { throw Failure("Fixture signer failed") }
 fixtureTrust=Trust(format:1,provider:"fixture-software",publicKey:pub as Data,revision:1,acceptedSignature:signature as Data)
 try JSONEncoder().encode(Seal(format:1,revision:1,signature:signature as Data)).write(to:URL(fileURLWithPath:CommandLine.arguments[1]+".seal.json"))
 try doctorCommand(["doctor","--baseline",CommandLine.arguments[1]])
 print("PASS: native doctor command with ephemeral signed software fixture")
} catch { FileHandle.standardError.write(Data("\(error)\n".utf8)); exit(1) }
SWIFT
swiftc Sources/repoctl/GitHubClient.swift Sources/repoctl/RepositoryCommands.swift Sources/repoctl/ActionsCommands.swift Sources/repoctl/DoctorCommands.swift Sources/repoctl/PolicyVerification.swift "$task_dir/main.swift" -o "$task_dir/compare"
python3 - "$task_dir/baseline.json" <<'PY'
import json,sys
rule={'name':'repoctl/v1/protected','target':'branch','enforcement':'active','conditions':{'ref_name':{'include':['~DEFAULT_BRANCH'],'exclude':[]}},'rules':[{'type':'required_signatures'}],'bypass_actors':[]}
policy={'name':'repoctl/v1/actions','enforcement':'active','conditions':{'workflow_path':{'include':['~ALL'],'exclude':[]}},'rules':[{'type':'restrict_actions_actors','parameters':{'allowed_actors':[{'type':'User','id':100}]}},{'type':'restrict_action_events','parameters':{'allowed_events':['push']}}]}
b={'protocol':'repoctl-repository-baseline-v1','repository':'owner/fixture','repository_id':101,'owner_id':100,'default_branch':'main','settings':{'fork':False,'archived':False,'allow_auto_merge':False,'delete_branch_on_merge':False},'rulesets':[{'id':7,'source':'owner/fixture','source_type':'Repository','body':rule}],'actions_policies':[{'id':8,'source':'owner/fixture','source_type':'Repository','body':policy}],'actions_permissions':{'enabled':True,'allowed_actions':'selected'},'selected_actions':{'github_owned_allowed':True,'verified_allowed':False,'patterns_allowed':['owner/action@'+'a'*40]},'workflow_permissions':{'default_workflow_permissions':'read','can_approve_pull_request_reviews':False},'immutable_releases':{'enabled':True,'enforced_by_owner':False}}
json.dump(b,open(sys.argv[1],'w'))
PY
cat > "$task_dir/gh" <<'PY'
#!/usr/bin/env python3
import json,os,sys
args=sys.argv[1:];method=args[args.index('--method')+1];path=next(x for x in args if x=='user' or x.startswith('repos/'))
with open(os.environ['FIXTURE_LOG'],'a') as f:f.write(method+' '+path+'\n')
if method!='GET':sys.exit('Unexpected mutation')
b=json.load(open(os.environ['FIXTURE_BASELINE']));mode=os.environ.get('FIXTURE_MODE','stable');root='repos/owner/fixture'
if path=='user':result={'id':999 if mode=='foreign-owner' else 100}
elif path==root:
 result={'id':101,'full_name':'owner/fixture','owner':{'id':100,'type':'User'},'default_branch':'main',**b['settings']}
 if mode=='settings':result['allow_auto_merge']=True
 if mode=='identity-drift' and open(os.environ['FIXTURE_LOG']).read().splitlines().count('GET '+root)>1:result['id']=102
 if mode=='baseline-drift' and open(os.environ['FIXTURE_LOG']).read().splitlines().count('GET '+root)>1:
  b['owner_id']=999;json.dump(b,open(os.environ['FIXTURE_BASELINE'],'w'))
elif path.startswith(root+'/rulesets?'):
 result=[{'id':7,'source':'owner/fixture','source_type':'Repository'}]
 if mode=='inherited':result[0]['source_type']='Organization'
 if mode=='new-rule':result.append({'id':9,'source':'owner/fixture','source_type':'Repository'})
 if mode=='denied':sys.exit('DO_NOT_PRINT_PROVIDER_SECRET')
elif path.startswith(root+'/rulesets/'):result={'id':int(path.rsplit('/',1)[1]),**b['rulesets'][0]['body']};result['rules']=[] if mode=='rule-body' else result['rules']
elif path.startswith(root+'/actions/policies?'):result={'policies':[{'id':8,'source':'owner/fixture','source_type':'Repository'}]}
elif path==root+'/actions/policies/8':
 result={'id':8,**b['actions_policies'][0]['body']}
 if mode=='detail-id':result['id']=999
 if mode=='events':result['rules'][1]['parameters']['allowed_events'].append('pull_request_target')
elif path==root+'/actions/permissions':result=b['actions_permissions']
elif path==root+'/actions/permissions/selected-actions':
 result=b['selected_actions']
 if mode=='allowlist':result['patterns_allowed'].append('*')
elif path==root+'/actions/permissions/workflow':result=b['workflow_permissions'];result['default_workflow_permissions']='write' if mode=='workflow' else 'read'
elif path==root+'/immutable-releases':result=b['immutable_releases'];result['enabled']=mode!='immutable'
else:sys.exit('Unknown fixture path')
print(json.dumps(result))
PY
chmod +x "$task_dir/gh"
export PATH="$task_dir:$PATH" FIXTURE_LOG="$task_dir/calls" FIXTURE_BASELINE="$task_dir/baseline.json"
: > "$FIXTURE_LOG"
"$task_dir/compare" "$FIXTURE_BASELINE"
cp "$FIXTURE_BASELINE" "$task_dir/original.json"
for mode in foreign-owner settings identity-drift inherited new-rule rule-body events workflow immutable denied baseline-drift detail-id allowlist; do
 cp "$task_dir/original.json" "$FIXTURE_BASELINE"
 : > "$FIXTURE_LOG"
 if FIXTURE_MODE="$mode" "$task_dir/compare" "$FIXTURE_BASELINE" > "$task_dir/result" 2>&1; then echo "Accepted $mode drift" >&2; exit 1; fi
 if /usr/bin/grep -q DO_NOT_PRINT_PROVIDER_SECRET "$task_dir/result"; then echo 'Provider stderr disclosed' >&2; exit 1; fi
 if /usr/bin/grep -Eq '^(POST|PUT|PATCH|DELETE) ' "$FIXTURE_LOG"; then echo 'Doctor mutated repository' >&2; exit 1; fi
 echo "PASS: $mode drift denied"
done
cp "$task_dir/original.json" "$FIXTURE_BASELINE"
python3 - "$FIXTURE_BASELINE" "$task_dir/invalid.json" <<'PY'
import json,sys
b=json.load(open(sys.argv[1]));b['rulesets']=[];json.dump(b,open(sys.argv[2],'w'))
PY
: > "$FIXTURE_LOG"
if "$task_dir/compare" "$task_dir/invalid.json" > "$task_dir/result" 2>&1; then echo 'Incomplete baseline accepted' >&2; exit 1; fi
[[ ! -s "$FIXTURE_LOG" ]] || { echo 'Invalid baseline contacted provider' >&2; exit 1; }
swift build
bin="$(swift build --show-bin-path)/repoctl"
: > "$FIXTURE_LOG"
if "$bin" doctor --baseline "$FIXTURE_BASELINE" > "$task_dir/result" 2>&1; then echo 'Unenrolled baseline accepted by real CLI' >&2; exit 1; fi
[[ ! -s "$FIXTURE_LOG" ]] || { echo 'Unenrolled baseline contacted provider' >&2; exit 1; }
/usr/bin/grep -q 'not enrolled' "$task_dir/result"
echo 'PASS: real native doctor requires enrolled seal before provider access'
