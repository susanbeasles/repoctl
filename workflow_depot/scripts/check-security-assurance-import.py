"""Offline import/path check only; does not run scanner actions or qualification."""
import hashlib,json,pathlib,tempfile,shutil,yaml
root=pathlib.Path(__file__).resolve().parents[1]
manifest=json.loads((root/'security-assurance-import.json').read_text())
for entry in manifest['files']:
 assert hashlib.sha256((root/'security-assurance'/entry['path']).read_bytes()).hexdigest()==entry['sha256'],entry['path']
original=(root/'security-assurance/.github/workflows/security-assurance.yml').read_text()
adapter=(root/'.github/workflows/security-assurance.yml').read_text()
addition='      - name: Materialize intact security-assurance module\n        run: cp -a -- .security-depot/security-assurance/. .security-depot/\n'
assert adapter.replace(addition,'')==original
parsed=yaml.load(adapter,Loader=yaml.BaseLoader)
assert set(parsed['on'])=={'workflow_call'}
with tempfile.TemporaryDirectory() as td:
 depot=pathlib.Path(td)/'.security-depot';depot.mkdir();shutil.copytree(root/'security-assurance',depot/'security-assurance')
 shutil.copytree(depot/'security-assurance',depot,dirs_exist_ok=True)
 for job in parsed['jobs'].values():
  seen=False
  for step in job.get('steps',[]):
   if step.get('name')=='Materialize intact security-assurance module':seen=True
   uses=step.get('uses','')
   if uses.startswith('./.security-depot/'):
    assert seen and (pathlib.Path(td)/uses/'action.yml').is_file(),uses
 assert (depot/'policy/release-policy.yml').is_file()
 assert (depot/'.github/scripts/verify_evidence.py').is_file()
print(f"Verified {len(manifest['files'])} unchanged files, workflow-call-only adapter and all local action paths.")
