import pathlib,json,hashlib,tempfile,shutil,subprocess,yaml
root=pathlib.Path(__file__).resolve().parents[1]
components=json.loads((root/'ci/source-components.json').read_text())
assert components['commit']=='447e4cafe983a4dd68b60632d2c6e3d4c56367e8'
for f in components['files']:assert hashlib.sha256((root/f['path']).read_bytes()).hexdigest()==f['sha256']
with tempfile.TemporaryDirectory() as td:
 depot=pathlib.Path(td);shutil.copytree(root/'security-assurance',depot/'security-assurance');shutil.copytree(root/'security-assurance',depot,dirs_exist_ok=True);shutil.copytree(root/'ci',depot/'ci',ignore=shutil.ignore_patterns('__pycache__'))
 subprocess.run(['python',str(depot/'ci/materialize-codeql.py')],check=True)
 original=(root/'security-assurance/.github/actions/sast-codeql/action.yml').read_text();adapted=(depot/'.github/actions/sast-codeql/action.yml').read_text()
 assert adapted==original.replace('        queries: security-extended\n','        config-file: ./.security-depot/ci/codeql/config.yml\n')
config=yaml.load((root/'ci/codeql/config.yml').read_text(),Loader=yaml.BaseLoader)
assert config['disable-default-queries']=='false' and config['queries']==[{'uses':'security-extended'}]
assert 'paths-ignore' not in config and 'query-filters' not in config
for name in ['accepted-main-artifacts','request-deployment','main-deployment']:
 w=yaml.load((root/f'.github/workflows/{name}.yml').read_text(),Loader=yaml.BaseLoader);assert set(w['on'])=={'workflow_call'}
main=yaml.load((root/'.github/workflows/accepted-main-artifacts.yml').read_text(),Loader=yaml.BaseLoader)
steps=main['jobs']['consume']['steps'];runs='\n'.join(s.get('run','') for s in steps)
assert 'cosign verify-blob' in runs and 'package-bundle.mjs' in runs and 'npm' not in runs
assert sum('main-source-run.mjs' in s.get('run','') for s in steps)==2
print('Verified canonical source hashes, owned CodeQL config without exclusions, and main packaging without rebuild or authority substitutes.')

combined=yaml.load((root/'.github/workflows/main-deployment.yml').read_text(),Loader=yaml.BaseLoader)
assert combined['jobs']['dispatch']['needs']=='artifact'
assert combined['jobs']['artifact']['uses']=='./.github/workflows/accepted-main-artifacts.yml'
assert combined['jobs']['dispatch']['uses']=='./.github/workflows/request-deployment.yml'
