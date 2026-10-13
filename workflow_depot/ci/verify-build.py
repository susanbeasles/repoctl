"""Verify downloaded integration artifact before any scanner consumes it."""
import hashlib,json,os,pathlib,re,sys

def verify(root,env):
 root=pathlib.Path(root)
 manifest=json.loads((root/'build-manifest.json').read_text())
 for key,expected in [('schema',1),('repository',env['GITHUB_REPOSITORY']),('sourceSha',env['GITHUB_SHA']),('sourceRef',env['GITHUB_REF']),('runId',env['GITHUB_RUN_ID']),('runAttempt',env['GITHUB_RUN_ATTEMPT'])]:
  if manifest.get(key)!=expected:raise ValueError('Build identity mismatch: '+key)
 payload=root/'payload';actual={}
 for path in payload.rglob('*'):
  if path.is_symlink() or not (path.is_dir() or path.is_file()):raise ValueError('Unsafe build entry')
  if path.is_file():actual[path.relative_to(payload).as_posix()]={'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
 expected={}
 for entry in manifest['files']:
  name=entry['path']
  if not name or '\\' in name or name.startswith('/') or any(p in ['.','..',''] for p in name.split('/')) or name in expected:raise ValueError('Unsafe or duplicate manifest entry')
  if not re.fullmatch('[a-f0-9]{64}',entry['sha256']):raise ValueError('Invalid digest')
  expected[name]={'bytes':entry['bytes'],'sha256':entry['sha256']}
 if not actual or actual!=expected:raise ValueError('Build bytes do not match manifest')
 if {p.name for p in root.iterdir()}!={'payload','build-manifest.json'}:raise ValueError('Unexpected bundle entries')
 return manifest
if __name__=='__main__':
 verify(sys.argv[1],os.environ);print('Verified exact integration artifact identity and bytes.')
