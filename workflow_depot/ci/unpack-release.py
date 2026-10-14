"""Bounded extraction after cosign verification; no project execution."""
import hashlib,io,json,os,pathlib,re,sys,tarfile

def unpack(source,destination,expected_sha):
 source=pathlib.Path(source);destination=pathlib.Path(destination)
 provenance=json.loads((source/'artifact-provenance.json').read_text());raw=(source/'integration-release.tar.gz').read_bytes()
 if provenance.get('sourceSha')!=expected_sha or provenance.get('bundleSha256')!=hashlib.sha256(raw).hexdigest():raise ValueError('Signed release provenance differs')
 if len(raw)>67108864:raise ValueError('Release archive exceeds compressed limit')
 files={};size=0
 with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as tar:
  for entry in tar:
   if not entry.isfile() or entry.name in files or entry.name.startswith('/') or '\\' in entry.name or any(p in ['..','.',''] for p in entry.name.split('/')):raise ValueError('Unsafe release archive')
   size+=entry.size
   if size>268435456 or len(files)>=10000:raise ValueError('Release extraction limit exceeded')
   files[entry.name]=tar.extractfile(entry).read()
 if hashlib.sha256(files['build-manifest.json']).hexdigest()!=provenance['buildManifestSha256']:raise ValueError('Manifest digest differs')
 expected={}
 for line in files['SHA256SUMS'].decode().splitlines():
  digest,name=line.split('  ',1)
  if not re.fullmatch('[a-f0-9]{64}',digest) or name in expected:raise ValueError('Invalid checksum inventory')
  expected[name]=digest
 actual={name:hashlib.sha256(data).hexdigest() for name,data in files.items() if name!='SHA256SUMS'}
 if not actual or expected!=actual:raise ValueError('Release checksum inventory differs')
 destination.mkdir(parents=True,exist_ok=False)
 for name,data in files.items():
  path=destination/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
 return provenance
if __name__=='__main__':unpack(sys.argv[1],sys.argv[2],os.environ['GITHUB_SHA'])
