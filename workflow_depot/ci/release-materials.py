"""Package previously verified integration bytes; never build project code."""
import gzip,hashlib,importlib.util,io,json,os,pathlib,sys,tarfile
spec=importlib.util.spec_from_file_location('build_verifier',pathlib.Path(__file__).with_name('verify-build.py'));v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
def package(root,sbom_dir,output,env):
 root=pathlib.Path(root);sbom_dir=pathlib.Path(sbom_dir);output=pathlib.Path(output)
 manifest=v.verify(root,env)
 cdx=json.loads((sbom_dir/'sbom.cdx.json').read_text());spdx=json.loads((sbom_dir/'sbom.spdx.json').read_text())
 if cdx.get('bomFormat')!='CycloneDX' or not isinstance(cdx.get('components',[]),list) or not spdx.get('spdxVersion','').startswith('SPDX-'):raise ValueError('Missing or malformed build SBOM')
 output.mkdir(parents=True,exist_ok=False)
 files=[(p.relative_to(root).as_posix(),p.read_bytes()) for p in root.rglob('*') if p.is_file()]
 files += [(p.name,p.read_bytes()) for p in [sbom_dir/'sbom.cdx.json',sbom_dir/'sbom.spdx.json']]
 checksum=''.join(hashlib.sha256(data).hexdigest()+'  '+name+'\n' for name,data in sorted(files))
 files.append(('SHA256SUMS',checksum.encode()));buf=io.BytesIO()
 with tarfile.open(fileobj=buf,mode='w',format=tarfile.PAX_FORMAT) as tar:
  for name,data in sorted(files):
   info=tarfile.TarInfo(name);info.size=len(data);info.mtime=0;info.mode=0o600;info.uid=info.gid=0;info.uname=info.gname='';tar.addfile(info,io.BytesIO(data))
 archive=gzip.compress(buf.getvalue(),mtime=0);(output/'integration-release.tar.gz').write_bytes(archive)
 (output/'SHA256SUMS').write_text(hashlib.sha256(archive).hexdigest()+'  integration-release.tar.gz\n')
 (output/'artifact-provenance.json').write_text(json.dumps({**{k:manifest[k] for k in ['repository','sourceSha','sourceRef','runId','runAttempt']},'schema':'workflow-depot-artifact-inventory/v1','bundleSha256':hashlib.sha256(archive).hexdigest(),'buildManifestSha256':hashlib.sha256((root/'build-manifest.json').read_bytes()).hexdigest()},sort_keys=True)+'\n')
if __name__=='__main__':package(*sys.argv[1:4],os.environ)
