import pathlib,importlib.util,tempfile,json,hashlib,unittest,io,tarfile
base=pathlib.Path(__file__).parent
spec=importlib.util.spec_from_file_location('package',base/'release-materials.py');p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
spec=importlib.util.spec_from_file_location('unpack',base/'unpack-release.py');u=importlib.util.module_from_spec(spec);spec.loader.exec_module(u)
class Extraction(unittest.TestCase):
 def test_checksums_provenance_and_unsafe_paths(self):
  with tempfile.TemporaryDirectory() as td:
   root=pathlib.Path(td);build=root/'build';(build/'payload').mkdir(parents=True);(build/'payload/app.js').write_bytes(b'code');env=dict(GITHUB_REPOSITORY='o/r',GITHUB_SHA='a'*40,GITHUB_REF='refs/heads/int/x',GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='2')
   (build/'build-manifest.json').write_text(json.dumps(dict(schema=1,repository='o/r',sourceSha='a'*40,sourceRef='refs/heads/int/x',runId='1',runAttempt='2',files=[dict(path='app.js',bytes=4,sha256=hashlib.sha256(b'code').hexdigest())])))
   sbom=root/'sbom';sbom.mkdir();(sbom/'sbom.cdx.json').write_text('{"bomFormat":"CycloneDX","components":[]}');(sbom/'sbom.spdx.json').write_text('{"spdxVersion":"SPDX-2.3"}');p.package(build,sbom,root/'release',env)
   u.unpack(root/'release',root/'accepted',env['GITHUB_SHA']);assert (root/'accepted/payload/app.js').read_bytes()==b'code'
   with self.assertRaises(ValueError):u.unpack(root/'release',root/'bad-sha','b'*40)
   buffer=io.BytesIO()
   with tarfile.open(fileobj=buffer,mode='w:gz') as tar:
    entry=tarfile.TarInfo('../escape');entry.size=4;tar.addfile(entry,io.BytesIO(b'evil'))
   raw=buffer.getvalue();(root/'release/integration-release.tar.gz').write_bytes(raw);doc=json.loads((root/'release/artifact-provenance.json').read_text());doc['bundleSha256']=hashlib.sha256(raw).hexdigest();(root/'release/artifact-provenance.json').write_text(json.dumps(doc))
   with self.assertRaises(ValueError):u.unpack(root/'release',root/'bad-path',env['GITHUB_SHA'])
   assert not (root/'escape').exists()
if __name__=='__main__':unittest.main()
