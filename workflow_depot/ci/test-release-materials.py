import pathlib,tempfile,json,hashlib,importlib.util,unittest
spec=importlib.util.spec_from_file_location('release',pathlib.Path(__file__).with_name('release-materials.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class ReleaseMaterials(unittest.TestCase):
 def test_no_rebuild_deterministic_bundle_and_bound_digest(self):
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td);root=p/'build';(root/'payload').mkdir(parents=True);(root/'payload/app.js').write_bytes(b'code')
   env=dict(GITHUB_REPOSITORY='o/r',GITHUB_SHA='a'*40,GITHUB_REF='refs/heads/int/x',GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='2');doc=dict(schema=1,repository='o/r',sourceSha='a'*40,sourceRef='refs/heads/int/x',runId='1',runAttempt='2',files=[dict(path='app.js',bytes=4,sha256=hashlib.sha256(b'code').hexdigest())]);(root/'build-manifest.json').write_text(json.dumps(doc))
   sbom=p/'sbom';sbom.mkdir();(sbom/'sbom.cdx.json').write_text('{"bomFormat":"CycloneDX","components":[]}');(sbom/'sbom.spdx.json').write_text('{"spdxVersion":"SPDX-2.3"}')
   m.package(root,sbom,p/'a',env);m.package(root,sbom,p/'b',env);assert (p/'a/integration-release.tar.gz').read_bytes()==(p/'b/integration-release.tar.gz').read_bytes()
   provenance=json.loads((p/'a/artifact-provenance.json').read_text());assert provenance['bundleSha256']==hashlib.sha256((p/'a/integration-release.tar.gz').read_bytes()).hexdigest()
   (root/'payload/app.js').write_bytes(b'evil')
   with self.assertRaises(ValueError):m.package(root,sbom,p/'c',env)
if __name__=='__main__':unittest.main()
