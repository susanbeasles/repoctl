import importlib.util,pathlib,tempfile,json,hashlib,unittest
spec=importlib.util.spec_from_file_location('verify',pathlib.Path(__file__).with_name('verify-build.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class BuildVerification(unittest.TestCase):
 def test_identity_and_bytes_fail_closed(self):
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td);(p/'payload').mkdir();(p/'payload/app.js').write_bytes(b'code')
   env=dict(GITHUB_REPOSITORY='o/r',GITHUB_SHA='a'*40,GITHUB_REF='refs/heads/int/x',GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='2')
   doc=dict(schema=1,repository='o/r',sourceSha='a'*40,sourceRef='refs/heads/int/x',runId='1',runAttempt='2',files=[dict(path='app.js',bytes=4,sha256=hashlib.sha256(b'code').hexdigest())]);(p/'build-manifest.json').write_text(json.dumps(doc))
   m.verify(p,env)
   with self.assertRaises(ValueError):m.verify(p,{**env,'GITHUB_SHA':'b'*40})
   (p/'payload/app.js').write_bytes(b'evil')
   with self.assertRaises(ValueError):m.verify(p,env)
   (p/'payload/app.js').write_bytes(b'code');(p/'payload/extra').write_bytes(b'extra')
   with self.assertRaises(ValueError):m.verify(p,env)
if __name__=='__main__':unittest.main()
