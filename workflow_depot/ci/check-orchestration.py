import pathlib,yaml
root=pathlib.Path(__file__).resolve().parents[1]
w=yaml.load((root/'.github/workflows/integration-quality.yml').read_text(),Loader=yaml.BaseLoader)
assert set(w['on'])=={'workflow_call'}
j=w['jobs'];assert j['admission']['needs']=='identity'
assert j['quality-build']['needs']=='admission'
assert j['security']['needs']=='quality-build'
assert j['quality-security-checks']['needs']==['admission','quality-build','security']
assert "== 'PASS'" in j['quality-build']['if']
assert j['quality-build']['permissions']=={'contents':'read'}
assert sum('project-profile.mjs' in s.get('run','') for s in j['quality-build']['steps'])==1
s=yaml.load((root/'.github/workflows/security-assurance.yml').read_text(),Loader=yaml.BaseLoader)
for name in ['analyze','codeql','gate-stage2','ai-review','evidence-sign']:
 assert '!inputs.admission_only' in s['jobs'][name]['if']
assert s['on']['workflow_call']['inputs']['admission_only']['default']=='false'
print('Verified source admission before tooling, single quality/build invocation, full source security before quality result; no push trigger.')

for job in s['jobs'].values():
 for step in job.get('steps',[]):
  value=step.get('with',{}).get('pattern','')
  if value.startswith('results-'):assert "'admission' || 'full'" in value
print('Verified phase-scoped artifacts prevent admission/full evidence collisions.')
