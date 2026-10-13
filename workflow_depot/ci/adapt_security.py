"""Deterministic adapter; original imported module remains byte-for-byte intact."""
def adapt(original):
 addition='      - name: Materialize intact security-assurance module\n        run: cp -a -- .security-depot/security-assurance/. .security-depot/\n'
 text=original.replace('    inputs:\n','    inputs:\n      admission_only:\n        description: "Only source admission; PASS is not release approval"\n        type: boolean\n        default: false\n',1)
 text=text.replace('value: ${{ jobs.evidence-sign.outputs.decision }}','value: ${{ inputs.admission_only && jobs.gate-stage0.outputs.decision || jobs.evidence-sign.outputs.decision }}')
 text=text.replace('group: security-assurance-${{ github.repository }}','group: security-assurance-${{ inputs.admission_only }}-${{ github.repository }}')
 # Skip later stages only for the explicit admission phase. Default full policy is unchanged.
 for name in ['analyze','codeql','gate-stage2','ai-review','evidence-sign']:
  start=text.index('\n  '+name+':'); end=text.find('\n  ',start+4)
  # Find the job-level conditional, not matrix step conditionals.
  pos=text.index('\n    if: ',start); line_end=text.index('\n',pos+1)
  text=text[:pos]+text[pos:line_end].replace('if: ','if: ${{ !inputs.admission_only && (',1)+') }}'+text[line_end:]
 lines=text.splitlines(True);result=[]
 for i,line in enumerate(lines):
  result.append(line)
  if 'with: { repository:' in line and 'path: .security-depot' in line:result.append(addition)
 return ''.join(result)
if __name__=='__main__':
 import pathlib
 root=pathlib.Path(__file__).resolve().parents[1]
 (root/'.github/workflows/security-assurance.yml').write_text(adapt((root/'security-assurance/.github/workflows/security-assurance.yml').read_text()))
