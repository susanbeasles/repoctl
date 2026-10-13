"""Deterministic adapter; original imported module remains byte-for-byte intact."""
def adapt(original):
 addition='      - name: Materialize intact security-assurance module\n        run: cp -a -- .security-depot/security-assurance/. .security-depot/\n'
 text=original.replace('    inputs:\n','    inputs:\n      integration_artifact_name:\n        description: "Same-run immutable build artifact; empty keeps source-only behavior"\n        type: string\n        default: ""\n      admission_only:\n        description: "Only source admission; PASS is not release approval"\n        type: boolean\n        default: false\n',1)
 text=text.replace('value: ${{ jobs.evidence-sign.outputs.decision }}','value: ${{ inputs.admission_only && jobs.gate-stage0.outputs.decision || jobs.evidence-sign.outputs.decision }}')
 text=text.replace('name: results-detect', 'name: "results-detect"').replace('name: results-ai-review', 'name: "results-ai-review"')
 text=text.replace('results-', "results-${{ inputs.admission_only && 'admission' || 'full' }}-")
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
 text=''.join(result)
 for name in ['admit','analyze']:
  start=text.index('\n  '+name+':');pos=text.index(addition,start)+len(addition)
  injection="      - if: inputs.integration_artifact_name != '' && !inputs.admission_only\n        uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333\n        with:\n          name: ${{ inputs.integration_artifact_name }}\n          path: .integration-build\n      - if: inputs.integration_artifact_name != '' && !inputs.admission_only\n        name: Verify build identity and byte inventory before scanning\n        run: python3 .security-depot/ci/verify-build.py  .integration-build\n"
  text=text[:pos]+injection+text[pos:]
 start=text.index('\n  admit:');end=text.index('\n  gate-stage0:',start)
 segment=text[start:end]
 for scan in ['secrets-scan','malware-scan','asset-scan','ai-injection-scan','binary-forensics']:
  at=segment.index("      - if: matrix.scan == '"+scan+"'")
  until=segment.find('\n      - ',at+1)
  if until<0:until=len(segment)
  block=segment[at:until].replace('source_path: src',"source_path: \"${{ inputs.integration_artifact_name != '' && !inputs.admission_only && '.integration-build/payload' || 'src' }}\"")
  segment=segment[:at]+block+segment[until:]
 text=text[:start]+segment+text[end:]
 return text
if __name__=='__main__':
 import pathlib
 root=pathlib.Path(__file__).resolve().parents[1]
 (root/'.github/workflows/security-assurance.yml').write_text(adapt((root/'security-assurance/.github/workflows/security-assurance.yml').read_text()))
