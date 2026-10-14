"""Add owned Advanced configuration without changing imported result/gate code."""
import pathlib
root=pathlib.Path(__file__).resolve().parents[1]
original=(root/'security-assurance/.github/actions/sast-codeql/action.yml').read_text()
needle='        queries: security-extended\n'
assert original.count(needle)==1
adapted=original.replace(needle,'        config-file: ./.security-depot/ci/codeql/config.yml\n')
(root/'.github/actions/sast-codeql/action.yml').write_text(adapted)
