# Agent protections

Repository hooks run the supplied deterministic ingress guard and action supervisor
for Claude Code, Codex, and GitHub Copilot. Cursor receives an instruction rule;
this is not a claim that Cursor has command-hook enforcement.

`policy.json` defines protected paths, quarantined content, secret paths, and
network/MCP allowlists. Network and MCP access start denied. Preserve task-specific
scope in the supervisor section. A reviewed `policy.local.json` can override local
policy; it must not be committed.

Run `node --test .guard/tests/guard.ts` with Node 24 and Python 3.11 or later.
The tests use temporary repositories and state directories, not your session logs.
CI validates syntax and behavior, rejects hidden Unicode in changed text and runs Gitleaks. Existing
project CI remains responsible for application tests; the local completion hook
runs the repository's `.guard/checks/on-stop`.

After merging, review and trust the project and Codex hooks before using them.
Hooks are guardrails, not an OS security boundary. No machine-level locks, daemon,
firewall, GitHub ruleset, required check, or required review is installed by these
files. CODEOWNERS only requests reviews unless repository settings require them.
Post-tool scanning cannot undo an operation. Host sandboxes and server-side
protection remain separate requirements.

The bundled supervisor was chosen over the separate older download because it
supports cross-agent payloads and project-root resolution. This rollout changes
its malformed-input/policy and internal-error handling to deny instead of allow.
The regex policy cannot prove that arbitrary indirect shell execution is safe.

Documentation sources checked during preparation:
- https://learn.chatgpt.com/docs/hooks
- https://learn.chatgpt.com/docs/config-file/config-reference
- https://docs.github.com/en/copilot/reference/hooks-reference

The bundled Codex config now uses the documented top-level `web_search = "disabled"`.
The provided Python implementation is preserved; the new regression tests use TypeScript.

CI blocks invisible/bidirectional Unicode markers. Broad natural-language injection
patterns run in the ingress hooks; they are not blanket CI failures because
legitimate security policies, instructions and specifications match them.
Local check adapters invoke Bash explicitly and do not rely on executable bits.
