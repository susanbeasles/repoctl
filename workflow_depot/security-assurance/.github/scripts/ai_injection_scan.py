#!/usr/bin/env python3
"""
Repository instruction-poisoning scanner (domain Q).

Scans the files an AI coding agent or reviewer is likely to read as
instructions (AGENTS.md, CLAUDE.md, .cursorrules, copilot-instructions,
README, docs, issue/PR templates, MCP configs, skill files) for:

  HARD indicators  -> critical/high (gate-blocking):
    invisible Unicode TAG characters, bidi overrides, zero-width runs,
    hidden HTML (comments / hidden / display:none / white-on-white) that
    contain imperative instructions, MCP tool descriptions with imperative
    instructions or shell-fetch commands, markdown images that exfiltrate.
  SOFT indicators  -> medium (reported, not blocking):
    classic injection phrasing in visible text, chat-template tokens,
    large base64 blobs in prose, mixed-script (homoglyph) words.

Heuristic by design. The AI reviewer never sees these files as instructions
regardless; this control exists so humans are told when content is trying.

  ai_injection_scan.py --root <dir> --out findings.json
"""
import argparse
import json
import os
import re
import sys

TARGET_NAMES = {"agents.md", "claude.md", ".cursorrules", "copilot-instructions.md", "readme.md", "contributing.md",
                "mcp.json", ".mcp.json", "claude_desktop_config.json", "skill.md", "gemini.md", ".windsurfrules",
                ".clinerules", "instructions.md", "prompt.md", "system.md"}
TARGET_DIRS = {".claude", ".cursor", ".github", "docs", "prompts", "skills", ".agents", "agents"}
TARGET_EXT = {".md", ".mdc", ".txt", ".rst", ".json", ".yaml", ".yml", ".html"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "target", "dist", "build", ".next"}

TAG_CHARS = re.compile("[\U000E0000-\U000E007F]")
BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
ZERO_WIDTH_RUN = re.compile("[\u200b-\u200d\u2060\ufeff]{3,}")
IMPERATIVE = re.compile(
    r"(ignore (all |any )?(previous|prior|above|earlier|your) (instructions|rules|messages|context|guidelines)|"
    r"disregard (all |any )?(previous|prior|above)|you are now|new instructions?:|system prompt|developer message|"
    r"do not (tell|inform|mention|reveal)( this)? (to )?the user|as an? (ai|assistant|llm)|"
    r"\b(assistant|claude|gpt|copilot|cursor|agent)\b[^.\n]{0,40}\b(must|should|always|never)\b|"
    r"(run|execute|eval|curl|wget|download)\b[^.\n]{0,60}(bash|sh|powershell|\|\s*sh)|"
    r"(print|send|post|upload|exfiltrate|leak)\b[^.\n]{0,60}(secret|token|key|credential|env|\.env|password))", re.I)
CHAT_TOKENS = re.compile(r"(<\|im_start\|>|<\|system\|>|\[INST\]|<<SYS>>|###\s*(system|instruction)|^\s*SYSTEM:\s)", re.I | re.M)
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
HIDDEN_HTML = re.compile(r"<(\w+)[^>]*(hidden|display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|"
                         r"color\s*:\s*(white|#fff(fff)?|transparent)|opacity\s*:\s*0)[^>]*>(.*?)</\1>", re.I | re.S)
MD_IMAGE = re.compile(r"!\[[^\]]*\]\((https?://[^)\s]+)\)")
EXFIL_QUERY = re.compile(r"[?&][^=]{0,30}=\s*(\{|\$|%7B|<)|(secret|token|apikey|api_key|password|env)=", re.I)
BASE64_BLOB = re.compile(r"(?:[A-Za-z0-9+/]{4}){60,}={0,2}")
LATIN = re.compile(r"[A-Za-z]")
CYRILLIC_GREEK = re.compile(r"[\u0400-\u04FF\u0370-\u03FF]")
WORD = re.compile(r"\S{3,}")
FETCH_EXEC = re.compile(r"(curl|wget|iwr|invoke-webrequest)[^|\n]{0,200}\|\s*(ba|z)?sh|npx\s+-y\s+\S+@(latest)?", re.I)


class Findings:
    def __init__(self):
        self.items = []

    def add(self, severity, rule, path, message, line=None, excerpt=""):
        item = {"severity": severity, "rule": rule, "path": path, "message": message}
        if line is not None:
            item["line"] = line
        if excerpt:
            item["excerpt"] = excerpt[:160]
        self.items.append(item)


def line_of(text, idx):
    return text.count("\n", 0, idx) + 1


def scan_text(rel, text, F):
    for m in TAG_CHARS.finditer(text):
        F.add("critical", "AI-UNICODE-TAGS", rel, "invisible Unicode TAG characters (hidden instruction channel)", line_of(text, m.start()))
        break
    for m in BIDI.finditer(text):
        F.add("high", "AI-BIDI-OVERRIDE", rel, "bidirectional override characters", line_of(text, m.start()))
        break
    for m in ZERO_WIDTH_RUN.finditer(text):
        F.add("high", "AI-ZERO-WIDTH-RUN", rel, "run of zero-width characters (steganographic payload)", line_of(text, m.start()))
        break
    for m in HTML_COMMENT.finditer(text):
        body = m.group(1)
        if IMPERATIVE.search(body) or CHAT_TOKENS.search(body):
            F.add("critical", "AI-HIDDEN-COMMENT-INSTRUCTION", rel, "HTML comment contains instructions aimed at an agent",
                  line_of(text, m.start()), body.strip())
    for m in HIDDEN_HTML.finditer(text):
        body = m.group(4)
        if IMPERATIVE.search(body) or CHAT_TOKENS.search(body) or len(body.strip()) > 40:
            F.add("critical", "AI-HIDDEN-HTML", rel, "visually hidden HTML block with content", line_of(text, m.start()), body.strip())
    for m in MD_IMAGE.finditer(text):
        url = m.group(1)
        if EXFIL_QUERY.search(url) or len(url) > 300:
            F.add("high", "AI-IMAGE-EXFIL", rel, "markdown image URL with templated/secret-bearing query (exfil pattern)",
                  line_of(text, m.start()), url)
    visible = HTML_COMMENT.sub("", text)
    for m in IMPERATIVE.finditer(visible):
        F.add("medium", "AI-INJECTION-PHRASE", rel, "instruction-injection phrasing in visible text",
              line_of(visible, m.start()), m.group(0))
    for m in CHAT_TOKENS.finditer(visible):
        F.add("medium", "AI-CHAT-TEMPLATE-TOKEN", rel, "chat-template control token in document", line_of(visible, m.start()), m.group(0))
    for m in BASE64_BLOB.finditer(visible):
        F.add("medium", "AI-BASE64-BLOB", rel, "large base64 blob in instruction/prose file", line_of(visible, m.start()))
        break
    for m in FETCH_EXEC.finditer(visible):
        F.add("high", "AI-FETCH-AND-EXECUTE", rel, "fetch-and-execute or unpinned npx instruction", line_of(visible, m.start()), m.group(0))
    mixed = 0
    for w in WORD.findall(visible):
        if LATIN.search(w) and CYRILLIC_GREEK.search(w):
            mixed += 1
            if mixed == 1:
                F.add("medium", "AI-MIXED-SCRIPT", rel, f"mixed Latin/Cyrillic-Greek word (homoglyph): {w[:40]}")


def scan_mcp_json(rel, text, F):
    try:
        doc = json.loads(text)
    except Exception:
        return

    def walk(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                lk = k.lower()
                if lk in {"description", "instructions", "prompt", "system"} and isinstance(v, str):
                    if IMPERATIVE.search(v) or CHAT_TOKENS.search(v):
                        F.add("high", "AI-MCP-DESCRIPTION-INJECTION", rel, f"tool/server {path}.{k} contains agent instructions", excerpt=v)
                if lk in {"command", "args"}:
                    s = v if isinstance(v, str) else " ".join(map(str, v)) if isinstance(v, list) else ""
                    if FETCH_EXEC.search(s) or re.search(r"\b(curl|wget)\b", s):
                        F.add("high", "AI-MCP-FETCH-EXEC", rel, f"server {path} launches via fetch/unpinned command", excerpt=s)
                    if re.search(r"npx\s+(-y\s+)?[^@\s]+(\s|$)", s) and "@" not in s:
                        F.add("medium", "AI-MCP-UNPINNED", rel, f"server {path} uses unpinned npx package", excerpt=s)
                if lk == "env" and isinstance(v, dict):
                    for ek, ev in v.items():
                        if isinstance(ev, str) and re.search(r"(sk-|ghp_|AKIA|xox[baprs]-|-----BEGIN)", ev):
                            F.add("critical", "AI-MCP-INLINE-SECRET", rel, f"inline credential in env {ek} of {path}")
                walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")

    walk(doc, "$")


def wanted(rel, fn):
    low = fn.lower()
    ext = os.path.splitext(low)[1]
    top = rel.split(os.sep)[0].lower() if os.sep in rel else ""
    return low in TARGET_NAMES or (ext in TARGET_EXT and (top in TARGET_DIRS or os.sep not in rel or "prompt" in rel.lower()
                                                          or "skill" in rel.lower() or "agent" in rel.lower()))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-bytes", type=int, default=1_000_000)
    a = ap.parse_args()
    F = Findings()
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(a.root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, a.root)
            if os.path.islink(p) or not wanted(rel, fn):
                continue
            if os.path.getsize(p) > a.max_bytes:
                continue
            with open(p, "rb") as f:
                data = f.read()
            text = data.decode("utf-8", errors="replace")
            scanned += 1
            if fn.lower() in {"mcp.json", ".mcp.json", "claude_desktop_config.json"} or fn.lower().endswith(".json"):
                scan_mcp_json(rel, text, F)
                if fn.lower() not in {"package.json", "package-lock.json", "tsconfig.json"}:
                    scan_text(rel, text, F)
            else:
                scan_text(rel, text, F)
    with open(a.out, "w") as f:
        json.dump({"items": F.items, "scanned_files": scanned,
                   "limitations": ["Heuristic pattern matching; multilingual and paraphrased injections are not reliably detected.",
                                   "Image/PDF-embedded instructions are not OCR'd."]}, f, indent=2)
    print(f"[ai-injection] {scanned} files, {len(F.items)} findings")


if __name__ == "__main__":
    main()
