#!/usr/bin/env python3
"""
Hostile asset scanner (domain H): SVG/XML, raster images, fonts, archives.

SVGs are treated as active-content XML documents. Parsing is done in stages:
raw-byte checks first (DOCTYPE/ENTITY => refuse to parse at all), then a
bounded ElementTree walk. Images/fonts/archives get structural checks for
appended data, magic/extension mismatch, traversal, embedded executables.

  asset_scan.py --root <dir> --out findings.json [--max-bytes 2097152]
"""
import argparse
import base64
import json
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET
import zipfile

EXT_MAGIC = {
    ".png": [b"\x89PNG\r\n\x1a\n"], ".jpg": [b"\xff\xd8\xff"], ".jpeg": [b"\xff\xd8\xff"],
    ".gif": [b"GIF87a", b"GIF89a"], ".webp": [b"RIFF"], ".ico": [b"\x00\x00\x01\x00"],
    ".woff": [b"wOFF"], ".woff2": [b"wOF2"], ".ttf": [b"\x00\x01\x00\x00", b"true"], ".otf": [b"OTTO"],
    ".pdf": [b"%PDF-"], ".zip": [b"PK\x03\x04", b"PK\x05\x06"], ".gz": [b"\x1f\x8b"], ".tgz": [b"\x1f\x8b"],
    ".wasm": [b"\x00asm"], ".jar": [b"PK\x03\x04"],
}
EXEC_MAGIC = [b"\x7fELF", b"MZ", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\x00asm"]
ARCHIVE_MAGIC = [b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf", b"Rar!", b"\xfd7zXZ"]
SVG_EXT = {".svg", ".svgz"}
XML_EXT = {".xml", ".xsl", ".xslt", ".rss", ".atom", ".plist"}
IMG_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico"}
FONT_EXT = {".woff", ".woff2", ".ttf", ".otf"}
ARCH_EXT = {".zip", ".jar"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "target", "dist", "build", ".next"}

EVENT_ATTR = re.compile(r"^on[a-z]+$", re.I)
DANGEROUS_URI = re.compile(r"^\s*(javascript|vbscript|data|file|blob|ftp|jar|ms-its|res):", re.I)
EXTERNAL_URI = re.compile(r"^\s*(https?:|//)", re.I)
CSS_URL = re.compile(r"(url\s*\(|@import|expression\s*\(|-moz-binding|behavior\s*:)", re.I)
INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u00ad]")
TAG_CHARS = re.compile("[\U000E0000-\U000E007F]")
MAX_DEPTH, MAX_ELEMENTS = 256, 50000
HTML_NS = "http://www.w3.org/1999/xhtml"
XLINK_NS = "http://www.w3.org/1999/xlink"


class Findings:
    def __init__(self):
        self.items = []
        self.counts = {}

    def add(self, severity, rule, path, message, **extra):
        self.items.append({"severity": severity, "rule": rule, "path": path, "message": message, **extra})


def local(tag):
    return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""


def ns_of(tag):
    return tag[1:].split("}", 1)[0] if isinstance(tag, str) and tag.startswith("{") else ""


def scan_svg_or_xml(path, data, F, is_svg):
    text = data.decode("utf-8", errors="replace")
    # Stage 1: raw checks that must happen before any parser touches the bytes.
    low = text.lower()
    if "<!doctype" in low or "<!entity" in low:
        F.add("critical", "XML-DTD", path, "DOCTYPE/ENTITY declaration (XXE / entity-expansion vector); not parsed further")
        return
    if "<?xml-stylesheet" in low:
        F.add("high", "XML-STYLESHEET-PI", path, "xml-stylesheet processing instruction (external resource load)")
    if TAG_CHARS.search(text):
        F.add("critical", "UNICODE-TAG-CHARS", path, "invisible Unicode TAG characters present")
    if INVISIBLE.search(text):
        F.add("medium", "UNICODE-INVISIBLE", path, "zero-width/bidi code points present")
    if re.search(r"&#x?[0-9a-f]+;", low) and re.search(r"&#x?(3c|60|73|115|74|116|6a|106);", low):
        F.add("high", "XML-ENCODED-MARKUP", path, "character-reference encoded '<', 's', 't' or 'j' (obfuscated markup/script)")
    # Polyglot / trailing data: content after the final closing root tag.
    m = re.search(r"</\s*(svg|[a-zA-Z:_][\w:.-]*)\s*>\s*$", text, re.S)
    if m is None:
        stripped = text.rstrip()
        if stripped and not stripped.endswith(">"):
            F.add("high", "XML-TRAILING-DATA", path, "non-whitespace data after document end (polyglot?)")
    # Stage 2: bounded structural parse. expat does not resolve external
    # entities by default; DTDs were already refused above.
    try:
        it = ET.iterparse(__import__("io").BytesIO(data), events=("start", "end"))
        depth = max_depth = count = 0
        for ev, el in it:
            if ev == "start":
                depth += 1
                count += 1
                max_depth = max(max_depth, depth)
                if max_depth > MAX_DEPTH:
                    F.add("high", "XML-NESTING", path, f"nesting depth > {MAX_DEPTH}")
                    return
                if count > MAX_ELEMENTS:
                    F.add("high", "XML-ELEMENT-FLOOD", path, f"> {MAX_ELEMENTS} elements")
                    return
                inspect_element(path, el, F, is_svg)
            else:
                depth -= 1
                el.clear()
    except ET.ParseError as e:
        F.add("high", "XML-MALFORMED", path, f"malformed XML: {e}")


def inspect_element(path, el, F, is_svg):
    name = local(el.tag)
    ns = ns_of(el.tag)
    if name == "script":
        F.add("critical", "SVG-SCRIPT", path, "<script> element")
    if name == "foreignobject":
        F.add("critical", "SVG-FOREIGNOBJECT", path, "<foreignObject> (embedded HTML)")
    if ns == HTML_NS or name in {"iframe", "embed", "object", "frame", "applet", "form", "input", "button"}:
        F.add("critical", "SVG-HTML-CONTENT", path, f"HTML element <{name}> inside SVG/XML")
    if name in {"set", "animate", "animatemotion", "animatetransform"}:
        attr = el.attrib.get("attributeName", "")
        if attr.lower() in {"href", "xlink:href", "src"}:
            F.add("critical", "SVG-ANIMATE-HREF", path, f"<{name}> targeting {attr} (SMIL href swap)")
        else:
            F.add("low", "SVG-ANIMATION", path, f"<{name}> animation element")
    if name == "style" and el.text and CSS_URL.search(el.text):
        F.add("high", "SVG-STYLE-URL", path, "url()/@import/expression in <style>")
    if name == "filter":
        F.counts["filters"] = F.counts.get("filters", 0) + 1
        if F.counts["filters"] == 50:
            F.add("medium", "SVG-FILTER-FLOOD", path, ">= 50 filter elements (rendering DoS)")
    if name == "image" or name == "use" or name == "feimage" or name == "font-face-uri":
        href = el.attrib.get("href") or el.attrib.get(f"{{{XLINK_NS}}}href") or ""
        if EXTERNAL_URI.match(href):
            F.add("high", "SVG-EXTERNAL-REF", path, f"<{name}> loads external resource: {href[:120]}")
    for k, v in el.attrib.items():
        lk = local(k)
        if EVENT_ATTR.match(lk):
            F.add("critical", "SVG-EVENT-HANDLER", path, f"event handler attribute {lk}")
        if lk in {"href", "src", "xlink:href", "action", "formaction", "data", "poster"} or k.endswith("}href"):
            if DANGEROUS_URI.match(v):
                scheme = v.strip().split(":", 1)[0].lower()
                sev = "critical" if scheme in {"javascript", "vbscript"} else "high"
                F.add(sev, "SVG-DANGEROUS-URI", path, f"{lk} uses {scheme}: URI")
                if scheme == "data":
                    check_data_uri(path, v, F)
            elif EXTERNAL_URI.match(v) and name not in {"a"}:
                F.add("medium", "SVG-EXTERNAL-URI", path, f"{lk} references external host: {v[:120]}")
        if lk == "style" and CSS_URL.search(v):
            F.add("high", "SVG-INLINE-STYLE-URL", path, "url()/@import in inline style")


def check_data_uri(path, v, F):
    m = re.match(r"\s*data:([^;,]*)(;base64)?,(.*)", v, re.S)
    if not m:
        return
    mime, b64, payload = m.group(1).lower(), m.group(2), m.group(3)
    if "svg" in mime or "html" in mime or "javascript" in mime:
        F.add("critical", "SVG-DATA-ACTIVE", path, f"data: URI with active MIME {mime}")
    if b64:
        try:
            raw = base64.b64decode(payload[:4096] + "===", validate=False)
        except Exception:
            return
        if any(raw.startswith(mg) for mg in EXEC_MAGIC + ARCHIVE_MAGIC):
            F.add("critical", "SVG-DATA-BINARY", path, "base64 data: URI contains executable/archive")
        if len(payload) > 200000:
            F.add("medium", "SVG-DATA-LARGE", path, f"large embedded data: URI ({len(payload)} chars)")


def scan_png(path, data, F):
    pos = 8
    while pos + 8 <= len(data):
        length, ctype = struct.unpack(">I4s", data[pos:pos + 8])
        if length > 50_000_000:
            F.add("high", "PNG-CHUNK-LENGTH", path, f"absurd chunk length {length}")
            return
        if ctype in (b"tEXt", b"zTXt", b"iTXt") and length > 65536:
            F.add("medium", "PNG-METADATA-LARGE", path, f"{ctype.decode()} chunk of {length} bytes")
        pos += 12 + length
        if ctype == b"IEND":
            if len(data) - pos > 0:
                F.add("high", "IMG-TRAILING-DATA", path, f"{len(data) - pos} bytes after IEND (appended payload)")
                sniff_payload(path, data[pos:], F)
            return
    F.add("medium", "PNG-NO-IEND", path, "no IEND chunk (truncated/malformed)")


def scan_jpeg(path, data, F):
    eoi = data.rfind(b"\xff\xd9")
    if eoi == -1:
        F.add("medium", "JPEG-NO-EOI", path, "no EOI marker")
        return
    trailing = data[eoi + 2:]
    if len(trailing) > 0:
        F.add("high", "IMG-TRAILING-DATA", path, f"{len(trailing)} bytes after EOI")
        sniff_payload(path, trailing, F)
    # scan APP segments for oversized metadata
    pos = 2
    while pos + 4 <= len(data) and data[pos] == 0xFF:
        marker = data[pos + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        seglen = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        if 0xE0 <= marker <= 0xEF and seglen > 65000:
            F.add("low", "JPEG-APP-LARGE", path, f"APP{marker - 0xE0} segment {seglen} bytes")
        if marker == 0xDA:
            break
        pos += 2 + seglen


def scan_gif(path, data, F):
    end = data.rfind(b"\x3b")
    if end != -1 and len(data) - end - 1 > 0:
        F.add("high", "IMG-TRAILING-DATA", path, f"{len(data) - end - 1} bytes after GIF trailer")
        sniff_payload(path, data[end + 1:], F)


def sniff_payload(path, blob, F):
    if any(blob.lstrip(b"\x00").startswith(mg) for mg in EXEC_MAGIC):
        F.add("critical", "IMG-EMBEDDED-EXECUTABLE", path, "appended data is an executable")
    elif any(blob.startswith(mg) for mg in ARCHIVE_MAGIC):
        F.add("critical", "IMG-EMBEDDED-ARCHIVE", path, "appended data is an archive")
    elif b"<script" in blob.lower() or b"<?php" in blob.lower():
        F.add("critical", "IMG-EMBEDDED-SCRIPT", path, "appended data contains script")


def scan_font(path, data, F):
    if data[:4] in (b"wOFF", b"wOF2"):
        return  # compressed container; structural checks would need decompression (brotli) - noted as limitation
    if len(data) < 12:
        F.add("medium", "FONT-TRUNCATED", path, "too small to be a font")
        return
    num_tables = struct.unpack(">H", data[4:6])[0]
    if num_tables == 0 or num_tables > 64:
        F.add("high", "FONT-TABLE-COUNT", path, f"numTables={num_tables}")
        return
    for i in range(num_tables):
        off = 12 + i * 16
        if off + 16 > len(data):
            F.add("high", "FONT-TABLE-DIR-OVERFLOW", path, "table directory exceeds file")
            return
        tag, _, toff, tlen = struct.unpack(">4sIII", data[off:off + 16])
        if toff + tlen > len(data):
            F.add("high", "FONT-TABLE-OVERFLOW", path, f"table {tag} extends past EOF")


def scan_zip(path, data, F):
    try:
        zf = zipfile.ZipFile(__import__("io").BytesIO(data))
    except zipfile.BadZipFile as e:
        F.add("medium", "ZIP-MALFORMED", path, str(e))
        return
    total = 0
    for info in zf.infolist()[:5000]:
        n = info.filename
        if n.startswith("/") or ".." in n.split("/") or re.match(r"[a-zA-Z]:\\", n):
            F.add("critical", "ZIP-TRAVERSAL", path, f"member path {n}")
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            F.add("high", "ZIP-SYMLINK", path, f"symlink member {n}")
        if info.compress_size and info.file_size / max(info.compress_size, 1) > 100 and info.file_size > 10_000_000:
            F.add("high", "ZIP-BOMB-RATIO", path, f"{n} ratio {info.file_size // max(info.compress_size, 1)}:1")
        total += info.file_size
        try:
            head = zf.open(info).read(8)
        except Exception:
            continue
        if any(head.startswith(mg) for mg in EXEC_MAGIC):
            F.add("high", "ZIP-EMBEDDED-EXECUTABLE", path, f"executable member {n}")
        if any(head.startswith(mg) for mg in ARCHIVE_MAGIC):
            F.add("medium", "ZIP-NESTED-ARCHIVE", path, f"nested archive {n}")
    if total > 2_000_000_000:
        F.add("high", "ZIP-TOTAL-SIZE", path, f"uncompressed total {total} bytes")


def scan_file(path, rel, F, max_bytes):
    ext = os.path.splitext(path)[1].lower()
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        data = f.read(max_bytes + 1)
    if len(data) > max_bytes:
        if ext in SVG_EXT | XML_EXT:
            F.add("high", "ASSET-OVERSIZE", rel, f"> {max_bytes} bytes; refused to parse")
        return
    # magic vs extension
    if ext in EXT_MAGIC and not any(data.startswith(m) for m in EXT_MAGIC[ext]):
        if ext == ".webp" and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
            pass
        else:
            F.add("high", "MAGIC-MISMATCH", rel, f"content does not match {ext} signature")
            if any(data.startswith(m) for m in EXEC_MAGIC):
                F.add("critical", "DISGUISED-EXECUTABLE", rel, "executable disguised as asset")
    if data[:5].lower() == b"<?xml" or data.lstrip()[:4].lower() == b"<svg":
        if ext not in SVG_EXT | XML_EXT:
            F.add("high", "XML-DISGUISED", rel, f"XML/SVG content with {ext or 'no'} extension")
            scan_svg_or_xml(rel, data, F, True)
    if ext in SVG_EXT:
        if ext == ".svgz":
            import gzip
            try:
                data = gzip.decompress(data[:max_bytes])
            except Exception:
                F.add("medium", "SVGZ-MALFORMED", rel, "cannot decompress")
                return
            if len(data) > max_bytes * 4:
                F.add("high", "SVGZ-DECOMPRESSION-RATIO", rel, "decompresses far beyond limit")
                return
        scan_svg_or_xml(rel, data, F, True)
    elif ext in XML_EXT:
        scan_svg_or_xml(rel, data, F, False)
    elif ext == ".png" and data.startswith(EXT_MAGIC[".png"][0]):
        scan_png(rel, data, F)
    elif ext in (".jpg", ".jpeg") and data.startswith(b"\xff\xd8"):
        scan_jpeg(rel, data, F)
    elif ext == ".gif" and data[:3] == b"GIF":
        scan_gif(rel, data, F)
    elif ext in FONT_EXT:
        scan_font(rel, data, F)
    elif ext in ARCH_EXT:
        scan_zip(rel, data, F)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-bytes", type=int, default=2 * 1024 * 1024)
    ap.add_argument("--max-files", type=int, default=20000)
    a = ap.parse_args()
    F = Findings()
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(a.root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if os.path.islink(p):
                continue
            rel = os.path.relpath(p, a.root)
            ext = os.path.splitext(fn)[1].lower()
            if ext in SVG_EXT | XML_EXT | IMG_EXT | FONT_EXT | ARCH_EXT | {".pdf", ".wasm", ".gz", ".tgz"} or ext == "":
                try:
                    scan_file(p, rel, F, a.max_bytes)
                except Exception as e:
                    F.add("medium", "ASSET-SCAN-ERROR", rel, f"scanner exception: {e}")
                scanned += 1
                if scanned >= a.max_files:
                    F.add("medium", "ASSET-FILE-LIMIT", ".", f"stopped after {a.max_files} files")
                    break
    limitations = ["WOFF/WOFF2 table structure not decompressed (brotli not available offline).",
                   "Decoder-vulnerability intelligence (CVE lookups for libpng/libjpeg) is covered by SCA on the consuming app, not here.",
                   "Sandboxed rendering is not performed; this is structural analysis only."]
    with open(a.out, "w") as f:
        json.dump({"items": F.items, "scanned_files": scanned, "limitations": limitations}, f, indent=2)
    print(f"[asset-scan] {scanned} files, {len(F.items)} findings")


if __name__ == "__main__":
    main()
