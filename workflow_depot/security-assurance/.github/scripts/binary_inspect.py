#!/usr/bin/env python3
"""
Static binary forensics (no execution). Finds every ELF/PE/Mach-O/Wasm blob
under a tree regardless of extension and reports structure, hardening, packing
and suspicious capability indicators.

  binary_inspect.py --root <dir> --out findings.json [--max-bytes 100000000]

ELF: class/type/arch, PT_LOAD segments with RWX, PT_GNU_STACK executable,
PT_GNU_RELRO presence, PIE, DT_NEEDED libs, interpreter, section entropy,
UPX/packer markers, suspicious imported symbols (ptrace, dlopen, execve, socket,
connect, fork, setuid, mprotect, LD_PRELOAD strings).
PE: machine, subsystem, sections with W+X, entropy, packer section names.
Mach-O: header, load commands count, LC_LOAD_DYLIB names, segment protections.
Wasm: import section (host function names), memory/table counts, custom sections.
"""
import argparse
import json
import math
import os
import re
import struct
import sys

SUSPICIOUS_SYMS = {b"ptrace", b"dlopen", b"execve", b"execvp", b"system", b"popen", b"socket", b"connect", b"fork", b"setuid", b"setgid",
                   b"mprotect", b"mmap", b"prctl", b"inotify_add_watch", b"getenv", b"LD_PRELOAD", b"/proc/self/mem", b"/dev/tcp",
                   b"CryptAcquireContext", b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread", b"SetWindowsHookEx", b"GetAsyncKeyState",
                   b"NtUnmapViewOfSection", b"IsDebuggerPresent", b"WinExec", b"URLDownloadToFile", b"InternetOpen"}
PACKER_MARKERS = [b"UPX!", b"UPX0", b"UPX1", b".themida", b".vmp0", b".aspack", b".petite", b"MPRESS", b".enigma"]
HOST_IMPORTS_SUSPICIOUS = {"fd_write", "sock_", "path_open", "proc_exec", "env_get", "random_get"}


def entropy(b):
    if not b:
        return 0.0
    c = [0] * 256
    for x in b:
        c[x] += 1
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c if v)


class F:
    def __init__(self):
        self.items, self.binaries = [], []

    def add(self, sev, rule, path, msg, **x):
        self.items.append({"severity": sev, "rule": rule, "path": path, "message": msg, **x})


def strings_hits(data):
    hits = sorted({s.decode() for s in SUSPICIOUS_SYMS if s in data})
    return hits


def elf(data, rel, F):
    if len(data) < 64:
        return
    ei_class, ei_data = data[4], data[5]
    bits = 64 if ei_class == 2 else 32
    end = "<" if ei_data == 1 else ">"
    info = {"format": "elf", "bits": bits}
    try:
        if bits == 64:
            e_type, e_machine, _, e_entry, e_phoff, e_shoff, _, _, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack(end + "HHIQQQIHHHHHH", data[16:64])
        else:
            e_type, e_machine, _, e_entry, e_phoff, e_shoff, _, _, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack(end + "HHIIIIIHHHHHH", data[16:52])
    except struct.error:
        F.add("high", "ELF-MALFORMED", rel, "truncated ELF header")
        return
    info.update(type={1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}.get(e_type, str(e_type)), machine=e_machine, phnum=e_phnum, shnum=e_shnum)
    if e_phnum > 512 or e_shnum > 4096:
        F.add("high", "ELF-HEADER-ABSURD", rel, f"phnum={e_phnum} shnum={e_shnum}")
    rwx = stack_exec = False
    relro = False
    interp = None
    for i in range(min(e_phnum, 512)):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data):
            F.add("high", "ELF-PHDR-OVERFLOW", rel, "program header table past EOF")
            break
        if bits == 64:
            p_type, p_flags, p_offset, _, _, p_filesz, p_memsz, _ = struct.unpack(end + "IIQQQQQQ", data[off:off + 56])
        else:
            p_type, p_offset, _, _, p_filesz, p_memsz, p_flags, _ = struct.unpack(end + "IIIIIIII", data[off:off + 32])
        if p_type == 1 and (p_flags & 0b111) == 0b111:
            rwx = True
        if p_type == 0x6474E551 and p_flags & 1:
            stack_exec = True
        if p_type == 0x6474E552:
            relro = True
        if p_type == 3 and p_offset + p_filesz <= len(data):
            interp = data[p_offset:p_offset + p_filesz].rstrip(b"\0").decode(errors="replace")
        if p_type == 1 and p_offset + p_filesz <= len(data) and p_filesz > 4096:
            e = entropy(data[p_offset:p_offset + min(p_filesz, 1 << 20)])
            if e > 7.6 and p_flags & 1:
                F.add("high", "ELF-PACKED-SEGMENT", rel, f"executable PT_LOAD with entropy {e:.2f} (packed/encrypted)")
    if rwx:
        F.add("high", "ELF-RWX-SEGMENT", rel, "PT_LOAD segment is readable+writable+executable")
    if stack_exec:
        F.add("high", "ELF-EXEC-STACK", rel, "PT_GNU_STACK marks the stack executable")
    if e_type == 2:
        F.add("low", "ELF-NO-PIE", rel, "ET_EXEC (not position independent)")
    if e_type in (2, 3) and not relro and e_phnum:
        F.add("low", "ELF-NO-RELRO", rel, "no PT_GNU_RELRO")
    if interp and interp not in ("/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux.so.2", "/lib/ld-linux-aarch64.so.1", "/lib/ld-musl-x86_64.so.1", "/lib/ld-musl-aarch64.so.1", "/lib/ld-linux-armhf.so.3"):
        F.add("high", "ELF-ODD-INTERP", rel, f"unusual interpreter {interp}")
    info["interp"] = interp
    for m in PACKER_MARKERS:
        if m in data:
            F.add("high", "BIN-PACKER-MARKER", rel, f"packer marker {m.decode(errors='replace')}")
            break
    hits = strings_hits(data)
    info["suspicious_symbols"] = hits
    strong = [h for h in hits if h in ("ptrace", "LD_PRELOAD", "/proc/self/mem", "/dev/tcp", "inotify_add_watch", "prctl")]
    if strong or len(hits) >= 8:
        F.add("medium", "BIN-SUSPICIOUS-CAPABILITIES", rel, f"symbols: {', '.join(hits)[:200]}", strong=strong)
    if b"\x7fELF" in data[64:]:
        F.add("high", "BIN-EMBEDDED-ELF", rel, "another ELF header embedded in the file (dropper/loader pattern)")
    return info


def pe(data, rel, F):
    if len(data) < 0x40:
        return
    pe_off = struct.unpack("<I", data[0x3C:0x40])[0]
    if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\0\0":
        F.add("medium", "PE-MALFORMED", rel, "no PE signature at e_lfanew")
        return
    machine, nsec, _, _, _, opt_size, chars = struct.unpack("<HHIIIHH", data[pe_off + 4:pe_off + 24])
    info = {"format": "pe", "machine": hex(machine), "sections": nsec}
    sec_off = pe_off + 24 + opt_size
    for i in range(min(nsec, 96)):
        o = sec_off + i * 40
        if o + 40 > len(data):
            break
        name = data[o:o + 8].rstrip(b"\0")
        vsize, vaddr, rawsize, rawptr = struct.unpack("<IIII", data[o + 8:o + 24])
        sc = struct.unpack("<I", data[o + 36:o + 40])[0]
        if sc & 0x80000000 and sc & 0x20000000:
            F.add("high", "PE-WX-SECTION", rel, f"section {name.decode(errors='replace')} is writable+executable")
        if rawptr + rawsize <= len(data) and rawsize > 4096:
            e = entropy(data[rawptr:rawptr + min(rawsize, 1 << 20)])
            if e > 7.6 and sc & 0x20000000:
                F.add("high", "PE-PACKED-SECTION", rel, f"executable section {name.decode(errors='replace')} entropy {e:.2f}")
        if any(name.startswith(m.strip(b".")) for m in (b"UPX", b"themida", b"vmp", b"aspack", b"petite", b"enigma")):
            F.add("high", "BIN-PACKER-MARKER", rel, f"packer section {name.decode(errors='replace')}")
    hits = strings_hits(data)
    info["suspicious_symbols"] = hits
    strong = [h for h in hits if h in ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "SetWindowsHookEx", "GetAsyncKeyState", "NtUnmapViewOfSection", "URLDownloadToFile")]
    if strong or len(hits) >= 8:
        F.add("medium", "BIN-SUSPICIOUS-CAPABILITIES", rel, f"imports/strings: {', '.join(hits)[:200]}", strong=strong)
    return info


def macho(data, rel, F):
    magic = data[:4]
    if magic == b"\xca\xfe\xba\xbe":
        F.add("low", "MACHO-FAT", rel, "fat/universal binary (slices not individually analysed)")
        return {"format": "macho-fat"}
    le = magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe")
    end = "<" if le else ">"
    is64 = magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
    try:
        _, cputype, _, filetype, ncmds, sizeofcmds, flags = struct.unpack(end + "IIIIIII", data[:28])
    except struct.error:
        return
    off = 32 if is64 else 28
    dylibs = []
    for _ in range(min(ncmds, 512)):
        if off + 8 > len(data):
            F.add("high", "MACHO-LC-OVERFLOW", rel, "load commands past EOF")
            break
        cmd, cmdsize = struct.unpack(end + "II", data[off:off + 8])
        if cmdsize < 8:
            break
        if cmd in (0xC, 0x18, 0x80000018, 0x1F):
            so = struct.unpack(end + "I", data[off + 8:off + 12])[0]
            dylibs.append(data[off + so:off + cmdsize].split(b"\0", 1)[0].decode(errors="replace"))
        if cmd in (0x1, 0x19):
            segname = data[off + 8:off + 24].rstrip(b"\0").decode(errors="replace")
            prot_off = off + (60 if is64 else 44)
            maxprot, initprot = struct.unpack(end + "II", data[prot_off:prot_off + 8])
            if initprot & 0b111 == 0b111:
                F.add("high", "MACHO-RWX-SEGMENT", rel, f"segment {segname} is rwx")
        off += cmdsize
    if not flags & 0x200000:
        F.add("low", "MACHO-NO-PIE", rel, "MH_PIE not set")
    hits = strings_hits(data)
    if any(h in ("ptrace", "/dev/tcp", "dlopen") for h in hits) or len(hits) >= 8:
        F.add("medium", "BIN-SUSPICIOUS-CAPABILITIES", rel, f"symbols: {', '.join(hits)[:200]}")
    return {"format": "macho", "dylibs": dylibs[:30], "suspicious_symbols": hits}


def leb(data, off):
    r = s = 0
    while True:
        b = data[off]
        r |= (b & 0x7F) << s
        off += 1
        if not b & 0x80:
            return r, off
        s += 7


def wasm(data, rel, F):
    if len(data) < 8:
        return
    off = 8
    imports, customs, memories = [], [], 0
    try:
        while off < len(data):
            sid = data[off]
            size, off2 = leb(data, off + 1)
            body = data[off2:off2 + size]
            if sid == 0:
                nlen, o = leb(body, 0)
                customs.append(body[o:o + nlen].decode(errors="replace"))
            elif sid == 2:
                n, o = leb(body, 0)
                for _ in range(min(n, 2000)):
                    ml, o = leb(body, o); mod = body[o:o + ml].decode(errors="replace"); o += ml
                    fl, o = leb(body, o); fld = body[o:o + fl].decode(errors="replace"); o += fl
                    kind = body[o]; o += 1
                    if kind == 0:
                        _, o = leb(body, o)
                    elif kind == 1:
                        o += 1; flg = body[o]; o += 1; _, o = leb(body, o); o = leb(body, o)[1] if flg & 1 else o
                    elif kind == 2:
                        flg = body[o]; o += 1; _, o = leb(body, o); o = leb(body, o)[1] if flg & 1 else o
                    elif kind == 3:
                        o += 2
                    imports.append(f"{mod}.{fld}")
            elif sid == 5:
                memories, _ = leb(body, 0)
            off = off2 + size
    except (IndexError, struct.error):
        F.add("high", "WASM-MALFORMED", rel, "section parsing ran past EOF")
    sus = [i for i in imports if any(k in i for k in HOST_IMPORTS_SUSPICIOUS) or i.startswith("env.")]
    if sus:
        F.add("medium", "WASM-HOST-IMPORTS", rel, f"host imports: {', '.join(sus)[:200]}")
    if memories > 1:
        F.add("low", "WASM-MULTI-MEMORY", rel, f"{memories} memories")
    return {"format": "wasm", "imports": imports[:50], "custom_sections": customs[:20]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-bytes", type=int, default=100 * 1024 * 1024)
    a = ap.parse_args()
    F_ = F()
    for dp, dns, fns in os.walk(a.root):
        dns[:] = [d for d in dns if d != ".git"]
        for fn in fns:
            p = os.path.join(dp, fn)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            rel = os.path.relpath(p, a.root)
            with open(p, "rb") as f:
                head = f.read(4)
            fmt = "elf" if head == b"\x7fELF" else "pe" if head[:2] == b"MZ" else "macho" if head in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe") else "wasm" if head == b"\x00asm" else None
            if not fmt:
                continue
            if os.path.getsize(p) > a.max_bytes:
                F_.add("medium", "BIN-OVERSIZE", rel, "skipped (size)")
                continue
            with open(p, "rb") as f:
                data = f.read()
            try:
                info = {"elf": elf, "pe": pe, "macho": macho, "wasm": wasm}[fmt](data, rel, F_) or {"format": fmt}
            except Exception as e:
                F_.add("medium", "BIN-INSPECT-ERROR", rel, f"{type(e).__name__}: {str(e)[:120]}")
                info = {"format": fmt, "error": True}
            info.update(path=rel, bytes=len(data), entropy=round(entropy(data[:1 << 20]), 3))
            F_.binaries.append(info)
    with open(a.out, "w") as f:
        json.dump({"items": F_.items, "binaries": F_.binaries}, f, indent=2)
    print(f"[binary-inspect] {len(F_.binaries)} binaries, {len(F_.items)} findings")


if __name__ == "__main__":
    main()
