#!/usr/bin/env python3
"""Erzeugt resource_windows_amd64.syso: Programmsymbol (icon/certbumblebee.ico) und Versionsangaben der EXE.

Der Go-Linker nimmt die Datei beim Bauen für Windows/amd64 automatisch auf. Name, Autor und Version
kommen aus version.go, damit sie nicht auseinanderlaufen. Es wird nur die Standardbibliothek benutzt,
und die Ausgabe ist immer gleich (keine Zeitstempel).

Aufruf (im Hauptverzeichnis):  python3 tools/mkresource.py
"""
import os
import re
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "resource_windows_amd64.syso")
ICO = os.path.join(ROOT, "icon", "certbumblebee.ico")

RT_ICON, RT_GROUP_ICON, RT_VERSION = 3, 14, 16
ICON_GROUP_ID = 1      # window_windows.go lädt das Fenstersymbol unter dieser Kennung (appIconID)
LANG = 0x0407          # Deutsch
CODEPAGE = 0x04B0      # Unicode


def const(name):
    src = open(os.path.join(ROOT, "version.go"), encoding="utf-8").read()
    m = re.search(r'\b%s\s*=\s*"([^"]*)"' % name, src)
    if not m:
        sys.exit("version.go: %s nicht gefunden" % name)
    return m.group(1)


def align4(n):
    return (n + 3) & ~3


def pad4(b):
    return b + b"\0" * (-len(b) % 4)


def utf16(s):
    return s.encode("utf-16-le")


# ---------- Symbol ----------

def read_ico(path):
    b = open(path, "rb").read()
    reserved, kind, count = struct.unpack("<HHH", b[:6])
    if reserved != 0 or kind != 1 or count == 0:
        sys.exit("Keine gültige ICO-Datei: " + path)
    images = []
    for i in range(count):
        w, h, colors, _, planes, bpp, size, off = struct.unpack("<BBBBHHII", b[6 + 16 * i:22 + 16 * i])
        images.append((w, h, colors, planes, bpp, b[off:off + size]))
        if len(images[-1][5]) != size:
            sys.exit("ICO-Datei ist abgeschnitten")
    return images


def icon_resources(images):
    res = {}
    group = struct.pack("<HHH", 0, 1, len(images))
    for n, (w, h, colors, planes, bpp, data) in enumerate(images, start=1):
        res.setdefault(RT_ICON, {})[n] = {LANG: data}
        group += struct.pack("<BBBBHHIH", w, h, colors, 0, planes, bpp, len(data), n)
    res[RT_GROUP_ICON] = {ICON_GROUP_ID: {LANG: group}}
    return res


# ---------- Versionsangaben ----------

def block(key, vtype, value=b"", vlen=0, children=()):
    b = struct.pack("<HHH", 0, vlen, vtype) + utf16(key) + b"\0\0"
    b = pad4(b) + value
    for c in children:
        b = pad4(b) + c
    return struct.pack("<H", len(b)) + b[2:]


def version_resource(name, author, version, exe):
    nums = [int(x) for x in version.split(".")] + [0, 0, 0, 0]
    nums = nums[:4]
    ms, ls = (nums[0] << 16) | nums[1], (nums[2] << 16) | nums[3]
    fixed = struct.pack("<13I", 0xFEEF04BD, 0x00010000, ms, ls, ms, ls, 0x3F, 0, 0x00040004, 1, 0, 0, 0)
    strings = [
        ("Comments", "Programmiert von " + author),
        ("CompanyName", author),
        ("FileDescription", name + " – Zertifikate holen, erstellen und erneuern"),
        ("FileVersion", "%d.%d.%d.%d" % tuple(nums)),
        ("InternalName", exe.rsplit(".", 1)[0]),
        ("LegalCopyright", "Programmiert von " + author),
        ("OriginalFilename", exe),
        ("ProductName", name),
        ("ProductVersion", version),
    ]
    table = block("%04X%04X" % (LANG, CODEPAGE), 1, children=[
        block(k, 1, utf16(v) + b"\0\0", len(v) + 1) for k, v in strings
    ])
    var = block("VarFileInfo", 1, children=[block("Translation", 0, struct.pack("<HH", LANG, CODEPAGE), 4)])
    return block("VS_VERSION_INFO", 0, fixed, len(fixed), children=[block("StringFileInfo", 1, children=[table]), var])


# ---------- Ressourcenbaum und COFF-Datei ----------

def build_rsrc(res):
    """Gibt (Abschnittsinhalt, Verschiebungen der Datenadressen) zurück."""
    types = sorted(res)
    pos = 16 + 8 * len(types)
    type_dir, name_dir, entry_pos, blob_pos = {}, {}, {}, {}
    for t in types:
        type_dir[t] = pos
        pos += 16 + 8 * len(res[t])
    for t in types:
        for n in sorted(res[t]):
            name_dir[(t, n)] = pos
            pos += 16 + 8 * len(res[t][n])
    keys = [(t, n, l) for t in types for n in sorted(res[t]) for l in sorted(res[t][n])]
    for k in keys:
        entry_pos[k] = pos
        pos += 16
    for k in keys:
        pos = align4(pos)
        blob_pos[k] = pos
        pos += len(res[k[0]][k[1]][k[2]])
    out = bytearray(align4(pos))

    def directory(at, entries):
        struct.pack_into("<IIHHHH", out, at, 0, 0, 0, 0, 0, len(entries))
        for i, (ident, target) in enumerate(entries):
            struct.pack_into("<II", out, at + 16 + 8 * i, ident, target)

    directory(0, [(t, 0x80000000 | type_dir[t]) for t in types])
    for t in types:
        directory(type_dir[t], [(n, 0x80000000 | name_dir[(t, n)]) for n in sorted(res[t])])
        for n in sorted(res[t]):
            directory(name_dir[(t, n)], [(l, entry_pos[(t, n, l)]) for l in sorted(res[t][n])])
    relocs = []
    for k in keys:
        data = res[k[0]][k[1]][k[2]]
        struct.pack_into("<IIII", out, entry_pos[k], blob_pos[k], len(data), 0, 0)
        relocs.append(entry_pos[k])
        out[blob_pos[k]:blob_pos[k] + len(data)] = data
    return bytes(out), relocs


def coff(section, relocs):
    raw_ptr = 20 + 40
    rel_ptr = raw_ptr + len(section)
    sym_ptr = rel_ptr + 10 * len(relocs)
    head = struct.pack("<HHIIIHH", 0x8664, 1, 0, sym_ptr, 1, 0, 0)
    sect = struct.pack("<8sIIIIIIHHI", b".rsrc", 0, 0, len(section), raw_ptr, rel_ptr, 0, len(relocs), 0, 0xC0000040)
    rels = b"".join(struct.pack("<IIH", r, 0, 0x0003) for r in relocs)   # IMAGE_REL_AMD64_ADDR32NB
    sym = struct.pack("<8sIhHBB", b".rsrc", 0, 1, 0, 3, 0)
    return head + sect + section + rels + sym + struct.pack("<I", 4)


def main():
    name, author, version, exe = const("appName"), const("appAuthor"), const("appVersion"), const("appExeName")
    res = icon_resources(read_ico(ICO))
    res[RT_VERSION] = {1: {LANG: version_resource(name, author, version, exe)}}
    section, relocs = build_rsrc(res)
    with open(OUT, "wb") as f:
        f.write(coff(section, relocs))
    print("%s: %d Symbolgrößen, Version %s" % (os.path.basename(OUT), len(res[RT_ICON]), version))


if __name__ == "__main__":
    main()
