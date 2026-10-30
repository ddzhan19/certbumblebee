#!/usr/bin/env python3
"""Erzeugt THIRD_PARTY_LICENSES.md: die Lizenztexte aller Bibliotheken, die im Programm stecken.

Die BSD-Lizenzen der Bibliotheken verlangen, ihren Urheberrechtshinweis und Lizenztext bei der Weitergabe von
Programmen mitzuliefern. Die Datei kommt deshalb ins Docker-Image (/licenses) und ins Release. Welche Module
dazugehören, fragt das Skript bei Go ab (für Linux und Windows), die Texte stehen im Modul-Zwischenspeicher von Go.
Es wird nur die Standardbibliothek benutzt, und die Ausgabe ist immer gleich (keine Zeitstempel).

Aufruf (im Hauptverzeichnis, nach go mod download oder go build):  python3 tools/licenses.py
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "THIRD_PARTY_LICENSES.md")
LICENSE_NAMES = ("license", "license.txt", "license.md", "licence", "copying", "copying.txt")


def go(*args, **env):
    e = dict(os.environ)
    e.update(env)
    r = subprocess.run(["go", *args], cwd=ROOT, env=e, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("go %s: %s" % (" ".join(args), r.stderr.strip()))
    return r.stdout


def modules():
    """Alle fremden Module, aus denen Pakete ins Programm kommen (Linux und Windows zusammen)."""
    found = {}
    for goos in ("linux", "windows"):
        out = go("list", "-deps", "-f", "{{with .Module}}{{if not .Main}}{{.Path}}\t{{.Version}}\t{{.Dir}}{{end}}{{end}}", ".",
                 GOOS=goos, GOARCH="amd64", CGO_ENABLED="0")
        for line in out.splitlines():
            if line.strip():
                path, version, directory = line.split("\t")
                found[path] = (version, directory)
    return found


def license_file(directory):
    for name in sorted(os.listdir(directory)):
        if name.lower() in LICENSE_NAMES and os.path.isfile(os.path.join(directory, name)):
            return os.path.join(directory, name)
    return None


def read(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read().replace("\r\n", "\n").strip("\n")


def kind(text):
    """Erkennt die Lizenzart an typischen Sätzen (nur zur Übersicht, maßgeblich ist der Text)."""
    if "Apache License" in text:
        return "Apache-2.0"
    if "Mozilla Public License" in text:
        return "MPL-2.0"
    if "GNU General Public License" in text or "GNU Lesser General Public License" in text:
        return "GPL/LGPL"
    if "Permission is hereby granted, free of charge" in text:
        return "MIT"
    if "Permission to use, copy, modify, and/or distribute this software" in text:
        return "ISC"
    if "Redistribution and use in source and binary forms" in text:
        return "BSD-3-Clause" if ("Neither the name" in text or "endorse or promote" in text) else "BSD-2-Clause"
    return "siehe Text"


def main():
    entries = []  # (Name, Version, Lizenzart, Text, Quelle)
    for path, (version, directory) in sorted(modules().items()):
        lf = license_file(directory)
        if lf is None:
            sys.exit("%s %s: keine Lizenzdatei gefunden in %s" % (path, version, directory))
        text = read(lf)
        entries.append((path, version, kind(text), text, "https://pkg.go.dev/%s@%s" % (path, version)))
    goroot = go("env", "GOROOT").strip()
    # Offizielle Go-Pakete legen LICENSE in GOROOT ab, Homebrew eine Ebene darüber.
    candidates = [os.path.join(goroot, "LICENSE"), os.path.join(os.path.dirname(goroot), "LICENSE")]
    golicense = next((c for c in candidates if os.path.isfile(c)), None)
    if golicense is None:
        sys.exit("Die Lizenzdatei von Go wurde nicht gefunden (gesucht: %s)." % ", ".join(candidates))
    gotext = read(golicense)
    entries.append(("Go (Laufzeit und Standardbibliothek)", "–", kind(gotext), gotext, "https://go.dev/LICENSE"))

    out = ["# Lizenzen der eingebauten Bibliotheken", "",
           "Certbumblebee steht unter der GNU General Public License, Version 3 oder später (siehe [LICENSE](LICENSE)).",
           "Das Programm enthält die folgenden",
           "Bibliotheken. Für sie gelten ihre eigenen Lizenzen, deren Texte unten stehen.", "",
           "Diese Datei wird mit `python3 tools/licenses.py` aus den tatsächlich verwendeten Modulen erzeugt.", "",
           "| Bibliothek | Version | Lizenz |", "|---|---|---|"]
    for name, version, lic, _, _ in entries:
        out.append("| %s | %s | %s |" % (name, version, lic))
    for name, version, lic, text, source in entries:
        out += ["", "---", "", "## %s%s" % (name, "" if version == "–" else " " + version), "",
                "Lizenz: %s. Quelle: %s" % (lic, source), "", "````text", text, "````"]
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out) + "\n")
    print("%s: %d Bibliotheken" % (os.path.basename(OUT), len(entries)))


if __name__ == "__main__":
    main()
