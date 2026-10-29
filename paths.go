package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// dataDir ist der Arbeitsordner der EXE (Profile, Schlüssel, Protokoll).
func dataDir() string {
	if v := os.Getenv("ZA_DATA"); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "Certbumblebee")
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".certbumblebee")
}

const smartQuotes = "\u2018\u2019\u201a\u201b\u201c\u201d"

var (
	uncRe       = regexp.MustCompile(`^\\\\[^\\]+\\[^\\]+`)
	localRe     = regexp.MustCompile(`^[A-Za-z]:\\`)
	dotDotWinRe = regexp.MustCompile(`(^|\\)\.\.(\\|$)`)
)

// validatePath prüft einen Ordnerpfad. win=true: lokaler Windows-Pfad (D:\x) oder UNC (\\server\freigabe\x).
// win=false: absoluter Pfad (nur für Tests unter Linux).
func validatePath(input string, win bool, label string) (string, error) {
	p := strings.TrimSpace(input)
	if p == "" {
		return "", fmt.Errorf("%s: Bitte einen Pfad angeben.", label)
	}
	for _, r := range p {
		if r < 0x20 || strings.ContainsRune(`"<>|?*`+smartQuotes, r) {
			return "", fmt.Errorf("%s: Der Pfad enthält ein unzulässiges Zeichen (Anführungszeichen, < > | ? *).", label)
		}
	}
	if !win {
		if !strings.HasPrefix(p, "/") {
			return "", fmt.Errorf("%s: Bitte einen vollständigen Pfad angeben.", label)
		}
		for _, seg := range strings.Split(p, "/") {
			if seg == ".." {
				return "", fmt.Errorf("%s: Der Pfad darf kein „..“ enthalten.", label)
			}
		}
		p = path.Clean(p)
		if len(p) > 240 {
			return "", fmt.Errorf("%s: Der Pfad ist zu lang.", label)
		}
		return p, nil
	}
	p = strings.ReplaceAll(p, "/", `\`)
	if strings.HasPrefix(p, `\\?\`) || strings.HasPrefix(p, `\\.\`) {
		return "", fmt.Errorf(`%s: Pfade mit \\?\ oder \\.\ werden nicht unterstützt.`, label)
	}
	if !uncRe.MatchString(p) && !localRe.MatchString(p) {
		return "", fmt.Errorf(`%s: Bitte einen vollständigen Pfad angeben, z. B. D:\Zertifikate oder \\server\freigabe\ordner.`, label)
	}
	rest := p[2:]
	if strings.Contains(rest, ":") {
		return "", fmt.Errorf("%s: Der Pfad enthält einen Doppelpunkt an falscher Stelle.", label)
	}
	if strings.Contains(rest, `\\`) {
		return "", fmt.Errorf("%s: Der Pfad enthält doppelte Backslashes.", label)
	}
	if dotDotWinRe.MatchString(p) {
		return "", fmt.Errorf("%s: Der Pfad darf kein „..“ enthalten.", label)
	}
	p = strings.TrimRight(p, `\`)
	if len(p) == 2 && p[1] == ':' {
		p += `\`
	}
	if len(p) > 240 {
		return "", fmt.Errorf("%s: Der Pfad ist zu lang.", label)
	}
	return p, nil
}

func isUNC(p string) bool { return strings.HasPrefix(p, `\\`) }
