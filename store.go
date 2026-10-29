package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

// Profile beschreibt ein Zertifikat, das automatisch ausgestellt und erneuert wird.
type Profile struct {
	ID           string       `json:"id"`
	Domains      []string     `json:"domains"`
	Method       string       `json:"method"`               // "standalone" (eingebauter Webserver) | "webroot" | "dns" (Cloudflare) | "selfsigned"
	DNSAccount   string       `json:"dnsAccount,omitempty"` // nur „dns“: gewählter DNS-Zugang, leer = je Zone automatisch
	ValidDays    int          `json:"validDays,omitempty"`  // Gültigkeit selbstsignierter Zertifikate in Tagen
	Webroot      []string     `json:"webroot,omitempty"`
	TargetDir    string       `json:"targetDir"`
	FileName     string       `json:"fileName"` // Name der PFX-Datei (oder der ersten Datei)
	Outputs      []OutputSpec `json:"outputs,omitempty"`
	ServerKind   string       `json:"serverKind"` // prod | staging | custom
	DirectoryURL string       `json:"directoryUrl"`
	Email        string       `json:"email,omitempty"`
	KeyBits      int          `json:"keyBits"`
	PfxFormat    string       `json:"pfxFormat"` // compat (3DES, überall lesbar) | aes (AES-256)
	Task         TaskConfig   `json:"task"`
	Firewall     bool         `json:"firewall"`
	Created      time.Time    `json:"created"`
}

type TaskConfig struct {
	Enabled bool   `json:"enabled"`
	Name    string `json:"name"`
	Time    string `json:"time"`  // HH:MM
	RunAs   string `json:"runAs"` // SYSTEM oder DOMÄNE\Benutzer
}

// State hält fest, was zuletzt passiert ist.
type State struct {
	LastRun     time.Time `json:"lastRun"`
	LastResult  string    `json:"lastResult"` // ausgestellt | erneuert | nicht-faellig | fehler
	LastMessage string    `json:"lastMessage"`
	PfxSig      string    `json:"pfxSig"`
	SyncedAt    time.Time `json:"syncedAt"`
	AutoRunDay  string    `json:"autoRunDay,omitempty"` // Tag des letzten erfolgreichen Zeitplan-Laufs (Dauerbetrieb)
	AutoNext    time.Time `json:"autoNext,omitempty"`   // frühester nächster Versuch nach einem Fehler
}

func profilesRoot() string { return filepath.Join(dataDir(), "profiles") }

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)

func validID(id string) bool { return idRe.MatchString(id) && !strings.Contains(id, "..") }

func profileDir(id string) string { return filepath.Join(profilesRoot(), id) }

func slugID(main string) string {
	s := strings.ToLower(main)
	if strings.HasPrefix(s, "*.") {
		s = "wildcard." + s[2:]
	}
	s = regexp.MustCompile(`[^a-z0-9.-]`).ReplaceAllString(s, "_")
	return strings.TrimLeft(s, "._-")
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b, 0o600)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func loadProfile(id string) (*Profile, error) {
	if !validID(id) {
		return nil, fmt.Errorf("Ungültige Kennung.")
	}
	b, err := os.ReadFile(filepath.Join(profileDir(id), "profile.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("Es gibt kein Zertifikat mit der Kennung „%s“.", id)
		}
		return nil, err
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("Die Einstellungen von „%s“ sind beschädigt: %v", id, err)
	}
	return &p, nil
}

func saveProfile(p *Profile) error {
	return writeJSON(filepath.Join(profileDir(p.ID), "profile.json"), p)
}

func loadState(id string) State {
	var st State
	if b, err := os.ReadFile(filepath.Join(profileDir(id), "state.json")); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func saveState(id string, st State) error {
	return writeJSON(filepath.Join(profileDir(id), "state.json"), st)
}

func listProfileIDs() []string {
	ents, err := os.ReadDir(profilesRoot())
	if err != nil {
		return nil
	}
	var ids []string
	for _, e := range ents {
		if e.IsDir() && validID(e.Name()) {
			if _, err := os.Stat(filepath.Join(profilesRoot(), e.Name(), "profile.json")); err == nil {
				ids = append(ids, e.Name())
			}
		}
	}
	sort.Strings(ids)
	return ids
}

// ---- Passwort der PFX-Datei (geschützt abgelegt) ----

func saveSecret(id, pw string) error {
	enc, err := plat.Protect([]byte(pw))
	if err != nil {
		return fmt.Errorf("Das Passwort konnte nicht geschützt gespeichert werden: %v", err)
	}
	return writeFileAtomic(filepath.Join(profileDir(id), "pfx.secret"), []byte(base64.StdEncoding.EncodeToString(enc)), 0o600)
}

func loadSecret(id string) (string, error) {
	b, err := os.ReadFile(filepath.Join(profileDir(id), "pfx.secret"))
	if err != nil {
		return "", fmt.Errorf("Das gespeicherte PFX-Passwort fehlt: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return "", fmt.Errorf("Das gespeicherte PFX-Passwort ist beschädigt.")
	}
	pt, err := plat.Unprotect(raw)
	if err != nil {
		return "", fmt.Errorf("Das gespeicherte PFX-Passwort lässt sich nicht entschlüsseln (nur auf dem Rechner lesbar, auf dem es gespeichert wurde): %v", err)
	}
	return string(pt), nil
}

// ---- Sperre gegen gleichzeitige Läufe (Aufgabe und Oberfläche) ----

func lockProfile(id string) (func(), error) {
	p := filepath.Join(profileDir(id), "run.lock")
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d %s", os.Getpid(), time.Now().Format(time.RFC3339))
			f.Close()
			return func() { _ = os.Remove(p) }, nil
		}
		if fi, serr := os.Stat(p); serr == nil && time.Since(fi.ModTime()) > 45*time.Minute {
			_ = os.Remove(p) // veraltete Sperre eines abgestürzten Laufs
			continue
		}
		break
	}
	return nil, fmt.Errorf("Für „%s“ läuft gerade schon ein Vorgang. Bitte später noch einmal versuchen.", id)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- Domains ----

var domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// normalizeDomains trennt an Zeilenumbruch, Leerzeichen, Komma und Semikolon, wandelt in Punycode um und prüft.
func normalizeDomains(input string) ([]string, error) {
	fields := strings.FieldsFunc(input, func(r rune) bool { return r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == ',' || r == ';' })
	seen := map[string]bool{}
	var out []string
	for _, f := range fields {
		d := strings.ToLower(strings.TrimSpace(f))
		d = strings.TrimSuffix(d, ".")
		if d == "" {
			continue
		}
		if strings.HasPrefix(d, "*.") {
			return nil, fmt.Errorf("„%s“ ist eine Wildcard-Domain. Wildcards lassen sich nur über einen DNS-Eintrag bestätigen. Bitte die Methode „DNS (Cloudflare)“ wählen oder den Reiter „Wildcard / DNS (manuell)“ verwenden.", d)
		}
		if net.ParseIP(d) != nil {
			return nil, fmt.Errorf("„%s“ ist eine IP-Adresse. Dafür stellt Let’s Encrypt kein Zertifikat aus. Mit „Selbstsigniert“ sind IP-Adressen möglich.", d)
		}
		if strings.Contains(d, "://") || strings.ContainsAny(d, "/:@") {
			return nil, fmt.Errorf("„%s“ ist keine Domain. Bitte nur den Namen ohne http:// oder Pfad eintragen.", d)
		}
		a, err := idna.Lookup.ToASCII(d)
		if err != nil || !domainRe.MatchString(a) {
			return nil, fmt.Errorf("„%s“ ist keine gültige Domain.", d)
		}
		if seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("Bitte mindestens eine Domain eintragen.")
	}
	if len(out) > 100 {
		return nil, fmt.Errorf("Es sind höchstens 100 Domains pro Zertifikat möglich.")
	}
	return out, nil
}
