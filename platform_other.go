//go:build !windows

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/hkdf"
)

// unixPlatform ist die Plattform für Linux und macOS (auch im Container). Es gibt keine Aufgabenplanung und keine
// Windows-Firewall: Die automatische Erneuerung übernimmt der Dauerbetrieb („serve“) oder ein Aufruf von „renew“
// durch cron/systemd. Aufgaben werden nur im Arbeitsordner vermerkt, damit die Übersicht sie anzeigen kann.
type unixPlatform struct{}

var fakeMu sync.Mutex

func newPlatform() Platform { return unixPlatform{} }

func (unixPlatform) IsWindows() bool  { return false }
func (unixPlatform) IsElevated() bool { return true }

// SecureDir beschränkt den Arbeitsordner auf den Besitzer. Gehört er jemand anderem (gemountetes Volume), bleibt es dabei.
func (unixPlatform) SecureDir(dir, extra string) error {
	if err := os.Chmod(dir, 0o700); err != nil && !errors.Is(err, os.ErrPermission) {
		return err
	}
	return nil
}

// ---- Geheimnisse (Tokens, PFX-Passwörter) ----
// AES-256-GCM. Der Schlüssel kommt aus ZA_SECRET_KEY oder ZA_SECRET_KEY_FILE; sonst wird im Arbeitsordner eine
// Schlüsseldatei angelegt. Liegt der Schlüssel im selben Ordner wie die Daten, schützt das nur vor zufälligem Mitlesen:
// Für echten Schutz ZA_SECRET_KEY getrennt von den Daten übergeben (z. B. als Docker-Secret).

func deriveSecretKey(s string) ([]byte, error) {
	k := make([]byte, 32)
	r := hkdf.New(sha256.New, []byte(s), []byte("certbumblebee/v1"), []byte("secret-protection"))
	if _, err := io.ReadFull(r, k); err != nil {
		return nil, err
	}
	return k, nil
}

var keyFileMu sync.Mutex

func secretKey() ([]byte, error) {
	if v := os.Getenv("ZA_SECRET_KEY"); v != "" {
		return deriveSecretKey(v)
	}
	if f := strings.TrimSpace(os.Getenv("ZA_SECRET_KEY_FILE")); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("Die Schlüsseldatei ZA_SECRET_KEY_FILE ist nicht lesbar: %v", err)
		}
		v := strings.TrimSpace(string(b))
		if v == "" {
			return nil, fmt.Errorf("Die Schlüsseldatei ZA_SECRET_KEY_FILE ist leer.")
		}
		return deriveSecretKey(v)
	}
	keyFileMu.Lock()
	defer keyFileMu.Unlock()
	path := filepath.Join(dataDir(), "secret.key")
	if b, err := os.ReadFile(path); err == nil {
		if k, err := hex.DecodeString(strings.TrimSpace(string(b))); err == nil && len(k) == 32 {
			return k, nil
		}
		return nil, fmt.Errorf("Die Schlüsseldatei %s ist beschädigt.", path)
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, []byte(hex.EncodeToString(k)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

const protectMagic = "UXG1"

func (unixPlatform) Protect(data []byte) ([]byte, error) {
	k, err := secretKey()
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte(protectMagic), nonce...)
	return g.Seal(out, nonce, data, []byte(protectMagic)), nil
}

func (unixPlatform) Unprotect(data []byte) ([]byte, error) {
	if len(data) < len(protectMagic) || string(data[:len(protectMagic)]) != protectMagic {
		return nil, fmt.Errorf("unbekanntes Format")
	}
	k, err := secretKey()
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	rest := data[len(protectMagic):]
	if len(rest) < g.NonceSize() {
		return nil, fmt.Errorf("Daten zu kurz")
	}
	pt, err := g.Open(nil, rest[:g.NonceSize()], rest[g.NonceSize():], []byte(protectMagic))
	if err != nil {
		return nil, fmt.Errorf("falscher Schlüssel oder beschädigte Daten")
	}
	return pt, nil
}

// InstallSelf: Unter Linux/macOS läuft die Erneuerung im Dauerbetrieb oder über „renew“ aus dem installierten
// Programm. Eine Kopie im Arbeitsordner ist nicht nötig.
func (unixPlatform) InstallSelf(dir string) (string, error) { return os.Executable() }

func fakeFile(name string) string { return filepath.Join(dataDir(), name) }

func fakeLoad(name string) map[string]TaskSpec {
	m := map[string]TaskSpec{}
	if b, err := os.ReadFile(fakeFile(name)); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func fakeSave(name string, m map[string]TaskSpec) error { return writeJSON(fakeFile(name), m) }

func (unixPlatform) TaskRegister(spec TaskSpec) error {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	spec.Password = ""
	m := fakeLoad("tasks.json")
	m[spec.Name] = spec
	return fakeSave("tasks.json", m)
}

func (unixPlatform) TaskExists(name string) (bool, error) {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	_, ok := fakeLoad("tasks.json")[name]
	return ok, nil
}

func (unixPlatform) TaskDelete(name string) error {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	m := fakeLoad("tasks.json")
	delete(m, name)
	return fakeSave("tasks.json", m)
}

func (unixPlatform) TaskRun(name string) error {
	fakeMu.Lock()
	spec, ok := fakeLoad("tasks.json")[name]
	fakeMu.Unlock()
	if !ok {
		return fmt.Errorf("Die Aufgabe „%s“ existiert nicht.", name)
	}
	cmd := exec.Command(spec.ExePath, strings.Fields(spec.Args)...)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

func (unixPlatform) FirewallAdd(rule, program string) error {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	m := fakeLoad("firewall.json")
	m[rule] = TaskSpec{Name: rule, ExePath: program}
	return fakeSave("firewall.json", m)
}

func (unixPlatform) FirewallRemove(rule string) error {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	m := fakeLoad("firewall.json")
	delete(m, rule)
	return fakeSave("firewall.json", m)
}

func (unixPlatform) OpenBrowser(url string) error { return nil }
func (unixPlatform) Drives() []string             { return nil }
func (unixPlatform) IsMappedDrive(string) bool    { return false }
func (unixPlatform) ComputerAccount() string {
	h, _ := os.Hostname()
	return strings.ToUpper(h) + "$"
}

func relaunchElevated() error { return nil }
func initConsole()            {}
