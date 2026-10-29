//go:build !windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// fakePlatform ersetzt unter Linux/macOS die Windows-Funktionen. Aufgaben und Firewall-Regeln werden nur in
// Dateien im Arbeitsordner vermerkt. „TaskRun“ startet die installierte Programmkopie wirklich.
type fakePlatform struct{}

var fakeMu sync.Mutex

func newPlatform() Platform { return fakePlatform{} }

func (fakePlatform) IsWindows() bool  { return false }
func (fakePlatform) IsElevated() bool { return true }

func (fakePlatform) SecureDir(dir, extra string) error { return os.Chmod(dir, 0o700) }

func (fakePlatform) Protect(data []byte) ([]byte, error) {
	return append([]byte("FAKE1:"), data...), nil
}

func (fakePlatform) Unprotect(data []byte) ([]byte, error) {
	if !strings.HasPrefix(string(data), "FAKE1:") {
		return nil, fmt.Errorf("unbekanntes Format")
	}
	return data[6:], nil
}

func (fakePlatform) InstallSelf(dir string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	dest := filepath.Join(dir, strings.TrimSuffix(appExeName, ".exe"))
	if self == dest {
		return dest, nil
	}
	sh, _ := fileSHA256(self)
	if dh, _ := fileSHA256(dest); dh != "" && dh == sh {
		return dest, nil
	}
	b, err := os.ReadFile(self)
	if err != nil {
		return "", err
	}
	if err := writeFileAtomic(dest+".new", b, 0o755); err != nil {
		return "", err
	}
	return dest, os.Rename(dest+".new", dest)
}

func fakeFile(name string) string { return filepath.Join(dataDir(), name) }

func fakeLoad(name string) map[string]TaskSpec {
	m := map[string]TaskSpec{}
	if b, err := os.ReadFile(fakeFile(name)); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func fakeSave(name string, m map[string]TaskSpec) error { return writeJSON(fakeFile(name), m) }

func (fakePlatform) TaskRegister(spec TaskSpec) error {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	spec.Password = ""
	m := fakeLoad("fake-tasks.json")
	m[spec.Name] = spec
	return fakeSave("fake-tasks.json", m)
}

func (fakePlatform) TaskExists(name string) (bool, error) {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	_, ok := fakeLoad("fake-tasks.json")[name]
	return ok, nil
}

func (fakePlatform) TaskDelete(name string) error {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	m := fakeLoad("fake-tasks.json")
	delete(m, name)
	return fakeSave("fake-tasks.json", m)
}

func (fakePlatform) TaskRun(name string) error {
	fakeMu.Lock()
	spec, ok := fakeLoad("fake-tasks.json")[name]
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

func (fakePlatform) FirewallAdd(rule, program string) error {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	m := fakeLoad("fake-firewall.json")
	m[rule] = TaskSpec{Name: rule, ExePath: program}
	return fakeSave("fake-firewall.json", m)
}

func (fakePlatform) FirewallRemove(rule string) error {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	m := fakeLoad("fake-firewall.json")
	delete(m, rule)
	return fakeSave("fake-firewall.json", m)
}

func (fakePlatform) OpenBrowser(url string) error { return nil }
func (fakePlatform) Drives() []string             { return nil }
func (fakePlatform) IsMappedDrive(string) bool    { return false }
func (fakePlatform) ComputerAccount() string {
	h, _ := os.Hostname()
	return strings.ToUpper(h) + "$"
}

func relaunchElevated() error { return nil }
func initConsole()            {}
