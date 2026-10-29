//go:build windows

package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsPlatform struct{}

func newPlatform() Platform { return windowsPlatform{} }

func (windowsPlatform) IsWindows() bool { return true }

func (windowsPlatform) IsElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

func hidden(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

func runCmd(name string, args ...string) (string, error) {
	var out bytes.Buffer
	cmd := hidden(exec.Command(name, args...))
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

// SecureDir: nur SYSTEM und Administratoren (und optional ein Konto) dürfen in den Ordner.
func (windowsPlatform) SecureDir(dir, extra string) error {
	if out, err := runCmd("icacls.exe", dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F"); err != nil {
		return fmt.Errorf("icacls: %v %s", err, out)
	}
	if extra != "" {
		if out, err := runCmd("icacls.exe", dir, "/grant:r", extra+":(OI)(CI)M"); err != nil {
			return fmt.Errorf("Das Konto „%s“ wurde nicht gefunden oder erhielt keine Rechte am Arbeitsordner: %v %s", extra, err, out)
		}
	}
	return nil
}

// DPAPI im Computer-Bereich: Die Datei ist nur auf diesem Server lesbar.
func (windowsPlatform) Protect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("leere Eingabe")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN|windows.CRYPTPROTECT_LOCAL_MACHINE, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func (windowsPlatform) Unprotect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("leere Eingabe")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

// InstallSelf kopiert das Programm in den geschützten Arbeitsordner. Die Aufgabe startet SYSTEM von dort und
// nicht aus einem Ordner, in den normale Benutzer schreiben dürfen.
func (windowsPlatform) InstallSelf(dir string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	dest := filepath.Join(dir, appExeName)
	if strings.EqualFold(filepath.Clean(self), filepath.Clean(dest)) {
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
	if err := os.WriteFile(dest+".new", b, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(dest+".new", dest); err != nil {
		_ = os.Remove(dest + ".new")
		return "", err
	}
	return dest, nil
}

func psExe() string {
	if r := os.Getenv("SystemRoot"); r != "" {
		p := filepath.Join(r, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "powershell.exe"
}

// runPS führt ein PowerShell-Skript aus. Rückgabe: Ausgabe, Exit-Code, Fehler beim Start.
func runPS(body string, env map[string]string) (string, int, error) {
	u := utf16.Encode([]rune(wrapPS(body)))
	buf := make([]byte, 0, len(u)*2)
	for _, c := range u {
		buf = append(buf, byte(c), byte(c>>8))
	}
	cmd := hidden(exec.Command(psExe(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-OutputFormat", "Text", "-EncodedCommand", base64.StdEncoding.EncodeToString(buf)))
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	text := strings.TrimSpace(out.String())
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return text, ee.ExitCode(), nil
	}
	return text, 0, err
}

func psMust(body string, env map[string]string) error {
	out, code, err := runPS(body, env)
	if err != nil {
		return err
	}
	if code != 0 {
		if out == "" {
			out = fmt.Sprintf("PowerShell beendete sich mit Code %d", code)
		}
		return errors.New(out)
	}
	return nil
}

func (windowsPlatform) TaskRegister(s TaskSpec) error {
	return psMust(psTaskRegister, map[string]string{
		"ZA_TASK_NAME": s.Name, "ZA_TASK_EXE": s.ExePath, "ZA_TASK_ARGS": s.Args, "ZA_TASK_WORK": s.WorkDir,
		"ZA_TASK_TIME": s.Time, "ZA_TASK_USER": s.RunAs, "ZA_TASK_PASS": s.Password,
	})
}

func (windowsPlatform) TaskExists(name string) (bool, error) {
	out, code, err := runPS(psTaskExists, map[string]string{"ZA_TASK_NAME": name})
	if err != nil {
		return false, err
	}
	switch code {
	case 0:
		return true, nil
	case 3:
		return false, nil
	}
	return false, errors.New(out)
}

func (windowsPlatform) TaskDelete(name string) error {
	return psMust(psTaskDelete, map[string]string{"ZA_TASK_NAME": name})
}

func (windowsPlatform) TaskRun(name string) error {
	return psMust(psTaskRun, map[string]string{"ZA_TASK_NAME": name})
}

func (windowsPlatform) FirewallAdd(rule, program string) error {
	return psMust(psFirewallAdd, map[string]string{"ZA_FW_NAME": rule, "ZA_FW_PROGRAM": program, "ZA_FW_PORT": httpPort()})
}

func (windowsPlatform) FirewallRemove(rule string) error {
	return psMust(psFirewallRemove, map[string]string{"ZA_FW_NAME": rule})
}

func (windowsPlatform) OpenBrowser(url string) error {
	return hidden(exec.Command("rundll32", "url.dll,FileProtocolHandler", url)).Start()
}

func (windowsPlatform) Drives() []string {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	var out []string
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		switch windows.GetDriveType(windows.StringToUTF16Ptr(root)) {
		case windows.DRIVE_FIXED, windows.DRIVE_REMOTE, windows.DRIVE_REMOVABLE:
			out = append(out, root)
		}
	}
	return out
}

func (windowsPlatform) IsMappedDrive(p string) bool {
	if len(p) < 2 || p[1] != ':' {
		return false
	}
	return windows.GetDriveType(windows.StringToUTF16Ptr(p[:2]+`\`)) == windows.DRIVE_REMOTE
}

func (windowsPlatform) ComputerAccount() string {
	return os.Getenv("USERDOMAIN") + `\` + os.Getenv("COMPUTERNAME") + "$"
}

// relaunchElevated startet das Programm mit Administratorrechten neu (Windows fragt per UAC nach).
func relaunchElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var parts []string
	for _, a := range os.Args[1:] {
		parts = append(parts, syscall.EscapeArg(a))
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	par, _ := windows.UTF16PtrFromString(strings.Join(parts, " "))
	cwd, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	return windows.ShellExecute(0, verb, file, par, cwd, windows.SW_NORMAL)
}

// initConsole: Das Programm ist eine Fenster-Anwendung ohne eigene Konsole. Wird es aus einer Konsole gestartet
// (z. B. „renew“ oder „list“), hängt es sich an diese an und stellt sie auf UTF-8, damit Umlaute stimmen.
func initConsole() {
	k := windows.NewLazySystemDLL("kernel32.dll")
	const attachParentProcess = 0xFFFFFFFF
	if r, _, _ := k.NewProc("AttachConsole").Call(attachParentProcess); r == 0 {
		return
	}
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout, os.Stderr = f, f
	}
	if f, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err == nil {
		os.Stdin = f
	}
	_, _, _ = k.NewProc("SetConsoleOutputCP").Call(65001)
}
