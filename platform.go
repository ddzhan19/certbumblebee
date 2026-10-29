package main

import "runtime"

// Platform kapselt alles, was vom Betriebssystem abhängt. Unter Windows werden Aufgabenplanung,
// Firewall, Rechte und Passwortschutz angesprochen, unter Linux (Tests) eine Attrappe.
type Platform interface {
	IsWindows() bool
	IsElevated() bool
	SecureDir(dir, extraAccount string) error
	Protect(data []byte) ([]byte, error)
	Unprotect(data []byte) ([]byte, error)
	InstallSelf(dir string) (string, error)
	TaskRegister(spec TaskSpec) error
	TaskExists(name string) (bool, error)
	TaskDelete(name string) error
	TaskRun(name string) error
	FirewallAdd(rule, program string) error
	FirewallRemove(rule string) error
	OpenBrowser(url string) error
	Drives() []string
	IsMappedDrive(path string) bool
	ComputerAccount() string
}

type TaskSpec struct {
	Name     string
	ExePath  string
	Args     string
	WorkDir  string
	Time     string // HH:MM
	RunAs    string // "SYSTEM" oder Konto
	Password string // nur bei Konto
}

var plat Platform = newPlatform()

func osIsWindows() bool { return runtime.GOOS == "windows" }
