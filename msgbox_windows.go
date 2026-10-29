//go:build windows

package main

import (
	"syscall"

	"golang.org/x/sys/windows"
)

const idYes = 6

func u16(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

// showError zeigt eine Fehlermeldung. Das Programm hat keine Konsole, deshalb würde eine Textausgabe sonst niemand sehen.
func showError(title, text string) {
	_, _ = windows.MessageBox(0, u16(text), u16(title), windows.MB_OK|windows.MB_ICONERROR|windows.MB_SETFOREGROUND)
}

func askYesNo(title, text string) bool {
	r, _ := windows.MessageBox(0, u16(text), u16(title), windows.MB_YESNO|windows.MB_ICONQUESTION|windows.MB_DEFBUTTON2|windows.MB_SETFOREGROUND)
	return r == idYes
}
