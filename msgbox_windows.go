//go:build windows

package main

import "golang.org/x/sys/windows"

// showError zeigt eine Fehlermeldung. Das Programm hat keine Konsole, deshalb würde eine Textausgabe sonst niemand sehen.
func showError(title, text string) {
	_, _ = windows.MessageBox(0, u16(text), u16(title), windows.MB_OK|windows.MB_ICONERROR|windows.MB_SETFOREGROUND)
}

func askYesNo(title, text string) bool {
	r, _ := windows.MessageBox(0, u16(text), u16(title), windows.MB_YESNO|windows.MB_ICONQUESTION|windows.MB_DEFBUTTON2|windows.MB_SETFOREGROUND)
	return r == idYes
}
