//go:build windows

package main

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	webview2 "github.com/jchv/go-webview2"
	"github.com/jchv/go-webview2/webviewloader"
	"golang.org/x/sys/windows"
)

var (
	user32dll         = windows.NewLazySystemDLL("user32.dll")
	procSetDPIAware   = user32dll.NewProc("SetProcessDPIAware")
	procGetDpiForSys  = user32dll.NewProc("GetDpiForSystem")
	procGetSysMetrics = user32dll.NewProc("GetSystemMetrics")
)

// systemScale liefert den Skalierungsfaktor der Anzeige (1.0 = 100 %).
func systemScale() float64 {
	if procGetDpiForSys.Find() == nil {
		if dpi, _, _ := procGetDpiForSys.Call(); dpi >= 96 {
			return float64(dpi) / 96
		}
	}
	return 1
}

func screenSize() (int, int) {
	w, _, _ := procGetSysMetrics.Call(0) // SM_CXSCREEN
	h, _, _ := procGetSysMetrics.Call(1) // SM_CYSCREEN
	return int(w), int(h)
}

// showError zeigt eine Fehlermeldung in einem Windows-Dialog. Das Programm hat keine Konsole,
// deshalb würde eine Textausgabe sonst niemand sehen.
func showError(title, text string) {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	_, _ = windows.MessageBox(0, m, t, windows.MB_OK|windows.MB_ICONERROR|windows.MB_SETFOREGROUND)
}

func askYesNo(title, text string) bool {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	r, _ := windows.MessageBox(0, m, t, windows.MB_YESNO|windows.MB_ICONQUESTION|windows.MB_DEFBUTTON2|windows.MB_SETFOREGROUND)
	return r == 6 // IDYES
}

// runWindow zeigt die Oberfläche in einem eigenen Programmfenster (Edge WebView2) und kehrt zurück,
// wenn das Fenster geschlossen wurde. Rückgabe false: Das Fenster ließ sich nicht öffnen
// (z. B. weil WebView2 auf dem Rechner fehlt). Dann übernimmt der Browser.
func runWindow(link string, s *server) bool {
	runtime.LockOSThread()
	if v, err := webviewloader.GetInstalledVersion(); err != nil {
		appLogGlobal("Fenster: WebView2 nicht gefunden: " + err.Error())
		return false
	} else {
		appLogGlobal("Fenster: WebView2 " + v)
	}
	_, _, _ = procSetDPIAware.Call()
	scale := systemScale()
	sw, sh := screenSize()
	width, height := int(1220*scale), int(900*scale)
	if sw > 0 && width > sw-int(40*scale) {
		width = sw - int(40*scale)
	}
	if sh > 0 && height > sh-int(80*scale) {
		height = sh - int(80*scale)
	}
	_ = os.RemoveAll(filepath.Join(dataDir(), "webview2")) // Rest der Version 1.1.0 (dort ließ er sich nicht benutzen)
	log.SetOutput(logWriter{})                             // Meldungen der WebView2-Bibliothek ins Protokoll statt ins Leere
	opts := webview2.WebViewOptions{
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title: appName, Width: uint(width), Height: uint(height), Center: true,
		},
		CloseGuard: func() bool {
			if anyJobRunning() {
				return askYesNo(appName, "Es läuft gerade ein Vorgang (z. B. das Ausstellen eines Zertifikats).\n\nWenn Sie das Fenster jetzt schließen, wird er abgebrochen. Trotzdem beenden?")
			}
			if s.wild.Load() {
				return askYesNo(appName, "Das Wildcard-Zertifikat wurde noch nicht heruntergeladen. Der private Schlüssel existiert nur in diesem Fenster und geht beim Schließen verloren.\n\nTrotzdem beenden?")
			}
			return true
		},
	}
	// Der Datenordner von WebView2 muss für den Benutzer und für die abgeschotteten Edge-Prozesse beschreibbar sein.
	// Der geschützte Arbeitsordner unter ProgramData (nur SYSTEM und Administratoren) genügt dafür nicht.
	// Üblich ist der Ordner im Benutzerprofil; ersatzweise der temporäre Ordner.
	var w webview2.WebView
	for _, data := range webviewDataDirs() {
		if err := os.MkdirAll(data, 0o700); err != nil {
			appLogGlobal("Fenster: Datenordner nicht anlegbar: " + data + ": " + err.Error())
			continue
		}
		opts.DataPath = data
		if w = webview2.NewWithOptions(opts); w != nil {
			appLogGlobal("Fenster: Datenordner " + data)
			break
		}
		appLogGlobal("Fenster: WebView2 ließ sich mit dem Datenordner nicht starten: " + data)
	}
	if w == nil {
		return false
	}
	w.SetSize(int(900*scale), int(640*scale), webview2.HintMin)
	go func() { // „Programm beenden“ in der Oberfläche oder Abschalten von außen schließt das Fenster
		<-s.done
		w.Destroy()
	}()
	w.Navigate(link)
	w.Run()
	return true
}

func webviewDataDirs() []string {
	var out []string
	if d := os.Getenv("LOCALAPPDATA"); d != "" {
		out = append(out, filepath.Join(d, appName, "webview2"))
	}
	return append(out, filepath.Join(os.TempDir(), appName+"-webview2"))
}

// logWriter leitet die Ausgabe des Standard-Loggers (WebView2-Bibliothek) ins Programmprotokoll.
type logWriter struct{}

func (logWriter) Write(p []byte) (int, error) {
	appLogGlobal("webview2: " + strings.TrimSpace(string(p)))
	return len(p), nil
}
