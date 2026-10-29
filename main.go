package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"
)

func usage() {
	fmt.Printf(`%s %s – programmiert von %s

Aufruf:
  %s                      Oberfläche starten (Programmfenster)
  %s ui [--port N] [--browser] [--no-browser]
  %s renew --id KENNUNG [--force]   Zertifikat prüfen und bei Bedarf erneuern
  %s renew --all [--force]          alle eingerichteten Zertifikate
  %s list                           eingerichtete Zertifikate anzeigen
  %s version

Ohne Befehl startet die Oberfläche. Die automatische Erneuerung ruft „renew“ über die Aufgabenplanung auf.
`, appName, appVersion, appAuthor, appExeName, appExeName, appExeName, appExeName, appExeName, appExeName)
}

func main() {
	initConsole()
	args := os.Args[1:]
	cmd := "ui"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "ui":
		os.Exit(cmdUI(args))
	case "renew":
		os.Exit(cmdRenew(args))
	case "list":
		os.Exit(cmdList())
	case "version":
		fmt.Printf("%s %s (programmiert von %s)\n", appName, appVersion, appAuthor)
	case "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

func pauseIfInteractive() {
	if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		fmt.Print("\nZum Beenden die Eingabetaste drücken …")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	}
}

func cmdUI(args []string) int {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	port := fs.String("port", "", "Port der Oberfläche (Standard 8765)")
	noBrowser := fs.Bool("no-browser", false, "Browser nicht automatisch öffnen")
	inBrowser := fs.Bool("browser", false, "Oberfläche im Browser statt im Programmfenster anzeigen")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fmt.Printf("%s %s – programmiert von %s\n\n", appName, appVersion, appAuthor)

	if plat.IsWindows() && !plat.IsElevated() && os.Getenv("ZA_NO_ELEVATE") == "" {
		fmt.Println("Für das Anlegen von Aufgaben und Zugriffsrechten braucht das Programm Administratorrechte.")
		fmt.Println("Windows fragt jetzt nach Ihrer Bestätigung und startet das Programm neu …")
		if err := relaunchElevated(); err != nil {
			fmt.Println("\nDer Neustart mit Administratorrechten wurde abgebrochen:", err)
			fmt.Println("Bitte die Datei per Rechtsklick „Als Administrator ausführen“ starten.")
			showError(appName, "Der Neustart mit Administratorrechten wurde abgebrochen.\n\nBitte die Datei per Rechtsklick „Als Administrator ausführen“ starten.")
			pauseIfInteractive()
			return 1
		}
		return 0
	}

	want := *port
	if want == "" {
		want = os.Getenv("ZA_PORT")
	}
	if want == "" {
		want = "8765"
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+want)
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Println("Der lokale Webserver konnte nicht gestartet werden:", err)
			showError(appName, "Der lokale Webserver für die Oberfläche konnte nicht gestartet werden:\n"+err.Error())
			pauseIfInteractive()
			return 1
		}
	}
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	s := newServer(p)
	link := s.newStartLink()

	windowed := plat.IsWindows() && !*inBrowser && os.Getenv("ZA_BROWSER") == ""
	s.window.Store(windowed)
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.serve(ln) }()

	if windowed {
		fmt.Println("Die Oberfläche öffnet sich in einem Programmfenster.")
		if runWindow(link, s) { // kehrt zurück, wenn das Fenster geschlossen wurde
			s.shutdown()
			select {
			case <-serveErr:
			case <-time.After(4 * time.Second):
			}
			return 0
		}
		// Kein Fenster möglich (z. B. fehlt WebView2): Die Oberfläche läuft stattdessen im Browser.
		s.window.Store(false)
		appLogGlobal("Programmfenster nicht möglich, Browser wird verwendet")
	}

	fmt.Println("Die Oberfläche läuft nur auf diesem Computer (127.0.0.1).")
	fmt.Println("Link:", link)
	fmt.Println("\nEingabetaste: neuen Link erzeugen   |   Strg+C oder Fenster schließen: beenden")
	if !*noBrowser && os.Getenv("ZA_NO_BROWSER") == "" {
		if err := plat.OpenBrowser(link); err != nil {
			fmt.Println("Der Browser konnte nicht geöffnet werden. Bitte den Link oben kopieren.")
			showError(appName, "Das Programmfenster ließ sich nicht öffnen (Edge WebView2 fehlt?) und auch der Browser nicht.\n\nBitte diesen Link im Browser öffnen:\n"+link)
		}
	}

	go func() { // Eingabetaste = neuer Einmal-Link
		r := bufio.NewReader(os.Stdin)
		for {
			if _, err := r.ReadString('\n'); err != nil {
				return
			}
			nl := s.newStartLink()
			fmt.Println("Neuer Link:", nl)
			if !*noBrowser && os.Getenv("ZA_NO_BROWSER") == "" {
				_ = plat.OpenBrowser(nl)
			}
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; s.shutdown() }()

	if err := <-serveErr; err != nil && !strings.Contains(err.Error(), "closed") {
		fmt.Println("Fehler:", err)
		return 1
	}
	fmt.Println("Beendet.")
	return 0
}

func cmdRenew(args []string) int {
	fs := flag.NewFlagSet("renew", flag.ContinueOnError)
	id := fs.String("id", "", "Kennung des Zertifikats")
	all := fs.Bool("all", false, "alle Zertifikate")
	force := fs.Bool("force", false, "Erneuerung erzwingen")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if plat.IsWindows() && !plat.IsElevated() {
		fmt.Fprintln(os.Stderr, "FEHLER: Bitte als Administrator ausführen (die Daten liegen in einem geschützten Ordner).")
		return 1
	}
	var ids []string
	switch {
	case *all:
		ids = listProfileIDs()
		if len(ids) == 0 {
			fmt.Println("Es sind keine Zertifikate eingerichtet.")
			return 0
		}
	case *id != "":
		ids = []string{*id}
	default:
		fmt.Fprintln(os.Stderr, "FEHLER: Bitte --id KENNUNG oder --all angeben.")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Minute)
	defer cancel()
	code := 0
	for _, i := range ids {
		fmt.Printf("\n=== %s ===\n", i)
		rep := consoleReporter{id: i}
		res, err := renewProfile(ctx, i, *force, rep)
		if err != nil {
			fmt.Fprintln(os.Stderr, "FEHLER:", err)
			appLog(i, "ERROR", err.Error())
			code = 1
			continue
		}
		fmt.Println(res.Message)
	}
	return code
}

func cmdList() int {
	ps := listProfiles()
	if len(ps) == 0 {
		fmt.Println("Es sind keine Zertifikate eingerichtet.")
		return 0
	}
	for _, p := range ps {
		until := "–"
		if p.Cert != nil {
			until = fmt.Sprintf("%s (%d Tage)", p.Cert.NotAfter.Local().Format("02.01.2006"), p.DaysLeft)
		}
		fmt.Printf("%-40s gültig bis %-22s Ziel: %s  [%s]\n", p.ID, until, p.TargetDir, p.LastResult)
	}
	return 0
}
