package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

func envOr(def string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return def
}

func envOn(k string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(k))) {
	case "1", "true", "yes", "ja", "on":
		return true
	}
	return false
}

// cmdServe ist der Dauerbetrieb: Oberfläche mit Passwort und eigener Zeitplan für die Erneuerung.
func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "", "Adresse und Port (Standard :8080, oder ZA_LISTEN)")
	noSched := fs.Bool("no-scheduler", false, "keinen eigenen Zeitplan starten (Erneuerung dann per „renew“ von außen)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	logStdout.Store(true)
	fmt.Printf("%s %s – programmiert von %s\n", appName, appVersion, appAuthor)

	if err := os.MkdirAll(dataDir(), 0o755); err != nil {
		fmt.Println("FEHLER: Der Datenordner", dataDir(), "ist nicht beschreibbar:", err)
		return 1
	}
	_ = plat.SecureDir(dataDir(), "")
	if _, err := plat.Protect([]byte("test")); err != nil {
		fmt.Println("FEHLER: Der Schlüssel für gespeicherte Geheimnisse ist nicht verfügbar:", err)
		return 1
	}
	hash, source, generated, err := resolveAdminHash()
	if err != nil {
		fmt.Println("FEHLER:", err)
		return 1
	}
	if generated != "" {
		fmt.Println()
		fmt.Println("=====================================================================")
		fmt.Println(" Erster Start: Für die Oberfläche wurde ein Passwort erzeugt.")
		fmt.Println(" Es wird nur jetzt angezeigt und lässt sich mit „passwd“ ändern:")
		fmt.Println()
		fmt.Println("     " + generated)
		fmt.Println("=====================================================================")
		fmt.Println()
	}

	addr := *listen
	if addr == "" {
		addr = envOr(":8080", "ZA_LISTEN")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Println("FEHLER: Auf", addr, "lässt sich nicht lauschen:", err)
		return 1
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	trust := envOn("ZA_TRUST_PROXY")
	pa := newPasswordAuth(hash, trust)
	if source == "gespeichert" || source == "erzeugt" {
		pa.watchFile(adminPath())
	}
	s := newServerMode(port, pa, nil)
	s.tlsCert, s.tlsKey = strings.TrimSpace(os.Getenv("ZA_TLS_CERT")), strings.TrimSpace(os.Getenv("ZA_TLS_KEY"))
	if (s.tlsCert == "") != (s.tlsKey == "") {
		fmt.Println("FEHLER: ZA_TLS_CERT und ZA_TLS_KEY müssen zusammen angegeben werden.")
		return 1
	}
	if s.tlsCert != "" {
		if _, err := tls.LoadX509KeyPair(s.tlsCert, s.tlsKey); err != nil {
			fmt.Println("FEHLER: Zertifikat/Schlüssel für die Oberfläche nicht lesbar:", err)
			return 1
		}
	}

	clearStaleLocks()
	if !*noSched && !envOn("ZA_NO_SCHEDULER") {
		s.sched = newScheduler()
		s.sched.start()
	}

	scheme := "http"
	if s.tlsCert != "" {
		scheme = "https"
	}
	appLogGlobal(fmt.Sprintf("Dauerbetrieb gestartet: %s://%s (Passwort: %s), Datenordner %s, Zeitzone %s", scheme, ln.Addr(), source, dataDir(), time.Local))
	if s.tlsCert == "" && !trust && !isLoopbackAddr(ln.Addr()) {
		appLogGlobal("Hinweis: Die Oberfläche läuft ohne HTTPS. Das Passwort würde unverschlüsselt übertragen. Bitte einen Reverse-Proxy mit TLS davorsetzen (dann ZA_TRUST_PROXY=1) oder ZA_TLS_CERT/ZA_TLS_KEY setzen.")
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- s.serve(ln) }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	code := 0
	select {
	case <-sig:
		appLogGlobal("Beenden angefordert, räume auf …")
	case err := <-serveErr:
		if err != nil && !strings.Contains(err.Error(), "closed") {
			appLogGlobal("Fehler: " + err.Error())
			code = 1
		}
	}
	signal.Stop(sig) // ein zweites Signal beendet das Programm sofort
	s.shutdown()
	// Laufende Vorgänge (Zeitplan und Oberfläche) werden abgebrochen. Sie haben zusammen höchstens 25 Sekunden zum
	// Aufräumen (DNS-Einträge löschen u. a.), das passt in die Wartezeit von „docker stop“ (stop_grace_period: 30s).
	until := time.Now().Add(25 * time.Second)
	s.cancelJobs()
	if s.sched != nil {
		s.sched.stop(25 * time.Second)
	}
	if !s.waitJobs(time.Until(until)) {
		appLogGlobal("Hinweis: Ein Vorgang war nach 25 Sekunden noch nicht beendet. Übrig gebliebene DNS-Einträge bei Cloudflare räumt der nächste Lauf auf.")
	}
	select {
	case <-serveErr:
	case <-time.After(4 * time.Second):
	}
	appLogGlobal("Beendet.")
	return code
}

func isLoopbackAddr(a net.Addr) bool {
	ta, ok := a.(*net.TCPAddr)
	return ok && ta.IP.IsLoopback()
}

// clearStaleLocks entfernt Sperren eines früheren Laufs. Im Dauerbetrieb gibt es nur diesen einen Prozess,
// eine übrig gebliebene Sperre stammt daher aus einem Absturz oder Neustart.
func clearStaleLocks() {
	for _, id := range listProfileIDs() {
		_ = os.Remove(filepath.Join(profileDir(id), "run.lock"))
	}
}

// cmdHealthcheck fragt den eigenen Dauerbetrieb ab. Für HEALTHCHECK im Container, wo es kein curl gibt.
func cmdHealthcheck(args []string) int {
	addr := envOr(":8080", "ZA_LISTEN")
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Println("ZA_LISTEN ist ungültig:", addr)
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	scheme := "http"
	tr := &http.Transport{}
	if envOr("", "ZA_TLS_CERT") != "" {
		scheme = "https"
		// Nur die Abfrage des eigenen Prozesses auf dieser Maschine: Das Zertifikat passt oft nicht auf „127.0.0.1“.
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	c := &http.Client{Timeout: 5 * time.Second, Transport: tr}
	res, err := c.Get(scheme + "://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		fmt.Println("keine Antwort:", err)
		return 1
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		fmt.Println("Zustand schlecht: HTTP", res.StatusCode)
		return 1
	}
	fmt.Println("ok")
	return 0
}

// cmdPasswd setzt das Passwort der Oberfläche. Es gilt, sofern nicht ZA_PASSWORD/ZA_PASSWORD_HASH gesetzt sind.
func cmdPasswd(args []string) int {
	fs := flag.NewFlagSet("passwd", flag.ContinueOnError)
	fromStdin := fs.Bool("stdin", false, "Passwort aus der Standardeingabe lesen (eine Zeile)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var pw string
	if *fromStdin || !term.IsTerminal(int(os.Stdin.Fd())) {
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		pw = strings.TrimRight(line, "\r\n")
	} else {
		fmt.Print("Neues Passwort: ")
		a, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			fmt.Println("FEHLER:", err)
			return 1
		}
		fmt.Print("Noch einmal: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			fmt.Println("FEHLER:", err)
			return 1
		}
		if string(a) != string(b) {
			fmt.Println("FEHLER: Die Eingaben stimmen nicht überein.")
			return 1
		}
		pw = string(a)
	}
	if err := os.MkdirAll(dataDir(), 0o755); err != nil {
		fmt.Println("FEHLER:", err)
		return 1
	}
	if err := setAdminPassword(pw); err != nil {
		fmt.Println("FEHLER:", err)
		return 1
	}
	fmt.Println("Das Passwort wurde gespeichert. Es gilt sofort, angemeldete Sitzungen werden beendet.")
	if envOr("", "ZA_PASSWORD", "ZA_PASSWORD_FILE", "ZA_PASSWORD_HASH") != "" {
		fmt.Println("Hinweis: ZA_PASSWORD, ZA_PASSWORD_FILE oder ZA_PASSWORD_HASH ist gesetzt und hat Vorrang vor dem gespeicherten Passwort.")
	}
	return 0
}
