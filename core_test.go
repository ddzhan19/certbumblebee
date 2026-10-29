package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------- Hilfen ----------

func pebbleOnly(t *testing.T) {
	t.Helper()
	if os.Getenv("ZA_TEST_PEBBLE") == "" {
		t.Skip("ZA_TEST_PEBBLE nicht gesetzt (Pebble-Testserver nötig)")
	}
	t.Setenv("ZA_DATA", t.TempDir())
	t.Setenv("ZA_HTTP_PORT", "5002")
}

func baseReq(t *testing.T, domains string) CreateRequest {
	t.Helper()
	return CreateRequest{
		Domains: domains, Method: "standalone", TargetDir: filepath.Join(t.TempDir(), "ziel"),
		Password: "Müller-Pa$$wort 1!", Server: "custom", CustomURL: "https://localhost:14000/dir",
		AutoRenew: true, TaskTime: "04:15", RunAs: "system", Firewall: false,
	}
}

func create(t *testing.T, req CreateRequest) (*Profile, *RunResult, *Job, error) {
	t.Helper()
	p, err := buildProfile(req)
	if err != nil {
		t.Fatalf("buildProfile: %v", err)
	}
	j := newJob(p.ID)
	res, err := createProfile(context.Background(), p, req, j)
	if ue, ok := err.(*userError); ok && ue.Tech != "" {
		t.Logf("technische Details: %s", ue.Tech)
	}
	return p, res, j, err
}

func openssl(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("openssl", args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func stepState(j *Job, key string) string {
	for _, s := range j.view().Steps {
		if s.Key == key {
			return s.State
		}
	}
	return "?"
}

func leafOf(t *testing.T, id string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(profileDir(id), "fullchain.pem"))
	if err != nil {
		t.Fatal(err)
	}
	cs, err := parseCertsPEM(b)
	if err != nil {
		t.Fatal(err)
	}
	return cs[0]
}

// ---------- Reine Funktionen ----------

func TestNormalizeDomains(t *testing.T) {
	d, err := normalizeDomains("WWW.Beispiel.de, beispiel.de\nwww.beispiel.de.  bücher.example")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"www.beispiel.de", "beispiel.de", "xn--bcher-kva.example"}
	if fmt.Sprint(d) != fmt.Sprint(want) {
		t.Fatalf("got %v want %v", d, want)
	}
	for _, bad := range []string{"", "  ", "*.beispiel.de", "http://x.de", "x.de/pfad", "nodot", "a b@c.de", "-x.de", "x..de", strings.Repeat("a", 64) + ".de"} {
		if _, err := normalizeDomains(bad); err == nil {
			t.Errorf("%q sollte abgelehnt werden", bad)
		}
	}
	if _, err := normalizeDomains("*.beispiel.de"); err == nil || !strings.Contains(err.Error(), "Wildcard") {
		t.Errorf("Wildcard-Meldung fehlt: %v", err)
	}
}

func TestValidatePathWindows(t *testing.T) {
	ok := map[string]string{
		`D:\Zertifikate`:                `D:\Zertifikate`,
		`D:\Zertifikate\`:               `D:\Zertifikate`,
		`c:/x/y`:                        `c:\x\y`,
		`C:\`:                           `C:\`,
		`C:`:                            `C:\`, // wird unten gesondert geprüft
		`\\srv\share`:                   `\\srv\share`,
		`\\srv\share$\Sub Ordner\a`:     `\\srv\share$\Sub Ordner\a`,
		`\\192.168.1.5\zert`:            `\\192.168.1.5\zert`,
		`//srv/share/x`:                 `\\srv\share\x`,
		`D:\Über uns\Zertifikate`:       `D:\Über uns\Zertifikate`,
		`  \\fileserver\zertifikate$  `: `\\fileserver\zertifikate$`,
	}
	for in, want := range ok {
		if in == `C:` {
			continue // „C:“ ohne Backslash ist relativ und wird abgelehnt
		}
		got, err := validatePath(in, true, "T")
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "  ", `relativ\x`, "zert", `D:\a\\b`, `D:\a|b`, `D:\a"b`, `\\server`, `\\?\C:\x`, `D:\..\x`, `C:\a:b`, `D:\a*`, `\\srv\\share`, "D:\\a\u2019b", `C:`} {
		if _, err := validatePath(bad, true, "T"); err == nil {
			t.Errorf("%q sollte abgelehnt werden", bad)
		}
	}
}

func TestValidatePathPosix(t *testing.T) {
	if p, err := validatePath("/tmp//a/../b/", false, "T"); err == nil {
		t.Errorf("'..' muss abgelehnt werden, bekam %q", p)
	}
	if p, err := validatePath("/tmp//a/b/", false, "T"); err != nil || p != "/tmp/a/b" {
		t.Errorf("got %q, %v", p, err)
	}
	if _, err := validatePath("relativ", false, "T"); err == nil {
		t.Error("relativ muss abgelehnt werden")
	}
}

func TestRenewDue(t *testing.T) {
	now := time.Now()
	mk := func(life, remaining time.Duration) *x509.Certificate {
		return &x509.Certificate{NotBefore: now.Add(remaining - life), NotAfter: now.Add(remaining)}
	}
	day := 24 * time.Hour
	cases := []struct {
		life, rem time.Duration
		due       bool
	}{
		{90 * day, 89 * day, false},
		{90 * day, 31 * day, false},
		{90 * day, 29 * day, true},
		{45 * day, 16 * day, false},
		{45 * day, 14 * day, true},
		{6 * day, 3 * day, false},
		{6 * day, 1 * day, true},
		{5 * 365 * day, 100 * day, false},
		{90 * day, -1 * day, true},
	}
	for _, c := range cases {
		if got := renewDue(mk(c.life, c.rem), now); got != c.due {
			t.Errorf("Laufzeit %v, Rest %v: got %v want %v", c.life/day, c.rem/day, got, c.due)
		}
	}
}

func TestBuildProfileValidation(t *testing.T) {
	t.Setenv("ZA_DATA", t.TempDir())
	good := CreateRequest{Domains: "www.beispiel.de beispiel.de", TargetDir: "/srv/ziel", Password: "x", AutoRenew: true}
	p, err := buildProfile(good)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "www.beispiel.de" || p.FileName != "www.beispiel.de.pfx" || p.Task.Name != "Certbumblebee Erneuerung www.beispiel.de" ||
		p.Task.Time != "03:00" || p.Task.RunAs != "SYSTEM" || p.KeyBits != 2048 || p.PfxFormat != "compat" || p.DirectoryURL != dirProd {
		t.Fatalf("Standardwerte: %+v", p)
	}
	mod := func(f func(*CreateRequest)) CreateRequest { r := good; f(&r); return r }
	bad := map[string]CreateRequest{
		"Domain fehlt":       mod(func(r *CreateRequest) { r.Domains = "" }),
		"Wildcard":           mod(func(r *CreateRequest) { r.Domains = "*.beispiel.de" }),
		"Ziel relativ":       mod(func(r *CreateRequest) { r.TargetDir = "ziel" }),
		"Passwort fehlt":     mod(func(r *CreateRequest) { r.Password = "" }),
		"Dateiname":          mod(func(r *CreateRequest) { r.FileName = `a\b.pfx` }),
		"Server http":        mod(func(r *CreateRequest) { r.Server = "custom"; r.CustomURL = "http://ca.example/dir" }),
		"E-Mail":             mod(func(r *CreateRequest) { r.Email = "kaputt" }),
		"Uhrzeit":            mod(func(r *CreateRequest) { r.TaskTime = "25:00" }),
		"Konto":              mod(func(r *CreateRequest) { r.RunAs = "user"; r.User = "evil'user" }),
		"Schlüssel":          mod(func(r *CreateRequest) { r.KeyBits = 1024 }),
		"Webroot leer":       mod(func(r *CreateRequest) { r.Method = "webroot" }),
		"Webroot ungültig":   mod(func(r *CreateRequest) { r.Method = "webroot"; r.Webroot = "relativ" }),
		"Aufgabenname":       mod(func(r *CreateRequest) { r.TaskName = `a\b` }),
		"Methode":            mod(func(r *CreateRequest) { r.Method = "unbekannt" }),
		"DNS ohne Zugang":    mod(func(r *CreateRequest) { r.Method = "dns" }),
		"Passwort mit Umbr.": mod(func(r *CreateRequest) { r.Password = "a\nb" }),
	}
	for name, r := range bad {
		if _, err := buildProfile(r); err == nil {
			t.Errorf("%s: sollte abgelehnt werden", name)
		}
	}
	// Loopback-http ist für Tests erlaubt
	if _, err := buildProfile(mod(func(r *CreateRequest) { r.Server = "custom"; r.CustomURL = "http://127.0.0.1:1234/dir" })); err != nil {
		t.Errorf("Loopback-http: %v", err)
	}
}

func TestPSScriptsBalanced(t *testing.T) {
	for name, body := range map[string]string{"register": psTaskRegister, "exists": psTaskExists, "delete": psTaskDelete, "run": psTaskRun, "fwadd": psFirewallAdd, "fwdel": psFirewallRemove} {
		s := wrapPS(body)
		var stack []rune
		pairs := map[rune]rune{')': '(', '}': '{', ']': '['}
		inQ := false
		for _, r := range s {
			if inQ {
				if r == '\'' {
					inQ = false
				}
				continue
			}
			switch r {
			case '\'':
				inQ = true
			case '(', '{', '[':
				stack = append(stack, r)
			case ')', '}', ']':
				if len(stack) == 0 || stack[len(stack)-1] != pairs[r] {
					t.Fatalf("%s: Klammer %c passt nicht", name, r)
				}
				stack = stack[:len(stack)-1]
			}
		}
		if inQ || len(stack) != 0 {
			t.Fatalf("%s: nicht ausgeglichen (Anführungszeichen offen: %v, Klammern: %q)", name, inQ, string(stack))
		}
		if strings.Contains(s, "$env:ZA_TASK_PASS") && !strings.Contains(s, "-Password $env:ZA_TASK_PASS") {
			t.Fatalf("%s: Passwort muss aus der Umgebung kommen", name)
		}
	}
}

// ---------- Ende zu Ende gegen Pebble (echte HTTP-01-Prüfung) ----------

func TestPebbleStandaloneLifecycle(t *testing.T) {
	pebbleOnly(t)
	for _, format := range []string{"compat", "aes"} {
		t.Run(format, func(t *testing.T) {
			t.Setenv("ZA_DATA", t.TempDir())
			req := baseReq(t, "www.pebble-test.example pebble-test.example")
			req.PfxFormat = format
			p, res, job, err := create(t, req)
			if err != nil {
				t.Fatalf("createProfile: %v", err)
			}
			if res.Result != "ausgestellt" || !res.Written {
				t.Fatalf("Ergebnis: %+v", res)
			}
			for _, k := range []string{"einrichtung", "vorbereitung", "konto", "bestellung", "pruefung", "zertifikat", "pfx", "ziel", "aufgabe"} {
				if s := stepState(job, k); s != "ok" {
					t.Errorf("Schritt %s: %s", k, s)
				}
			}
			dest := filepath.Join(p.TargetDir, p.FileName)
			// OpenSSL 3 muss die Datei mit Umlaut-Passwort lesen können
			out := openssl(t, "", "pkcs12", "-in", dest, "-passin", "pass:"+req.Password, "-nokeys", "-legacy")
			if n := strings.Count(out, "BEGIN CERTIFICATE"); n < 2 {
				t.Errorf("Kette: nur %d Zertifikat(e)", n)
			}
			key := openssl(t, "", "pkcs12", "-in", dest, "-passin", "pass:"+req.Password, "-nocerts", "-nodes", "-legacy")
			leafPEM := openssl(t, "", "pkcs12", "-in", dest, "-passin", "pass:"+req.Password, "-nokeys", "-clcerts", "-legacy")
			m1 := openssl(t, leafPEM, "x509", "-noout", "-modulus")
			m2 := openssl(t, key, "rsa", "-noout", "-modulus")
			if m1 != m2 {
				t.Error("Schlüssel passt nicht zum Zertifikat")
			}
			san := openssl(t, leafPEM, "x509", "-noout", "-ext", "subjectAltName")
			if !strings.Contains(san, "www.pebble-test.example") || !strings.Contains(san, "DNS:pebble-test.example") {
				t.Errorf("SAN: %s", san)
			}
			// Aufgabe ist (in der Attrappe) eingetragen
			if ok, _ := plat.TaskExists(p.Task.Name); !ok {
				t.Error("Aufgabe nicht eingetragen")
			}

			// 2. Lauf: nicht fällig, nichts ändert sich
			serial1 := leafOf(t, p.ID).SerialNumber.String()
			j2 := newJob(p.ID)
			r2, err := renewProfile(context.Background(), p.ID, false, j2)
			if err != nil || r2.Result != "nicht-faellig" || r2.Written {
				t.Fatalf("2. Lauf: %+v %v", r2, err)
			}
			if leafOf(t, p.ID).SerialNumber.String() != serial1 {
				t.Error("Zertifikat wurde unnötig erneuert")
			}

			// Zielordner geleert (z. B. Freigabe war weg): wird nachgeliefert, ohne neues Zertifikat
			_ = os.Remove(dest)
			r3, err := renewProfile(context.Background(), p.ID, false, newJob(p.ID))
			if err != nil || !r3.Written || r3.Result != "nicht-faellig" {
				t.Fatalf("Nachlieferung: %+v %v", r3, err)
			}
			if _, err := os.Stat(dest); err != nil {
				t.Error("PFX wurde nicht nachgeliefert")
			}

			// Erzwungene Erneuerung: neue Seriennummer, Datei im Ziel ersetzt
			before, _ := fileSHA256(dest)
			r4, err := renewProfile(context.Background(), p.ID, true, newJob(p.ID))
			if err != nil || r4.Result != "erneuert" || !r4.Written {
				t.Fatalf("Erneuerung: %+v %v", r4, err)
			}
			after, _ := fileSHA256(dest)
			if before == after || leafOf(t, p.ID).SerialNumber.String() == serial1 {
				t.Error("Erneuerung hat nichts verändert")
			}
			if _, err := os.Stat(dest + ".tmp"); err == nil {
				t.Error("Hilfsdatei .tmp liegt noch im Zielordner")
			}

			// Löschen entfernt Aufgabe und Daten, aber nicht die PFX
			if err := deleteProfile(p.ID, &collectReporter{id: p.ID}); err != nil {
				t.Fatal(err)
			}
			if ok, _ := plat.TaskExists(p.Task.Name); ok {
				t.Error("Aufgabe nach dem Löschen noch vorhanden")
			}
			if _, err := os.Stat(profileDir(p.ID)); err == nil {
				t.Error("Profilordner nach dem Löschen noch vorhanden")
			}
			if _, err := os.Stat(dest); err != nil {
				t.Error("PFX im Zielordner wurde mitgelöscht")
			}
		})
	}
}

func TestPebbleExistsAndReplace(t *testing.T) {
	pebbleOnly(t)
	req := baseReq(t, "doppelt.pebble-test.example")
	if _, _, _, err := create(t, req); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := create(t, req); err != errExists {
		t.Fatalf("erwartet errExists, bekam %v", err)
	}
	req.Replace = true
	if _, res, _, err := create(t, req); err != nil || res.Result != "ausgestellt" {
		t.Fatalf("Ersetzen: %v %+v", err, res)
	}
}

func TestPebbleWebroot(t *testing.T) {
	pebbleOnly(t)
	web1, web2 := t.TempDir(), t.TempDir()
	// „vorhandener Webserver“ auf dem Prüfport, der die Ordner ausliefert
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(web1)))
	ln, err := net.Listen("tcp", ":5002")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	req := baseReq(t, "web.pebble-test.example")
	req.Method = "webroot"
	req.Webroot = web1 + "\n" + web2
	req.AutoRenew = false
	p, res, job, err := create(t, req)
	if err != nil {
		t.Fatalf("createProfile: %v", err)
	}
	if res.Result != "ausgestellt" || stepState(job, "pruefung") != "ok" {
		t.Fatalf("%+v", res)
	}
	if _, err := os.Stat(filepath.Join(challengeDir(web1), "web.config")); err != nil {
		t.Error("web.config für IIS fehlt")
	}
	ents, _ := os.ReadDir(challengeDir(web1))
	for _, e := range ents {
		if e.Name() != "web.config" {
			t.Errorf("Bestätigungsdatei nicht aufgeräumt: %s", e.Name())
		}
	}
	if _, err := os.Stat(filepath.Join(p.TargetDir, p.FileName)); err != nil {
		t.Error("PFX fehlt")
	}
	if ok, _ := plat.TaskExists(p.Task.Name); ok {
		t.Error("Aufgabe ohne Auftrag angelegt")
	}
}

func TestPebbleFailures(t *testing.T) {
	pebbleOnly(t)

	t.Run("Port belegt", func(t *testing.T) {
		ln, err := net.Listen("tcp", ":5002")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		req := baseReq(t, "belegt.pebble-test.example")
		p, _, job, err := create(t, req)
		if err == nil || !strings.Contains(err.Error(), "Port 5002 ist auf diesem Server belegt") {
			t.Fatalf("Meldung: %v", err)
		}
		if stepState(job, "vorbereitung") != "fail" {
			t.Error("Schritt nicht als fehlgeschlagen markiert")
		}
		if _, e := os.Stat(profileDir(p.ID)); e == nil {
			t.Error("Nach dem Fehler blieb ein Profil zurück")
		}
		if ok, _ := plat.TaskExists(p.Task.Name); ok {
			t.Error("Nach dem Fehler blieb eine Aufgabe zurück")
		}
	})

	t.Run("Domain zeigt ins Leere", func(t *testing.T) {
		// Test-DNS: diese Domain zeigt auf eine Adresse, an der nichts lauscht
		// alte Einträge löschen: add-a hängt Adressen an, statt sie zu ersetzen
		if r, err := http.Post("http://127.0.0.1:8055/clear-a", "application/json",
			strings.NewReader(`{"host":"leer.pebble-test.example"}`)); err == nil {
			r.Body.Close()
		}
		body := strings.NewReader(`{"host":"leer.pebble-test.example","addresses":["192.0.2.1"]}`)
		resp, err := http.Post("http://127.0.0.1:8055/add-a", "application/json", body)
		if err != nil {
			t.Skipf("challtestsrv nicht erreichbar: %v", err)
		}
		resp.Body.Close()
		req := baseReq(t, "leer.pebble-test.example")
		p, _, _, err := create(t, req)
		if err == nil || !strings.Contains(err.Error(), "nicht auf Port 80 erreichen") {
			t.Fatalf("Meldung: %v", err)
		}
		var ue *userError
		if e, ok := err.(*userError); ok {
			ue = e
		}
		if ue == nil || ue.Tech == "" {
			t.Error("technische Details fehlen")
		}
		if _, e := os.Stat(profileDir(p.ID)); e == nil {
			t.Error("Nach dem Fehler blieb ein Profil zurück")
		}
	})

	t.Run("Zielordner nicht beschreibbar", func(t *testing.T) {
		req := baseReq(t, "ziel.pebble-test.example")
		dir := t.TempDir()
		file := filepath.Join(dir, "ist-eine-datei")
		_ = os.WriteFile(file, []byte("x"), 0o600)
		req.TargetDir = filepath.Join(file, "unter") // Ordner unter einer Datei
		_, _, _, err := create(t, req)
		if err == nil || !strings.Contains(err.Error(), "Zielordner") {
			t.Fatalf("Meldung: %v", err)
		}
		if _, e := os.Stat(profileDir("ziel.pebble-test.example")); e == nil {
			t.Error("Nach dem Fehler blieb ein Profil zurück")
		}
	})
}

func TestPebbleSecretStaysProtected(t *testing.T) {
	pebbleOnly(t)
	req := baseReq(t, "geheim.pebble-test.example")
	p, _, _, err := create(t, req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(profileDir(p.ID), "pfx.secret"))
	if strings.Contains(string(b), req.Password) {
		t.Error("Passwort steht im Klartext in pfx.secret")
	}
	pj, _ := os.ReadFile(filepath.Join(profileDir(p.ID), "profile.json"))
	if strings.Contains(string(pj), req.Password) {
		t.Error("Passwort steht in profile.json")
	}
	if got, err := loadSecret(p.ID); err != nil || got != req.Password {
		t.Errorf("Passwort lässt sich nicht zurücklesen: %q %v", got, err)
	}
	// Schlüssel im Profilordner ist PKCS#8-PEM und nur für den Besitzer lesbar
	kb, _ := os.ReadFile(filepath.Join(profileDir(p.ID), "privkey.pem"))
	if blk, _ := pem.Decode(kb); blk == nil || blk.Type != "PRIVATE KEY" {
		t.Error("privkey.pem hat kein erwartetes Format")
	}
	if fi, _ := os.Stat(filepath.Join(profileDir(p.ID), "privkey.pem")); fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("privkey.pem ist zu offen: %v", fi.Mode())
	}
}
