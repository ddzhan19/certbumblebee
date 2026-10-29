package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testPW = "ein-langes-Passwort-42"

func fastAuth(t *testing.T) {
	t.Helper()
	oc, od := bcryptCost, loginFailDelay
	bcryptCost, loginFailDelay = 4, 0
	t.Cleanup(func() { bcryptCost, loginFailDelay = oc, od })
}

func newTestServer(t *testing.T, trust bool) (*server, http.Handler) {
	t.Helper()
	fastAuth(t)
	t.Setenv("ZA_DATA", t.TempDir())
	h, err := hashPassword(testPW)
	if err != nil {
		t.Fatal(err)
	}
	s := newServerMode("8080", newPasswordAuth(h, trust), nil)
	return s, s.handler()
}

func call(h http.Handler, method, path, host string, body any, mod func(*http.Request)) *httptest.ResponseRecorder {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Host = host
	req.RemoteAddr = "192.0.2.10:5555"
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-ZA", "1")
	}
	if mod != nil {
		mod(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func cookieOf(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "za_sid" {
			return c
		}
	}
	return nil
}

func TestServerModeLoginFlow(t *testing.T) {
	_, h := newTestServer(t, false)
	host := "zertifikate.firma.example:8080"

	// Die Seite selbst ist ohne Anmeldung erreichbar (enthält die Anmeldemaske), die Schnittstelle nicht.
	if rec := call(h, "GET", "/", host, nil, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "<html") {
		t.Fatalf("Startseite: %d", rec.Code)
	}
	rec := call(h, "GET", "/api/info", host, nil, nil)
	var b map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	if rec.Code != 401 || b["login"] != true {
		t.Fatalf("Info ohne Anmeldung: %d %v", rec.Code, b)
	}
	// Falsches Passwort
	if rec := call(h, "POST", "/api/login", host, map[string]string{"password": "falsch"}, nil); rec.Code != 401 || cookieOf(rec) != nil {
		t.Fatalf("falsches Passwort: %d", rec.Code)
	}
	// Richtiges Passwort
	rec = call(h, "POST", "/api/login", host, map[string]string{"password": testPW}, nil)
	c := cookieOf(rec)
	if rec.Code != 200 || c == nil || len(c.Value) != 64 || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Secure {
		t.Fatalf("Anmeldung: %d %+v", rec.Code, c)
	}
	withCookie := func(r *http.Request) { r.AddCookie(c) }
	rec = call(h, "GET", "/api/info", host, nil, withCookie)
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	if rec.Code != 200 || b["server"] != true {
		t.Fatalf("Info mit Sitzung: %d %v", rec.Code, b)
	}
	// Keine Beenden-Schnittstelle im Dauerbetrieb, keine Startlinks
	if rec := call(h, "POST", "/api/quit", host, map[string]any{}, withCookie); rec.Code == 200 {
		t.Error("/api/quit darf im Dauerbetrieb nicht antworten")
	}
	if rec := call(h, "GET", "/start?k=x", host, nil, nil); rec.Code == 200 || rec.Code == 303 {
		t.Errorf("/start im Dauerbetrieb: %d", rec.Code)
	}
	// Abmelden
	if rec := call(h, "POST", "/api/logout", host, map[string]any{}, withCookie); rec.Code != 200 {
		t.Fatalf("Abmelden: %d", rec.Code)
	}
	if rec := call(h, "GET", "/api/info", host, nil, withCookie); rec.Code != 401 {
		t.Errorf("Sitzung nach Abmeldung: %d", rec.Code)
	}
}

func TestServerModeRequestChecks(t *testing.T) {
	_, h := newTestServer(t, false)
	host := "srv.example:8080"
	rec := call(h, "POST", "/api/login", host, map[string]string{"password": testPW}, nil)
	c := cookieOf(rec)
	with := func(extra func(*http.Request)) func(*http.Request) {
		return func(r *http.Request) {
			r.AddCookie(c)
			if extra != nil {
				extra(r)
			}
		}
	}
	body := map[string]any{"name": "x", "token": "kurz"}
	// ohne X-ZA-Kopfzeile / falscher Inhaltstyp
	if rec := call(h, "POST", "/api/dns/accounts", host, body, with(func(r *http.Request) { r.Header.Del("X-ZA") })); rec.Code != 403 {
		t.Errorf("ohne X-ZA: %d", rec.Code)
	}
	if rec := call(h, "POST", "/api/dns/accounts", host, body, with(func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") })); rec.Code != 403 {
		t.Errorf("Inhaltstyp: %d", rec.Code)
	}
	// fremde Herkunft
	if rec := call(h, "POST", "/api/dns/accounts", host, body, with(func(r *http.Request) { r.Header.Set("Origin", "https://boese.example") })); rec.Code != 403 {
		t.Errorf("fremde Herkunft: %d", rec.Code)
	}
	// gleiche Herkunft (http oder https davor)
	for _, o := range []string{"http://srv.example:8080", "https://srv.example:8080"} {
		if rec := call(h, "POST", "/api/dns/accounts", host, body, with(func(r *http.Request) { r.Header.Set("Origin", o) })); rec.Code != 400 {
			t.Errorf("Herkunft %s: %d (400 für den ungültigen Token erwartet)", o, rec.Code)
		}
	}
	// Weitergeleiteter Host zählt nur mit ZA_TRUST_PROXY
	fwd := with(func(r *http.Request) {
		r.Header.Set("Origin", "https://zert.firma.example")
		r.Header.Set("X-Forwarded-Host", "zert.firma.example")
	})
	if rec := call(h, "POST", "/api/dns/accounts", host, body, fwd); rec.Code != 403 {
		t.Errorf("X-Forwarded-Host ohne Vertrauen: %d", rec.Code)
	}
	_, ht := newTestServer(t, true)
	rec = call(ht, "POST", "/api/login", host, map[string]string{"password": testPW}, nil)
	c = cookieOf(rec)
	if rec := call(ht, "POST", "/api/dns/accounts", host, body, fwd); rec.Code != 400 {
		t.Errorf("X-Forwarded-Host mit Vertrauen: %d", rec.Code)
	}
	// Schutzköpfe
	rec = call(h, "GET", "/", host, nil, nil)
	for _, k := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"} {
		if rec.Header().Get(k) == "" {
			t.Errorf("Kopfzeile %s fehlt", k)
		}
	}
}

func TestServerModeLoginLockout(t *testing.T) {
	s, h := newTestServer(t, false)
	host := "srv.example:8080"
	for i := 0; i < loginMaxFails; i++ {
		if rec := call(h, "POST", "/api/login", host, map[string]string{"password": "falsch"}, nil); rec.Code != 401 {
			t.Fatalf("Versuch %d: %d", i, rec.Code)
		}
	}
	// Jetzt ist diese Adresse gesperrt, auch mit dem richtigen Passwort.
	rec := call(h, "POST", "/api/login", host, map[string]string{"password": testPW}, nil)
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" || cookieOf(rec) != nil {
		t.Fatalf("Sperre: %d %v", rec.Code, rec.Header())
	}
	// Eine andere Adresse ist nicht betroffen.
	other := func(r *http.Request) { r.RemoteAddr = "198.51.100.7:4000" }
	if rec := call(h, "POST", "/api/login", host, map[string]string{"password": testPW}, other); rec.Code != 200 {
		t.Fatalf("andere Adresse: %d", rec.Code)
	}
	// Nach Ablauf der Sperre geht es wieder.
	s.pw.mu.Lock()
	s.pw.fails["192.0.2.10"].blockedUntil = time.Now().Add(-time.Second)
	s.pw.mu.Unlock()
	if rec := call(h, "POST", "/api/login", host, map[string]string{"password": testPW}, nil); rec.Code != 200 {
		t.Fatalf("nach der Sperre: %d", rec.Code)
	}
}

func TestServerModeProxyAddressAndSecureCookie(t *testing.T) {
	_, h := newTestServer(t, true)
	host := "zert.example"
	viaProxy := func(ip string) func(*http.Request) {
		return func(r *http.Request) {
			r.Header.Set("X-Forwarded-For", "6.6.6.6, "+ip) // der Anfang ist vom Client erfunden, der letzte Eintrag vom Proxy
			r.Header.Set("X-Forwarded-Proto", "https")
		}
	}
	for i := 0; i < loginMaxFails; i++ {
		call(h, "POST", "/api/login", host, map[string]string{"password": "falsch"}, viaProxy("203.0.113.5"))
	}
	if rec := call(h, "POST", "/api/login", host, map[string]string{"password": testPW}, viaProxy("203.0.113.5")); rec.Code != 429 {
		t.Fatalf("gesperrte Adresse hinter Proxy: %d", rec.Code)
	}
	rec := call(h, "POST", "/api/login", host, map[string]string{"password": testPW}, viaProxy("203.0.113.99"))
	c := cookieOf(rec)
	if rec.Code != 200 || c == nil || !c.Secure {
		t.Fatalf("Anmeldung hinter Proxy: %d %+v", rec.Code, c)
	}
}

func TestSessionExpiry(t *testing.T) {
	s, h := newTestServer(t, false)
	host := "srv.example:8080"
	c := cookieOf(call(h, "POST", "/api/login", host, map[string]string{"password": testPW}, nil))
	with := func(r *http.Request) { r.AddCookie(c) }
	if call(h, "GET", "/api/profiles", host, nil, with).Code != 200 {
		t.Fatal("Sitzung sollte gelten")
	}
	s.pw.mu.Lock()
	s.pw.sessions[c.Value].last = time.Now().Add(-sessionIdle - time.Minute)
	s.pw.mu.Unlock()
	if call(h, "GET", "/api/profiles", host, nil, with).Code != 401 {
		t.Error("untätige Sitzung sollte abgelaufen sein")
	}
	c = cookieOf(call(h, "POST", "/api/login", host, map[string]string{"password": testPW}, nil))
	s.pw.mu.Lock()
	s.pw.sessions[c.Value].created = time.Now().Add(-sessionMax - time.Minute)
	s.pw.mu.Unlock()
	if call(h, "GET", "/api/profiles", host, nil, func(r *http.Request) { r.AddCookie(c) }).Code != 401 {
		t.Error("zu alte Sitzung sollte abgelaufen sein")
	}
}

func TestHealthz(t *testing.T) {
	fastAuth(t)
	t.Setenv("ZA_DATA", t.TempDir())
	hh, _ := hashPassword(testPW)
	sc := newScheduler()
	s := newServerMode("8080", newPasswordAuth(hh, false), sc)
	h := s.handler()
	if rec := call(h, "GET", "/healthz", "irgendwer:1", nil, nil); rec.Code != 200 {
		t.Fatalf("gesund: %d", rec.Code)
	}
	sc.mu.Lock()
	sc.lastTick = time.Now().Add(-time.Hour)
	sc.mu.Unlock()
	if rec := call(h, "GET", "/healthz", "irgendwer:1", nil, nil); rec.Code != 503 {
		t.Fatalf("Zeitplan hängt: %d", rec.Code)
	}
}

func TestLocalModeUnchanged(t *testing.T) {
	t.Setenv("ZA_DATA", t.TempDir())
	s := newServer("8765")
	h := s.handler()
	// Fremder Host wird abgelehnt (Schutz vor DNS-Rebinding), Einmal-Link funktioniert genau einmal.
	if rec := call(h, "GET", "/api/info", "evil.example:8765", nil, nil); rec.Code != 403 {
		t.Errorf("fremder Host: %d", rec.Code)
	}
	if rec := call(h, "POST", "/api/login", "127.0.0.1:8765", map[string]string{"password": "x"}, nil); rec.Code == 200 {
		t.Error("Passwort-Anmeldung darf lokal nicht existieren")
	}
	link := s.newStartLink()
	path := strings.TrimPrefix(link, "http://127.0.0.1:8765")
	rec := call(h, "GET", path, "127.0.0.1:8765", nil, nil)
	c := cookieOf(rec)
	if rec.Code != 303 || c == nil {
		t.Fatalf("Startlink: %d", rec.Code)
	}
	if rec := call(h, "GET", path, "127.0.0.1:8765", nil, nil); rec.Code != 403 {
		t.Errorf("Startlink zweimal benutzt: %d", rec.Code)
	}
	if rec := call(h, "GET", "/api/info", "127.0.0.1:8765", nil, func(r *http.Request) { r.AddCookie(c) }); rec.Code != 200 {
		t.Errorf("Info mit Sitzung: %d", rec.Code)
	}
}

func TestResolveAdminHash(t *testing.T) {
	fastAuth(t)
	clear := func() {
		for _, k := range []string{"ZA_PASSWORD", "ZA_PASSWORD_FILE", "ZA_PASSWORD_HASH"} {
			t.Setenv(k, "")
		}
	}
	// Erster Start: Passwort wird erzeugt, nur der Hash gespeichert, beim zweiten Start gleich.
	t.Setenv("ZA_DATA", t.TempDir())
	clear()
	h, src, gen, err := resolveAdminHash()
	if err != nil || src != "erzeugt" || len(gen) != 20 || h == nil {
		t.Fatalf("erster Start: %q %q %v", src, gen, err)
	}
	if b, _ := os.ReadFile(adminPath()); strings.Contains(string(b), gen) {
		t.Fatal("Passwort steht im Klartext in admin.json")
	}
	h2, src2, gen2, err := resolveAdminHash()
	if err != nil || src2 != "gespeichert" || gen2 != "" || string(h2) != string(h) {
		t.Fatalf("zweiter Start: %q %q %v", src2, gen2, err)
	}
	pa := newPasswordAuth(h2, false)
	if _, err := pa.login("1.1.1.1", gen); err != nil {
		t.Errorf("erzeugtes Passwort: %v", err)
	}
	// Umgebungsvariablen haben Vorrang
	t.Setenv("ZA_PASSWORD", "umgebung-passwort-1")
	h3, src3, _, err := resolveAdminHash()
	if err != nil || src3 != "ZA_PASSWORD" {
		t.Fatal(src3, err)
	}
	if _, err := newPasswordAuth(h3, false).login("1.1.1.1", "umgebung-passwort-1"); err != nil {
		t.Error(err)
	}
	t.Setenv("ZA_PASSWORD", "kurz")
	if _, _, _, err := resolveAdminHash(); err == nil {
		t.Error("zu kurzes Passwort hätte abgelehnt werden müssen")
	}
	t.Setenv("ZA_PASSWORD", "")
	f := filepath.Join(t.TempDir(), "pw")
	_ = os.WriteFile(f, []byte("aus-der-datei-passwort\n"), 0o600)
	t.Setenv("ZA_PASSWORD_FILE", f)
	h4, src4, _, err := resolveAdminHash()
	if err != nil || src4 != "ZA_PASSWORD" {
		t.Fatal(src4, err)
	}
	if _, err := newPasswordAuth(h4, false).login("1.1.1.1", "aus-der-datei-passwort"); err != nil {
		t.Error(err)
	}
	t.Setenv("ZA_PASSWORD_FILE", "")
	ready, _ := hashPassword("fertiger-hash-passwort")
	t.Setenv("ZA_PASSWORD_HASH", string(ready))
	if _, src5, _, err := resolveAdminHash(); err != nil || src5 != "ZA_PASSWORD_HASH" {
		t.Fatal(src5, err)
	}
	t.Setenv("ZA_PASSWORD_HASH", "kein-hash")
	if _, _, _, err := resolveAdminHash(); err == nil {
		t.Error("ungültiger Hash hätte abgelehnt werden müssen")
	}
}

func TestPasswdChangeAppliesImmediately(t *testing.T) {
	fastAuth(t)
	t.Setenv("ZA_DATA", t.TempDir())
	for _, k := range []string{"ZA_PASSWORD", "ZA_PASSWORD_FILE", "ZA_PASSWORD_HASH"} {
		t.Setenv(k, "")
	}
	h, src, gen, err := resolveAdminHash()
	if err != nil {
		t.Fatal(err)
	}
	pa := newPasswordAuth(h, false)
	if src == "erzeugt" || src == "gespeichert" {
		pa.watchFile(adminPath())
	}
	sid, err := pa.login("1.1.1.1", gen)
	if err != nil || !pa.valid(sid) {
		t.Fatal(err)
	}
	if err := setAdminPassword("kurz"); err == nil {
		t.Error("kurzes Passwort hätte abgelehnt werden müssen")
	}
	time.Sleep(10 * time.Millisecond)
	if err := setAdminPassword("ganz-neues-passwort-7"); err != nil {
		t.Fatal(err)
	}
	// Dateizeit sicher verändern, falls das Dateisystem grob aufzeichnet
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(adminPath(), future, future)
	if pa.valid(sid) {
		t.Error("alte Sitzung hätte beendet sein müssen")
	}
	if _, err := pa.login("1.1.1.1", gen); err == nil {
		t.Error("altes Passwort gilt noch")
	}
	if _, err := pa.login("1.1.1.1", "ganz-neues-passwort-7"); err != nil {
		t.Errorf("neues Passwort: %v", err)
	}
}

// ---------- Zeitplan ----------

func TestDueNow(t *testing.T) {
	loc := time.FixedZone("x", 0)
	day := func(h, m int) time.Time { return time.Date(2026, 3, 10, h, m, 0, 0, loc) }
	p := &Profile{Task: TaskConfig{Enabled: true, Time: "03:00"}}
	today := "2026-03-10"
	for name, c := range map[string]struct {
		p    *Profile
		st   State
		now  time.Time
		want bool
	}{
		"vor der Zeit":             {p, State{}, day(2, 59), false},
		"zur Zeit":                 {p, State{}, day(3, 0), true},
		"nachgeholt am Nachmittag": {p, State{}, day(15, 30), true},
		"heute schon erledigt":     {p, State{AutoRunDay: today}, day(15, 30), false},
		"gestern erledigt":         {p, State{AutoRunDay: "2026-03-09"}, day(3, 1), true},
		"Wiederholung zu früh":     {p, State{AutoNext: day(5, 0)}, day(4, 59), false},
		"Wiederholung fällig":      {p, State{AutoNext: day(5, 0)}, day(5, 0), true},
		"aus":                      {&Profile{Task: TaskConfig{Enabled: false, Time: "03:00"}}, State{}, day(12, 0), false},
		"kaputte Uhrzeit":          {&Profile{Task: TaskConfig{Enabled: true, Time: "abc"}}, State{}, day(12, 0), false},
	} {
		if got := dueNow(c.p, c.st, c.now); got != c.want {
			t.Errorf("%s: %v, erwartet %v", name, got, c.want)
		}
	}
}

func TestSchedulerRunsDueProfilesOnce(t *testing.T) {
	t.Setenv("ZA_DATA", t.TempDir())
	req := CreateRequest{Domains: "geplant.local", Method: "selfsigned", ValidDays: 365, TargetDir: filepath.Join(t.TempDir(), "z"),
		Outputs: []string{"cert", "key"}, CertFormat: "pem", AutoRenew: true, TaskTime: "03:00"}
	p, res, _, err := create(t, req)
	if err != nil || res == nil {
		t.Fatal(err)
	}
	sc := newScheduler()
	clock := time.Now()
	sc.now = func() time.Time { return clock }
	// Heute 02:00: noch nicht fällig
	loc := time.Local
	base := time.Date(2026, 5, 4, 2, 0, 0, 0, loc)
	clock = base
	if n := sc.runDue(context.Background()); n != 0 {
		t.Fatalf("um 02:00 lief %d", n)
	}
	// Das Zertifikat vorher löschen, damit man sieht, dass der Lauf wirklich etwas tut
	files := res.Files
	for _, f := range files {
		_ = os.Remove(f)
	}
	clock = base.Add(1*time.Hour + 5*time.Minute) // 03:05
	if n := sc.runDue(context.Background()); n != 1 {
		t.Fatalf("um 03:05 lief %d", n)
	}
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("Datei fehlt nach dem Zeitplan-Lauf: %s", f)
		}
	}
	st := loadState(p.ID)
	if st.AutoRunDay != "2026-05-04" || !st.AutoNext.IsZero() || st.LastResult == "fehler" {
		t.Fatalf("Zustand: %+v", st)
	}
	clock = base.Add(10 * time.Hour)
	if n := sc.runDue(context.Background()); n != 0 {
		t.Fatalf("zweiter Lauf am selben Tag: %d", n)
	}
	clock = base.Add(25*time.Hour + 10*time.Minute) // nächster Tag 03:10
	if n := sc.runDue(context.Background()); n != 1 {
		t.Fatalf("am nächsten Tag lief %d", n)
	}
}

func TestSchedulerRetriesAfterFailure(t *testing.T) {
	t.Setenv("ZA_DATA", t.TempDir())
	req := CreateRequest{Domains: "fehler.local", Method: "selfsigned", ValidDays: 365, TargetDir: filepath.Join(t.TempDir(), "z"),
		Outputs: []string{"cert", "key"}, CertFormat: "pem", AutoRenew: true, TaskTime: "03:00"}
	p, _, _, err := create(t, req)
	if err != nil {
		t.Fatal(err)
	}
	// Zielordner unbrauchbar machen: eine Datei an der Stelle des Ordners
	_ = os.RemoveAll(p.TargetDir)
	if err := os.WriteFile(p.TargetDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sc := newScheduler()
	base := time.Date(2026, 5, 4, 3, 5, 0, 0, time.Local)
	clock := base
	sc.now = func() time.Time { return clock }
	if n := sc.runDue(context.Background()); n != 1 {
		t.Fatalf("lief %d", n)
	}
	st := loadState(p.ID)
	if st.LastResult != "fehler" || st.AutoRunDay != "" || st.AutoNext.Before(base.Add(schedRetryAfter-time.Minute)) {
		t.Fatalf("Zustand nach Fehler: %+v", st)
	}
	clock = base.Add(time.Hour)
	if n := sc.runDue(context.Background()); n != 0 {
		t.Fatalf("zu früh wiederholt: %d", n)
	}
	// Fehler behoben, nach der Wartezeit klappt es.
	_ = os.Remove(p.TargetDir)
	clock = base.Add(schedRetryAfter + time.Minute)
	if n := sc.runDue(context.Background()); n != 1 {
		t.Fatalf("Wiederholung lief %d", n)
	}
	if st := loadState(p.ID); st.AutoRunDay != "2026-05-04" || st.LastResult == "fehler" {
		t.Fatalf("Zustand nach Erfolg: %+v", st)
	}
}

func TestSchedulerStopsOnCancel(t *testing.T) {
	t.Setenv("ZA_DATA", t.TempDir())
	sc := newScheduler()
	sc.tick = 10 * time.Millisecond
	sc.start()
	done := make(chan struct{})
	go func() { sc.stop(2 * time.Second); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stop kehrt nicht zurück")
	}
}

func TestClearStaleLocks(t *testing.T) {
	t.Setenv("ZA_DATA", t.TempDir())
	p := &Profile{ID: "a.test", Domains: []string{"a.test"}, Method: "selfsigned"}
	if err := saveProfile(p); err != nil {
		t.Fatal(err)
	}
	if _, err := lockProfile(p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := lockProfile(p.ID); err == nil {
		t.Fatal("Sperre sollte halten")
	}
	clearStaleLocks()
	if unlock, err := lockProfile(p.ID); err != nil {
		t.Fatalf("nach dem Aufräumen: %v", err)
	} else {
		unlock()
	}
}
