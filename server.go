package main

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

//go:embed ui/index.html
var indexHTML []byte

const contentSecurityPolicy = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; " +
	"connect-src 'self' https: http://127.0.0.1:*; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

const idleLimit = 30 * time.Minute

// server ist der kleine Webserver für die Oberfläche. Er hört nur auf 127.0.0.1 und verlangt eine Anmeldung
// über einen Einmal-Link: Andere Benutzer auf demselben Rechner und Webseiten im Browser kommen nicht heran.
type server struct {
	port      string
	mu        sync.Mutex
	startKeys map[string]time.Time
	sessions  map[string]bool
	last      time.Time
	httpSrv   *http.Server
	done      chan struct{}
	doneOnce  sync.Once
	denied    int // Anzahl abgelehnter Anfragen ohne Anmeldung (nur für das Protokoll)
}

func newServer(port string) *server {
	return &server{port: port, startKeys: map[string]time.Time{}, sessions: map[string]bool{}, last: time.Now(), done: make(chan struct{})}
}

// newStartLink erzeugt einen Link, der genau einmal gültig ist.
func (s *server) newStartLink() string {
	k := randomHex(16)
	s.mu.Lock()
	s.startKeys[k] = time.Now().Add(15 * time.Minute)
	s.mu.Unlock()
	return "http://127.0.0.1:" + s.port + "/start?k=" + k
}

func (s *server) hostOK(h string) bool {
	return h == "127.0.0.1:"+s.port || h == "localhost:"+s.port || h == "[::1]:"+s.port
}

func (s *server) hasSession(r *http.Request) bool {
	c, err := r.Cookie("za_sid")
	if err != nil || len(c.Value) < 32 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for sid := range s.sessions {
		if subtle.ConstantTimeCompare([]byte(sid), []byte(c.Value)) == 1 {
			return true
		}
	}
	return false
}

func secureHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", contentSecurityPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
}

func (s *server) guard(auth bool, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secureHeaders(w)
		if !s.hostOK(r.Host) {
			http.Error(w, "Ungültiger Host.", http.StatusForbidden)
			return
		}
		s.mu.Lock()
		s.last = time.Now()
		s.mu.Unlock()
		if auth && !s.hasSession(r) {
			s.logDenied(r, "Schnittstelle")
			respond(w, http.StatusUnauthorized, map[string]any{"error": "Nicht angemeldet. Bitte den Link verwenden, den Certbumblebee anzeigt."})
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") || r.Header.Get("X-ZA") != "1" {
				respond(w, http.StatusForbidden, map[string]any{"error": "Ungültige Anfrage."})
				return
			}
			if o := r.Header.Get("Origin"); o != "" && o != "http://127.0.0.1:"+s.port && o != "http://localhost:"+s.port {
				respond(w, http.StatusForbidden, map[string]any{"error": "Ungültige Herkunft."})
				return
			}
		}
		h(w, r)
	}
}

func respond(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return fmt.Errorf("Die Anfrage konnte nicht gelesen werden.")
	}
	return nil
}

const notLoggedInHead = `<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Certbumblebee</title><body style="font:16px/1.5 system-ui,sans-serif;max-width:34rem;margin:12vh auto;padding:0 20px">
<h1 style="font-size:1.25rem">Diese Seite ist nicht freigeschaltet</h1>
`

func (s *server) notLoggedInPage() string {
	return notLoggedInHead + `<p>Bitte den Link verwenden, den Certbumblebee anzeigt. Er öffnet sich normalerweise von selbst und gilt nur einmal.</p>
<p>Wurde der Link schon benutzt: in dem Fenster, in dem das Programm läuft, die Eingabetaste drücken, dann erscheint ein neuer.</p>`
}

// logDenied schreibt ins Protokoll, warum eine Anfrage nicht angemeldet war (ohne den Wert des Cookies). Höchstens 30 Einträge.
func (s *server) logDenied(r *http.Request, where string) {
	s.mu.Lock()
	s.denied++
	n, sessions := s.denied, len(s.sessions)
	s.mu.Unlock()
	if n > 30 {
		return
	}
	state := "kein Cookie"
	if c, err := r.Cookie("za_sid"); err == nil {
		state = fmt.Sprintf("Cookie mit %d Zeichen, unbekannte Sitzung", len(c.Value))
	}
	appLogGlobal(fmt.Sprintf("Anmeldung fehlt bei %s %s (%s): %s, %d Sitzung(en) im Programm, Port %s, Browser=%q",
		r.Method, r.URL.Path, where, state, sessions, s.port, r.UserAgent()))
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /start", s.guard(false, func(w http.ResponseWriter, r *http.Request) {
		k := r.URL.Query().Get("k")
		s.mu.Lock()
		exp, ok := s.startKeys[k]
		if ok {
			delete(s.startKeys, k)
		}
		s.mu.Unlock()
		if !ok || time.Now().After(exp) {
			s.logDenied(r, "Startlink ungültig oder schon benutzt")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(s.notLoggedInPage()))
			return
		}
		sid := randomHex(32)
		s.mu.Lock()
		s.sessions[sid] = true
		n := len(s.sessions)
		s.mu.Unlock()
		appLogGlobal(fmt.Sprintf("Anmeldung: Sitzung angelegt (%d im Programm), Port %s, Browser=%q", n, s.port, r.UserAgent()))
		http.SetCookie(w, &http.Cookie{Name: "za_sid", Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}))

	mux.HandleFunc("GET /{$}", s.guard(false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if !s.hasSession(r) {
			s.logDenied(r, "Startseite")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(s.notLoggedInPage()))
			return
		}
		_, _ = w.Write(indexHTML)
	}))

	s.registerAPI(mux)
	return mux
}

func (s *server) shutdown() {
	s.doneOnce.Do(func() { close(s.done) })
}

// serve läuft, bis „shutdown“ aufgerufen wird oder die Sitzung zu lange ungenutzt bleibt.
func (s *server) serve(ln net.Listener) error {
	s.httpSrv = &http.Server{Handler: s.handler(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- s.httpSrv.Serve(ln) }()
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case err := <-errc:
			return err
		case <-s.done:
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			return s.httpSrv.Shutdown(ctx)
		case <-tick.C:
			s.mu.Lock()
			idle := time.Since(s.last)
			s.mu.Unlock()
			if idle > idleLimit && !anyJobRunning() {
				fmt.Println("Keine Aktivität seit 30 Minuten, das Programm beendet sich.")
				s.shutdown()
			}
		}
	}
}

func anyJobRunning() bool {
	jobsMu.Lock()
	defer jobsMu.Unlock()
	for _, j := range jobs {
		j.mu.Lock()
		run := j.state == "run"
		j.mu.Unlock()
		if run {
			return true
		}
	}
	return false
}
