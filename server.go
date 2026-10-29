package main

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

//go:embed ui/index.html
var indexHTML []byte

const contentSecurityPolicy = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; " +
	"connect-src 'self' https: http://127.0.0.1:*; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

const idleLimit = 30 * time.Minute

// server ist der Webserver für die Oberfläche. Er arbeitet in zwei Betriebsarten:
//
//   - lokal („ui“): hört nur auf 127.0.0.1 und verlangt eine Anmeldung über einen Einmal-Link. Andere Benutzer auf
//     demselben Rechner und Webseiten im Browser kommen nicht heran. Nach 30 Minuten ohne Nutzung beendet er sich.
//   - Dauerbetrieb („serve“): hört auf einer wählbaren Adresse, Anmeldung mit Passwort, Sitzungen mit Ablauf, Sperre
//     gegen Raten, Zeitplan für die Erneuerung im selben Prozess.
type server struct {
	port string
	mu   sync.Mutex

	// lokal
	startKeys map[string]time.Time
	sessions  map[string]bool
	last      time.Time
	denied    int // Anzahl abgelehnter Anfragen ohne Anmeldung (nur für das Protokoll)

	// Dauerbetrieb
	pw       *passwordAuth
	sched    *scheduler
	tlsCert  string
	tlsKey   string
	forceSec bool // Cookie immer mit „Secure“ (Proxy mit https davor)

	httpSrv  *http.Server
	done     chan struct{}
	doneOnce sync.Once

	// Vorgänge, die über die Oberfläche starten (Einrichten, Erneuern). Beim Beenden werden sie abgebrochen und
	// abgewartet, damit sie noch aufräumen können (z. B. DNS-Einträge löschen).
	jobCtx    context.Context
	jobCancel context.CancelFunc
	jobs      sync.WaitGroup
	stopping  bool
}

func newServer(port string) *server {
	ctx, cancel := context.WithCancel(context.Background())
	return &server{port: port, startKeys: map[string]time.Time{}, sessions: map[string]bool{}, last: time.Now(), done: make(chan struct{}),
		jobCtx: ctx, jobCancel: cancel}
}

var errShuttingDown = errors.New("Das Programm wird gerade beendet. Bitte später erneut versuchen.")

// goJob führt f im Hintergrund aus. Der Kontext wird beim Beenden abgebrochen (cancelJobs). Solange das Programm
// beendet wird, nimmt der Server keine neuen Vorgänge mehr an (false).
func (s *server) goJob(f func(ctx context.Context)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping {
		return false
	}
	s.jobs.Add(1)
	go func() {
		defer s.jobs.Done()
		f(s.jobCtx)
	}()
	return true
}

// cancelJobs bricht laufende Vorgänge ab und nimmt keine neuen mehr an.
func (s *server) cancelJobs() {
	s.mu.Lock()
	s.stopping = true
	s.mu.Unlock()
	s.jobCancel()
}

// waitJobs wartet höchstens so lange, bis die abgebrochenen Vorgänge aufgeräumt haben. false: nicht rechtzeitig fertig.
func (s *server) waitJobs(wait time.Duration) bool {
	done := make(chan struct{})
	go func() { s.jobs.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(wait):
		return false
	}
}

func (s *server) stopJobs(wait time.Duration) bool {
	s.cancelJobs()
	return s.waitJobs(wait)
}

// newServerMode baut den Server für den Dauerbetrieb.
func newServerMode(port string, pw *passwordAuth, sched *scheduler) *server {
	s := newServer(port)
	s.pw = pw
	s.sched = sched
	return s
}

func (s *server) serverMode() bool { return s.pw != nil }

// newStartLink erzeugt einen Link, der genau einmal gültig ist.
func (s *server) newStartLink() string {
	k := randomHex(16)
	s.mu.Lock()
	s.startKeys[k] = time.Now().Add(15 * time.Minute)
	s.mu.Unlock()
	return "http://127.0.0.1:" + s.port + "/start?k=" + k
}

func (s *server) hostOK(h string) bool {
	if s.serverMode() {
		return true // Das Passwort schützt; die Adresse bestimmt der Betreiber (Proxy, DNS-Name, IP)
	}
	return h == "127.0.0.1:"+s.port || h == "localhost:"+s.port || h == "[::1]:"+s.port
}

func (s *server) sessionID(r *http.Request) string {
	c, err := r.Cookie("za_sid")
	if err != nil {
		return ""
	}
	return c.Value
}

func (s *server) hasSession(r *http.Request) bool {
	sid := s.sessionID(r)
	if len(sid) < 32 {
		return false
	}
	if s.serverMode() {
		return s.pw.valid(sid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.sessions {
		if subtle.ConstantTimeCompare([]byte(id), []byte(sid)) == 1 {
			return true
		}
	}
	return false
}

// originOK: Anfragen, die etwas ändern, müssen von der eigenen Seite kommen.
func (s *server) originOK(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	if !s.serverMode() {
		return o == "http://127.0.0.1:"+s.port || o == "http://localhost:"+s.port
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	if s.pw.trustProxy {
		if xh := r.Header.Get("X-Forwarded-Host"); xh != "" && strings.EqualFold(u.Host, strings.TrimSpace(strings.Split(xh, ",")[0])) {
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
			if s.serverMode() {
				respond(w, http.StatusUnauthorized, map[string]any{"error": "Bitte anmelden.", "login": true})
				return
			}
			s.logDenied(r, "Schnittstelle")
			respond(w, http.StatusUnauthorized, map[string]any{"error": "Nicht angemeldet. Bitte den Link verwenden, den Certbumblebee anzeigt."})
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") || r.Header.Get("X-ZA") != "1" {
				respond(w, http.StatusForbidden, map[string]any{"error": "Ungültige Anfrage."})
				return
			}
			if !s.originOK(r) {
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

func (s *server) cookieSecure(r *http.Request) bool {
	if s.forceSec || r.TLS != nil {
		return true
	}
	return s.serverMode() && s.pw.trustProxy && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		secureHeaders(w)
		ok := s.sched == nil || s.sched.healthy()
		code := 200
		if !ok {
			code = http.StatusServiceUnavailable
		}
		respond(w, code, map[string]any{"ok": ok, "version": appVersion})
	})

	if s.serverMode() {
		s.registerLogin(mux)
	} else {
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
	}

	mux.HandleFunc("GET /{$}", s.guard(false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if !s.serverMode() && !s.hasSession(r) {
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

// registerLogin: Anmelden und Abmelden im Dauerbetrieb.
func (s *server) registerLogin(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/login", s.guard(false, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
		}
		if err := readJSON(r, &req); err != nil {
			respond(w, 400, errBody(err))
			return
		}
		ip := s.pw.clientIP(r)
		sid, err := s.pw.login(ip, req.Password)
		if err != nil {
			var be *loginBlockedError
			if asBlocked(err, &be) {
				mins := int(be.retryAfter.Minutes()) + 1
				w.Header().Set("Retry-After", fmt.Sprint(int(be.retryAfter.Seconds())+1))
				appLogGlobal(fmt.Sprintf("Anmeldung gesperrt für %s (zu viele Fehlversuche)", ip))
				respond(w, http.StatusTooManyRequests, map[string]any{"error": fmt.Sprintf("Zu viele falsche Eingaben. Bitte in etwa %d Minuten erneut versuchen.", mins)})
				return
			}
			appLogGlobal(fmt.Sprintf("Anmeldung fehlgeschlagen von %s", ip))
			respond(w, http.StatusUnauthorized, map[string]any{"error": err.Error(), "login": true})
			return
		}
		appLogGlobal(fmt.Sprintf("Anmeldung: %s, Browser=%q", ip, r.UserAgent()))
		http.SetCookie(w, &http.Cookie{Name: "za_sid", Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
			Secure: s.cookieSecure(r), MaxAge: int(sessionMax.Seconds())})
		respond(w, 200, map[string]any{"ok": true})
	}))

	mux.HandleFunc("POST /api/logout", s.guard(false, func(w http.ResponseWriter, r *http.Request) {
		if sid := s.sessionID(r); sid != "" {
			s.pw.logout(sid)
		}
		http.SetCookie(w, &http.Cookie{Name: "za_sid", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.cookieSecure(r), MaxAge: -1})
		respond(w, 200, map[string]any{"ok": true})
	}))
}

func asBlocked(err error, target **loginBlockedError) bool {
	be, ok := err.(*loginBlockedError)
	if ok {
		*target = be
	}
	return ok
}

func (s *server) shutdown() {
	s.doneOnce.Do(func() { close(s.done) })
}

// serve läuft, bis „shutdown“ aufgerufen wird. Lokal beendet sich der Server außerdem nach 30 Minuten ohne Nutzung.
func (s *server) serve(ln net.Listener) error {
	s.httpSrv = &http.Server{Handler: s.handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 2 * time.Minute, IdleTimeout: 2 * time.Minute}
	errc := make(chan error, 1)
	go func() {
		if s.tlsCert != "" {
			errc <- s.httpSrv.ServeTLS(ln, s.tlsCert, s.tlsKey)
		} else {
			errc <- s.httpSrv.Serve(ln)
		}
	}()
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
			if s.serverMode() {
				continue
			}
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
