package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Anmeldung im Dauerbetrieb: ein Passwort für die Oberfläche. Es kommt aus ZA_PASSWORD_HASH (bcrypt), ZA_PASSWORD oder
// ZA_PASSWORD_FILE; ohne eine davon wird beim ersten Start eines erzeugt und einmal im Protokoll angezeigt. Gespeichert
// wird nur der bcrypt-Wert (admin.json im Arbeitsordner).

var bcryptCost = 12

const (
	minPasswordLen = 10
	sessionIdle    = 8 * time.Hour
	sessionMax     = 24 * time.Hour
	loginMaxFails  = 5
	loginWindow    = 15 * time.Minute
	loginBlock     = 15 * time.Minute
)

// Pause nach einer falschen Eingabe (Tests setzen sie auf 0).
var loginFailDelay = 700 * time.Millisecond

type adminFile struct {
	PasswordHash string    `json:"passwordHash"`
	Updated      time.Time `json:"updated"`
}

func adminPath() string { return filepath.Join(dataDir(), "admin.json") }

const pwAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// generatePassword liefert ein Zufallspasswort ohne leicht verwechselbare Zeichen.
func generatePassword(n int) string {
	if n < 8 {
		n = 8
	}
	b := make([]byte, n)
	buf := make([]byte, n)
	for i := 0; i < n; {
		if _, err := rand.Read(buf); err != nil {
			panic(err)
		}
		for _, c := range buf {
			if int(c) >= 256-256%len(pwAlphabet) {
				continue
			}
			b[i] = pwAlphabet[int(c)%len(pwAlphabet)]
			i++
			if i == n {
				break
			}
		}
	}
	return string(b)
}

func hashPassword(pw string) ([]byte, error) {
	if len(pw) > 72 {
		return nil, fmt.Errorf("Das Passwort darf höchstens 72 Zeichen lang sein.")
	}
	return bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
}

// setAdminPassword speichert ein neues Passwort (Befehl „passwd“).
func setAdminPassword(pw string) error {
	if len([]rune(pw)) < minPasswordLen {
		return fmt.Errorf("Das Passwort muss mindestens %d Zeichen lang sein.", minPasswordLen)
	}
	h, err := hashPassword(pw)
	if err != nil {
		return err
	}
	return writeJSON(adminPath(), adminFile{PasswordHash: string(h), Updated: time.Now().Truncate(time.Second)})
}

// resolveAdminHash bestimmt das gültige Passwort. source sagt, woher es kommt; generated ist nur beim allerersten
// Start gefüllt und wird nie gespeichert.
func resolveAdminHash() (hash []byte, source, generated string, err error) {
	if v := strings.TrimSpace(os.Getenv("ZA_PASSWORD_HASH")); v != "" {
		if _, e := bcrypt.Cost([]byte(v)); e != nil {
			return nil, "", "", fmt.Errorf("ZA_PASSWORD_HASH ist kein gültiger bcrypt-Wert (er beginnt mit $2a$, $2b$ oder $2y$).")
		}
		return []byte(v), "ZA_PASSWORD_HASH", "", nil
	}
	pw, src := os.Getenv("ZA_PASSWORD"), "ZA_PASSWORD"
	if pw == "" {
		if f := strings.TrimSpace(os.Getenv("ZA_PASSWORD_FILE")); f != "" {
			b, e := os.ReadFile(f)
			if e != nil {
				return nil, "", "", fmt.Errorf("ZA_PASSWORD_FILE ist nicht lesbar: %v", e)
			}
			pw, src = strings.TrimRight(string(b), "\r\n"), "ZA_PASSWORD_FILE"
		}
	}
	if pw != "" {
		if len([]rune(pw)) < minPasswordLen {
			return nil, "", "", fmt.Errorf("Das Passwort aus ZA_PASSWORD/ZA_PASSWORD_FILE ist zu kurz (mindestens %d Zeichen).", minPasswordLen)
		}
		h, e := hashPassword(pw)
		return h, src, "", e
	}
	if b, e := os.ReadFile(adminPath()); e == nil {
		var af adminFile
		if json.Unmarshal(b, &af) == nil && af.PasswordHash != "" {
			if _, e := bcrypt.Cost([]byte(af.PasswordHash)); e == nil {
				return []byte(af.PasswordHash), "gespeichert", "", nil
			}
		}
		return nil, "", "", fmt.Errorf("Die Datei %s ist beschädigt. Mit „passwd“ lässt sich ein neues Passwort setzen.", adminPath())
	}
	pw = generatePassword(20)
	if err := setAdminPassword(pw); err != nil {
		return nil, "", "", err
	}
	b, _ := os.ReadFile(adminPath())
	var af adminFile
	_ = json.Unmarshal(b, &af)
	return []byte(af.PasswordHash), "erzeugt", pw, nil
}

type session struct{ created, last time.Time }

type failRec struct {
	count        int
	first        time.Time
	blockedUntil time.Time
}

// passwordAuth verwaltet Anmeldung, Sitzungen und die Sperre gegen Raten.
type passwordAuth struct {
	hash       []byte
	trustProxy bool

	mu       sync.Mutex
	sessions map[string]*session
	fails    map[string]*failRec

	watch    string    // admin.json: Ein mit „passwd“ geändertes Passwort gilt sofort
	watchMod time.Time // Änderungszeit, bei der zuletzt gelesen wurde
}

func newPasswordAuth(hash []byte, trustProxy bool) *passwordAuth {
	return &passwordAuth{hash: hash, trustProxy: trustProxy, sessions: map[string]*session{}, fails: map[string]*failRec{}}
}

// clientIP: Hinter einem vertrauenswürdigen Proxy zählt der letzte Eintrag in X-Forwarded-For (den hat der Proxy gesetzt).
// watchFile merkt sich die Datei mit dem gespeicherten Passwort. Ändert sich sie, gilt das neue Passwort sofort,
// und alle Sitzungen werden beendet.
func (a *passwordAuth) watchFile(path string) {
	a.watch = path
	if fi, err := os.Stat(path); err == nil {
		a.watchMod = fi.ModTime()
	}
}

func (a *passwordAuth) refresh() {
	if a.watch == "" {
		return
	}
	fi, err := os.Stat(a.watch)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if fi.ModTime().Equal(a.watchMod) {
		return
	}
	a.watchMod = fi.ModTime()
	b, err := os.ReadFile(a.watch)
	if err != nil {
		return
	}
	var af adminFile
	if json.Unmarshal(b, &af) != nil {
		return
	}
	if _, err := bcrypt.Cost([]byte(af.PasswordHash)); err != nil || af.PasswordHash == string(a.hash) {
		return
	}
	a.hash = []byte(af.PasswordHash)
	a.sessions = map[string]*session{}
	appLogGlobal("Das Passwort der Oberfläche wurde geändert, alle Sitzungen sind beendet.")
}

func (a *passwordAuth) clientIP(r *http.Request) string {
	if a.trustProxy {
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
			parts := strings.Split(xf, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

var errLoginBlocked = errors.New("gesperrt")

type loginBlockedError struct{ retryAfter time.Duration }

func (e *loginBlockedError) Error() string { return errLoginBlocked.Error() }

var errBadPassword = errors.New("Das Passwort stimmt nicht.")

// login prüft das Passwort und legt eine Sitzung an.
func (a *passwordAuth) login(ip, pw string) (string, error) {
	a.refresh()
	now := time.Now()
	a.mu.Lock()
	f := a.fails[ip]
	if f != nil && now.Before(f.blockedUntil) {
		wait := f.blockedUntil.Sub(now)
		a.mu.Unlock()
		return "", &loginBlockedError{retryAfter: wait}
	}
	hash := a.hash
	a.mu.Unlock()

	ok := len(pw) <= 72 && bcrypt.CompareHashAndPassword(hash, []byte(pw)) == nil
	if !ok {
		a.mu.Lock()
		f = a.fails[ip]
		if f == nil || now.Sub(f.first) > loginWindow {
			f = &failRec{first: now}
			a.fails[ip] = f
		}
		f.count++
		if f.count >= loginMaxFails {
			f.blockedUntil = now.Add(loginBlock)
		}
		a.mu.Unlock()
		if loginFailDelay > 0 {
			time.Sleep(loginFailDelay)
		}
		return "", errBadPassword
	}
	sid := randomHex(32)
	a.mu.Lock()
	delete(a.fails, ip)
	a.sessions[sid] = &session{created: now, last: now}
	a.gcLocked(now)
	a.mu.Unlock()
	return sid, nil
}

func (a *passwordAuth) gcLocked(now time.Time) {
	for id, s := range a.sessions {
		if now.Sub(s.last) > sessionIdle || now.Sub(s.created) > sessionMax {
			delete(a.sessions, id)
		}
	}
	for ip, f := range a.fails {
		if now.After(f.blockedUntil) && now.Sub(f.first) > loginWindow {
			delete(a.fails, ip)
		}
	}
}

// valid prüft eine Sitzung und verlängert sie.
func (a *passwordAuth) valid(sid string) bool {
	if len(sid) < 32 {
		return false
	}
	a.refresh()
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, s := range a.sessions {
		if subtle.ConstantTimeCompare([]byte(id), []byte(sid)) != 1 {
			continue
		}
		if now.Sub(s.last) > sessionIdle || now.Sub(s.created) > sessionMax {
			delete(a.sessions, id)
			return false
		}
		s.last = now
		return true
	}
	return false
}

func (a *passwordAuth) logout(sid string) {
	a.mu.Lock()
	delete(a.sessions, sid)
	a.mu.Unlock()
}
