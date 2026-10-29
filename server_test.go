package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestNotLoggedInPageAndLog(t *testing.T) {
	t.Setenv("ZA_DATA", t.TempDir())
	s := newServer("8765")

	if p := s.notLoggedInPage(); !strings.Contains(p, "Eingabetaste") {
		t.Errorf("Text unerwartet: %s", p)
	}

	h := s.handler()
	secret := strings.Repeat("ab", 32)
	for _, path := range []string{"/", "/api/profiles", "/start?k=falsch"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "127.0.0.1:8765"
		req.AddCookie(&http.Cookie{Name: "za_sid", Value: secret})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 401 && rec.Code != 403 {
			t.Errorf("%s: Status %d, erwartet 401 oder 403", path, rec.Code)
		}
	}
	b, err := os.ReadFile(logPath())
	if err != nil {
		t.Fatalf("Protokoll fehlt: %v", err)
	}
	log := string(b)
	if strings.Count(log, "Anmeldung fehlt bei") != 3 || !strings.Contains(log, "Startlink ungültig") || !strings.Contains(log, "Cookie mit 64 Zeichen") {
		t.Errorf("Protokoll unvollständig:\n%s", log)
	}
	if strings.Contains(log, secret) {
		t.Error("Der Wert des Cookies darf nicht ins Protokoll")
	}
}
