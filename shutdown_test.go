package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestStopJobsCancelsAndWaits(t *testing.T) {
	s := newServer("8080")
	started, cleaned := make(chan struct{}), make(chan struct{})
	if !s.goJob(func(ctx context.Context) {
		close(started)
		<-ctx.Done()
		time.Sleep(50 * time.Millisecond) // Aufräumen dauert etwas
		close(cleaned)
	}) {
		t.Fatal("der Vorgang wurde nicht angenommen")
	}
	<-started
	if !s.stopJobs(5 * time.Second) {
		t.Fatal("stopJobs hat nicht auf den Vorgang gewartet")
	}
	select {
	case <-cleaned:
	default:
		t.Fatal("der Vorgang hat nicht fertig aufgeräumt")
	}
	if s.goJob(func(context.Context) {}) {
		t.Error("während des Beendens darf kein neuer Vorgang starten")
	}
}

func TestStopJobsGivesUpAfterWait(t *testing.T) {
	s := newServer("8080")
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	s.goJob(func(context.Context) { <-release }) // reagiert nicht auf den Abbruch
	start := time.Now()
	if s.stopJobs(100 * time.Millisecond) {
		t.Fatal("stopJobs hätte aufgeben müssen")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("stopJobs hat %v gewartet", d)
	}
}

// fakeACME ist ein winziger ACME-Server: Konto, Bestellung und eine DNS-Bestätigung. Mehr braucht der Ablauf bis
// zum Anlegen der DNS-Einträge nicht.
func fakeACME(t *testing.T, domain string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	var nonce atomic.Int64
	reply := func(w http.ResponseWriter, code int, loc string, v any) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", nonce.Add(1)))
		if loc != "" {
			w.Header().Set("Location", srv.URL+loc)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		if v != nil {
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	id := map[string]string{"type": "dns", "value": domain}
	mux := http.NewServeMux()
	mux.HandleFunc("/dir", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, "", map[string]string{"newNonce": srv.URL + "/nonce", "newAccount": srv.URL + "/acct",
			"newOrder": srv.URL + "/order", "revokeCert": srv.URL + "/revoke", "keyChange": srv.URL + "/key"})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) { reply(w, 204, "", nil) })
	mux.HandleFunc("/acct", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 201, "/acct/1", map[string]string{"status": "valid"})
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 201, "/order/1", map[string]any{"status": "pending", "identifiers": []any{id},
			"authorizations": []string{srv.URL + "/authz/1"}, "finalize": srv.URL + "/finalize/1"})
	})
	mux.HandleFunc("/authz/1", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, "", map[string]any{"identifier": id, "status": "pending", "challenges": []any{
			map[string]string{"type": "dns-01", "url": srv.URL + "/chall/1", "token": "dG9rZW4", "status": "pending"}}})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// Wird das Programm beendet, während ein Vorgang aus der Oberfläche auf die DNS-Einträge wartet, müssen die
// Einträge bei Cloudflare vorher verschwinden.
func TestShutdownAbortsDNSJobAndCleansUp(t *testing.T) {
	s, h := newTestServer(t, false)
	t.Setenv("ZA_CLOUDFLARE_TOKEN", "")
	f := newFakeCF(t, testToken)
	f.addZone("abbruch.test")
	oldAuth, oldEvery := authTXT, dnsPollEvery
	// Der Eintrag wird nie sichtbar: Der Vorgang bleibt im Warten, bis er abgebrochen wird.
	authTXT = func(context.Context, []string, string) ([]string, error) { return nil, nil }
	dnsPollEvery = 5 * time.Millisecond
	t.Cleanup(func() { authTXT, dnsPollEvery = oldAuth, oldEvery })
	if _, _, _, err := addDNSAccount(context.Background(), "Test", testToken); err != nil {
		t.Fatal(err)
	}
	acme := fakeACME(t, "abbruch.test")

	host := "zertifikate.firma.example:8080"
	c := cookieOf(call(h, "POST", "/api/login", host, map[string]string{"password": testPW}, nil))
	if c == nil {
		t.Fatal("Anmeldung fehlgeschlagen")
	}
	withCookie := func(r *http.Request) { r.AddCookie(c) }
	jobState := func(id string) string {
		var v struct {
			State   string `json:"state"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(call(h, "GET", "/api/jobs/"+id, host, nil, withCookie).Body.Bytes(), &v)
		return v.State + " " + v.Message
	}

	req := CreateRequest{Domains: "abbruch.test", Method: "dns", TargetDir: filepath.Join(t.TempDir(), "ziel"),
		Outputs: []string{"fullchain", "key"}, CertFormat: "pem", Server: "custom", CustomURL: acme.URL + "/dir"}
	rec := call(h, "POST", "/api/profiles", host, req, withCookie)
	var started struct {
		JobID string `json:"jobId"`
	}
	if rec.Code != 202 || json.Unmarshal(rec.Body.Bytes(), &started) != nil || started.JobID == "" {
		t.Fatalf("Einrichtung starten: %d %s", rec.Code, rec.Body.String())
	}

	// Warten, bis der Eintrag bei Cloudflare liegt.
	for deadline := time.Now().Add(10 * time.Second); f.countRecords() == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("der DNS-Eintrag wurde nicht angelegt (Vorgang: %s)", jobState(started.JobID))
		}
	}

	if !s.stopJobs(10 * time.Second) {
		t.Fatal("der Vorgang wurde beim Beenden nicht rechtzeitig fertig")
	}
	if n := f.countRecords(); n != 0 {
		t.Errorf("%d Einträge bei Cloudflare liegen geblieben", n)
	}
	if st := jobState(started.JobID); st == "run " || st == " " {
		t.Errorf("der Vorgang läuft noch oder ist unbekannt: %q", st)
	}

	// Beim Beenden kommt kein neuer Vorgang mehr dazu.
	if rec := call(h, "POST", "/api/profiles", host, req, withCookie); rec.Code != 503 {
		t.Errorf("neuer Vorgang beim Beenden: %d %s", rec.Code, rec.Body.String())
	}
}
