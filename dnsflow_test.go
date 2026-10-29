package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// challtestsrv (Test-DNS von Pebble, Verwaltung auf Port 8055): Einträge setzen und löschen.
func setTestDNS(host string, values []string) {
	post := func(path string, body map[string]string) {
		b, _ := json.Marshal(body)
		if r, err := http.Post("http://127.0.0.1:8055/"+path, "application/json", bytes.NewReader(b)); err == nil {
			r.Body.Close()
		}
	}
	post("clear-txt", map[string]string{"host": host + "."})
	for _, v := range values {
		post("set-txt", map[string]string{"host": host + ".", "value": v})
	}
}

// pebbleDNSSetup richtet Konto und Zone ein. Die Cloudflare-Attrappe gibt jede Änderung an das Test-DNS weiter,
// so sieht Pebble die Einträge wie bei einem echten Anbieter. Die direkte Abfrage der Nameserver wird durch einen
// Blick in die Attrappe ersetzt.
func pebbleDNSSetup(t *testing.T, zones ...string) *fakeCF {
	t.Helper()
	t.Setenv("ZA_CLOUDFLARE_TOKEN", "")
	f := newFakeCF(t, testToken)
	for _, z := range zones {
		f.addZone(z)
	}
	f.onChange = setTestDNS
	old, oldEvery := authTXT, dnsPollEvery
	authTXT = func(_ context.Context, _ []string, name string) ([]string, error) { return f.txt(name), nil }
	dnsPollEvery = 5 * time.Millisecond
	t.Cleanup(func() { authTXT, dnsPollEvery = old, oldEvery })
	if _, _, _, err := addDNSAccount(context.Background(), "Test", testToken); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestPebbleDNSWildcardLifecycle(t *testing.T) {
	pebbleOnly(t)
	f := pebbleDNSSetup(t, "wild.test")

	req := baseReq(t, "*.wild.test\nwild.test")
	req.Method = "dns"
	req.Outputs = []string{"pfx", "fullchain", "key"}
	req.CertFormat = "crt"
	req.AutoRenew = true
	p, res, job, err := create(t, req)
	if err != nil {
		t.Fatalf("createProfile: %v", err)
	}
	if res.Result != "ausgestellt" || !res.Written || len(res.Files) != 3 {
		t.Fatalf("Ergebnis: %+v", res)
	}
	names := strings.Join(res.Cert.DNSNames, ",")
	if !strings.Contains(names, "*.wild.test") || !strings.Contains(names, "wild.test") {
		t.Fatalf("Namen im Zertifikat: %s", names)
	}
	if filepath.Base(res.Files[0]) != "_.wild.test.pfx" {
		t.Errorf("Dateiname: %v", res.Files)
	}
	for _, k := range []string{"konto", "bestellung", "dns", "dnswarten", "pruefung", "aufraeumen", "zertifikat", "pfx", "ziel"} {
		if s := stepState(job, k); s != "ok" {
			t.Errorf("Schritt %s: %s", k, s)
		}
	}
	// Nichts bleibt bei Cloudflare liegen, auch nicht im Test-DNS.
	if n := f.countRecords(); n != 0 {
		t.Errorf("%d Einträge bei Cloudflare übrig", n)
	}
	// Die Anfragen kamen in sinnvoller Reihenfolge: Zone suchen, aufräumen, anlegen, löschen.
	log := strings.Join(f.requests(), "\n")
	if !strings.Contains(log, "POST /zones/") || !strings.Contains(log, "DELETE /zones/") {
		t.Errorf("Anfragen:\n%s", log)
	}

	// Erneuerung: jetzt nicht fällig, mit force wirklich neu.
	rep := newJob(p.ID)
	r2, err := renewProfile(context.Background(), p.ID, false, rep)
	if err != nil || r2.Result != "nicht-faellig" {
		t.Fatalf("Erneuerung ohne Fälligkeit: %+v %v", r2, err)
	}
	for _, k := range []string{"dns", "dnswarten", "aufraeumen"} {
		if s := stepState(rep, k); s != "ok" {
			t.Errorf("nicht fällig, Schritt %s: %s", k, s)
		}
	}
	rep = newJob(p.ID)
	r3, err := renewProfile(context.Background(), p.ID, true, rep)
	if err != nil || r3.Result != "erneuert" {
		t.Fatalf("erzwungene Erneuerung: %+v %v", r3, err)
	}
	if f.countRecords() != 0 {
		t.Errorf("nach der Erneuerung %d Einträge übrig", f.countRecords())
	}
	fmt.Fprintln(os.Stderr, "DNS-Ablauf mit Pebble in Ordnung:", names)
}

func TestPebbleDNSTwoZones(t *testing.T) {
	pebbleOnly(t)
	f := pebbleDNSSetup(t, "eins.test", "zwei.test")
	req := baseReq(t, "www.eins.test\n*.zwei.test")
	req.Method = "dns"
	req.AutoRenew = false
	req.Outputs = []string{"fullchain", "key"}
	req.CertFormat = "pem"
	req.Password = ""
	_, res, _, err := create(t, req)
	if err != nil {
		t.Fatalf("createProfile: %v", err)
	}
	if got := strings.Join(res.Cert.DNSNames, ","); !strings.Contains(got, "www.eins.test") || !strings.Contains(got, "*.zwei.test") {
		t.Fatalf("Namen: %s", got)
	}
	var posts []string
	for _, r := range f.requests() {
		if strings.HasPrefix(r, "POST ") {
			posts = append(posts, r)
		}
	}
	if len(posts) != 2 || posts[0] == posts[1] {
		t.Errorf("je Zone ein Eintrag erwartet: %v", posts)
	}
	if f.countRecords() != 0 {
		t.Errorf("%d Einträge übrig", f.countRecords())
	}
}

func TestPebbleDNSFailureCleansUp(t *testing.T) {
	pebbleOnly(t)
	f := pebbleDNSSetup(t, "kaputt.test")
	f.onChange = nil // Der Zertifikatsanbieter sieht die Einträge nicht (z. B. falsche Nameserver).
	req := baseReq(t, "kaputt.test")
	req.Method = "dns"
	req.AutoRenew = false
	req.Outputs = []string{"fullchain", "key"}
	req.CertFormat = "pem"
	req.Password = ""
	p, _, job, err := create(t, req)
	if err == nil {
		t.Fatal("ohne sichtbaren Eintrag hätte die Bestätigung scheitern müssen")
	}
	if !strings.Contains(err.Error(), "TXT-Eintrag") || !strings.Contains(err.Error(), "Cloudflare") {
		t.Errorf("Meldung: %v", err)
	}
	if s := stepState(job, "pruefung"); s != "fail" {
		t.Errorf("Schritt pruefung: %s", s)
	}
	if f.countRecords() != 0 {
		t.Errorf("%d Einträge bei Cloudflare liegen geblieben", f.countRecords())
	}
	if _, e := os.Stat(profileDir(p.ID)); e == nil {
		t.Error("die Einrichtung hätte zurückgenommen werden müssen")
	}
}

func TestDNSRunWithoutAccountExplains(t *testing.T) {
	t.Setenv("ZA_DATA", t.TempDir())
	t.Setenv("ZA_CLOUDFLARE_TOKEN", "")
	p := &Profile{ID: "x.test", Domains: []string{"x.test"}, Method: "dns"}
	if _, err := newDNSRouter(p.DNSAccount); err == nil || !strings.Contains(err.Error(), "DNS-Zugänge") {
		t.Errorf("Meldung ohne Zugang: %v", err)
	}
}
