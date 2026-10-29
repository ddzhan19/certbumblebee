package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestNormalizeWildDomains(t *testing.T) {
	ok := map[string]string{
		"*.Beispiel.de\nbeispiel.de":       "*.beispiel.de,beispiel.de",
		"*.beispiel.de, *.beispiel.de":     "*.beispiel.de",
		"*.münchen.de":                     "*.xn--mnchen-3ya.de",
		"  www.beispiel.de  \n\n a.b.de. ": "www.beispiel.de,a.b.de",
	}
	for in, want := range ok {
		got, err := normalizeWildDomains(in)
		if err != nil || strings.Join(got, ",") != want {
			t.Errorf("%q: %v %v, erwartet %s", in, got, err, want)
		}
	}
	for _, in := range []string{"", "  ", "a.*.de", "*.*.de", "*beispiel.de", "*.", "*.de", "10.0.0.1", "*.10.0.0.1", "https://x.de", "bad name!.de"} {
		if got, err := normalizeWildDomains(in); err == nil {
			t.Errorf("%q hätte abgelehnt werden müssen, ergab %v", in, got)
		}
	}
}

func TestUnquoteTXT(t *testing.T) {
	for in, want := range map[string]string{
		`abc`:                "abc",
		`"abc"`:              "abc",
		`"ab" "cd"`:          "abcd",
		`"a\"b"`:             `a"b`,
		`"v=spf1 -all"`:      "v=spf1 -all",
		`"1234" "5678" "90"`: "1234567890",
		`"x\\y"`:             `x\y`,
	} {
		if got := unquoteTXT(in); got != want {
			t.Errorf("%q: %q, erwartet %q", in, got, want)
		}
	}
}

// fakeDoH antwortet wie ein DNS-over-HTTPS-Dienst mit JSON.
type fakeDoH struct {
	mu   sync.Mutex
	txt  map[string][]string
	fail bool
	hits int
}

func (f *fakeDoH) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits++
	if f.fail {
		http.Error(w, "kaputt", 500)
		return
	}
	name := r.URL.Query().Get("name")
	var ans []map[string]any
	for _, v := range f.txt[name] {
		ans = append(ans, map[string]any{"name": name, "type": 16, "data": `"` + v + `"`})
	}
	ans = append(ans, map[string]any{"name": name, "type": 5, "data": "anderer.typ."})
	_ = json.NewEncoder(w).Encode(map[string]any{"Status": 0, "Answer": ans})
}

func withDoH(t *testing.T, f *fakeDoH) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	old := dohEndpoints
	dohEndpoints = []string{srv.URL + "/dns-query"}
	t.Cleanup(func() { dohEndpoints = old })
}

func TestCheckDNSWithFakeDoH(t *testing.T) {
	f := &fakeDoH{txt: map[string][]string{}}
	withDoH(t, f)
	w := &WildSession{Records: []DNSRecord{
		{Name: "_acme-challenge.a.test", Values: []string{"AAA"}, Domains: []string{"a.test"}},
		{Name: "_acme-challenge.b.test", Values: []string{"B1", "B2"}, Domains: []string{"*.b.test", "b.test"}},
	}}
	res := w.CheckDNS(context.Background())
	if len(res) != 2 || res[0].Complete() || res[1].Complete() || len(res[1].Missing) != 2 {
		t.Fatalf("zu Beginn müsste alles fehlen: %+v", res)
	}
	f.mu.Lock()
	f.txt["_acme-challenge.a.test"] = []string{"AAA", "fremd"}
	f.txt["_acme-challenge.b.test"] = []string{"B2"}
	f.mu.Unlock()
	res = w.CheckDNS(context.Background())
	if !res[0].Complete() {
		t.Fatalf("a.test müsste vollständig sein: %+v", res[0])
	}
	if res[1].Complete() || len(res[1].Found) != 1 || res[1].Missing[0] != "B1" {
		t.Fatalf("b.test müsste B1 vermissen: %+v", res[1])
	}
	f.mu.Lock()
	f.txt["_acme-challenge.b.test"] = []string{"B2", "B1"}
	f.mu.Unlock()
	if res = w.CheckDNS(context.Background()); !res[1].Complete() {
		t.Fatalf("b.test müsste vollständig sein: %+v", res[1])
	}
}

func TestCheckDNSFallsBackToNextEndpoint(t *testing.T) {
	bad := &fakeDoH{fail: true}
	good := &fakeDoH{txt: map[string][]string{"_acme-challenge.c.test": {"CCC"}}}
	s1, s2 := httptest.NewServer(bad), httptest.NewServer(good)
	defer s1.Close()
	defer s2.Close()
	old := dohEndpoints
	dohEndpoints = []string{s1.URL, s2.URL}
	defer func() { dohEndpoints = old }()
	w := &WildSession{Records: []DNSRecord{{Name: "_acme-challenge.c.test", Values: []string{"CCC"}}}}
	if res := w.CheckDNS(context.Background()); !res[0].Complete() {
		t.Fatalf("Ausweichen auf den zweiten Dienst fehlgeschlagen: %+v", res[0])
	}
	if bad.hits == 0 || good.hits == 0 {
		t.Fatalf("beide Dienste hätten gefragt werden müssen (%d/%d)", bad.hits, good.hits)
	}
}

func TestGroupRecords(t *testing.T) {
	ch := []*wildChallenge{
		{domain: "b.test", wildcard: true, name: "_acme-challenge.b.test", value: "Z"},
		{domain: "b.test", name: "_acme-challenge.b.test", value: "A"},
		{domain: "a.test", name: "_acme-challenge.a.test", value: "Q"},
		{domain: "fertig.test", valid: true, name: "_acme-challenge.fertig.test", value: "X"},
	}
	rec := groupRecords(ch)
	if len(rec) != 2 || rec[0].Name != "_acme-challenge.a.test" {
		t.Fatalf("Gruppierung falsch: %+v", rec)
	}
	if strings.Join(rec[1].Values, ",") != "A,Z" || strings.Join(rec[1].Domains, ",") != "*.b.test,b.test" {
		t.Fatalf("Werte/Domains falsch: %+v", rec[1])
	}
}

func TestStartWildRejectsBadInput(t *testing.T) {
	rep := &collectReporter{}
	for _, r := range []WildRequest{
		{Domains: ""},
		{Domains: "a.*.de"},
		{Domains: "*.x.de", Server: "custom", CustomURL: "ftp://x"},
		{Domains: "*.x.de", Email: "kein-mail"},
		{Domains: "*.x.de", KeyBits: 1024},
	} {
		if _, err := startWild(context.Background(), r, rep); err == nil {
			t.Errorf("%+v hätte abgelehnt werden müssen", r)
		}
	}
}

func TestSaveWildResult(t *testing.T) {
	leaf, inter, _, key := testChain(t)
	chain := certsToPEM([]*x509.Certificate{leaf, inter})
	keyPEM := pkcs8PEM(t, key)
	dir := filepath.Join(t.TempDir(), "wild")
	files, err := saveWildResult([]string{"*.beispiel.test", "beispiel.test"}, chain, keyPEM, []byte("CSR"), WildSave{
		TargetDir: dir, Outputs: []string{"pfx", "cert", "key"}, CertFormat: "pem", Password: "pw-ä", PfxFormat: "compat",
	})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, filepath.Base(f))
	}
	if strings.Join(names, ",") != "_.beispiel.test.pfx,_.beispiel.test.pem,_.beispiel.test.key" {
		t.Fatalf("Dateinamen: %v", names)
	}
	b, _ := os.ReadFile(files[0])
	if c, err := openPFX(b, "pw-ä"); err != nil || len(c.Certs) != 2 {
		t.Fatalf("PFX nicht lesbar: %v", err)
	}
	if _, err := saveWildResult([]string{"a.test"}, chain, keyPEM, nil, WildSave{TargetDir: dir, Outputs: []string{"pfx"}}); err == nil {
		t.Fatal("PFX ohne Passwort hätte scheitern müssen")
	}
	if _, err := saveWildResult([]string{"a.test"}, chain, keyPEM, nil, WildSave{TargetDir: "relativ", Outputs: []string{"key"}}); err == nil {
		t.Fatal("relativer Pfad hätte scheitern müssen")
	}
}

// pushTXT legt Einträge im Test-DNS von Pebble an (challtestsrv, Verwaltung auf Port 8055).
func pushTXT(t *testing.T, host, value string) {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"host": host + ".", "value": value})
	r, err := http.Post("http://127.0.0.1:8055/set-txt", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	t.Cleanup(func() {
		b, _ := json.Marshal(map[string]string{"host": host + "."})
		if r, err := http.Post("http://127.0.0.1:8055/clear-txt", "application/json", bytes.NewReader(b)); err == nil {
			r.Body.Close()
		}
	})
}

func TestPebbleWildcardLifecycle(t *testing.T) {
	pebbleOnly(t)
	job := newJob("wild-test")
	ctx := context.Background()

	w, err := startWild(ctx, WildRequest{Domains: "*.wild.test\nwild.test", Server: "custom", CustomURL: "https://localhost:14000/dir", Email: "a@b.test", KeyBits: 2048}, job)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Records) != 1 || w.Records[0].Name != "_acme-challenge.wild.test" || len(w.Records[0].Values) != 2 {
		t.Fatalf("erwartet 1 Eintrag mit 2 Werten: %+v", w.Records)
	}

	// Vor dem Anlegen scheitert die Bestätigung mit einer verständlichen Meldung.
	if err := w.Verify(ctx, job); err == nil {
		t.Fatal("Bestätigung ohne DNS-Eintrag hätte scheitern müssen")
	} else {
		t.Logf("Meldung ohne Eintrag: %v", err)
		if !strings.Contains(err.Error(), "DNS") && !strings.Contains(err.Error(), "TXT") {
			t.Errorf("Meldung nennt den DNS-Eintrag nicht: %v", err)
		}
	}

	// Neue Bestellung, jetzt mit Einträgen.
	job = newJob("wild-test2")
	w, err = startWild(ctx, WildRequest{Domains: "*.wild.test\nwild.test", Server: "custom", CustomURL: "https://localhost:14000/dir"}, job)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range w.Records[0].Values {
		pushTXT(t, w.Records[0].Name, v)
	}
	if err := w.Verify(ctx, job); err != nil {
		t.Fatalf("Bestätigung: %v", err)
	}
	chain, key, csr, err := w.Finish(ctx, job)
	if err != nil {
		t.Fatalf("Ausstellung: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "ziel")
	files, err := saveWildResult(w.Domains, chain, key, csr, WildSave{TargetDir: dir, Outputs: []string{"pfx", "fullchain", "key"}, CertFormat: "crt", Password: "Wild-1!", PfxFormat: "aes"})
	if err != nil {
		t.Fatal(err)
	}
	leaf := firstCert(t, files[1])
	got := strings.Join(leaf.DNSNames, ",")
	if !strings.Contains(got, "*.wild.test") || !strings.Contains(got, "wild.test") {
		t.Fatalf("Namen im Zertifikat: %s", got)
	}
	if st := stepState(job, "pruefung"); st != "ok" {
		t.Errorf("Schritt „pruefung“: %s", st)
	}
	fmt.Fprintln(os.Stderr, "Wildcard-Ablauf mit Pebble in Ordnung:", got)
}

func firstCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := parseCertsPEM(b)
	if err != nil {
		t.Fatal(err)
	}
	return cs[0]
}
