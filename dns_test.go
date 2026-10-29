package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "cf-test-token-0123456789abcdefABCDEF_-"

func newCFClient(t *testing.T) (*fakeCF, *cloudflare) {
	t.Helper()
	f := newFakeCF(t, testToken)
	return f, newCloudflare(testToken)
}

func TestCloudflareFindZone(t *testing.T) {
	f, c := newCFClient(t)
	f.addZone("beispiel.de")
	f.addZone("sub.beispiel.de") // delegierte Unterzone
	f.addZone("andere.org")
	ctx := context.Background()

	for name, want := range map[string]string{
		"_acme-challenge.beispiel.de":       "beispiel.de",
		"_acme-challenge.www.beispiel.de":   "beispiel.de",
		"_acme-challenge.a.sub.beispiel.de": "sub.beispiel.de",
		"_acme-challenge.sub.beispiel.de":   "sub.beispiel.de",
		"_ACME-CHALLENGE.Tief.Andere.ORG.":  "andere.org",
		"_acme-challenge.x.y.z.andere.org":  "andere.org",
	} {
		z, err := c.FindZone(ctx, name)
		if err != nil || z == nil || z.Name != want {
			t.Errorf("%s: %+v %v, erwartet %s", name, z, err, want)
		}
	}
	for _, name := range []string{"_acme-challenge.unbekannt.de", "de", "_acme-challenge.beispiel.com"} {
		if z, err := c.FindZone(ctx, name); err != nil || z != nil {
			t.Errorf("%s: sollte keine Zone liefern, bekam %+v %v", name, z, err)
		}
	}
	// Ergebnisse werden zwischengespeichert, auch „nicht gefunden“.
	n := len(f.requests())
	_, _ = c.FindZone(ctx, "_acme-challenge.beispiel.de")
	_, _ = c.FindZone(ctx, "_acme-challenge.unbekannt.de")
	if len(f.requests()) != n {
		t.Errorf("Zwischenspeicher fehlt: %d neue Anfragen", len(f.requests())-n)
	}
	// Nie nach der obersten Ebene („de“) fragen.
	for _, r := range f.requests() {
		if strings.Contains(r, "name=de&") || strings.HasSuffix(r, "name=de") {
			t.Errorf("unnötige Anfrage: %s", r)
		}
	}
}

func TestCloudflareAddDeleteAndStale(t *testing.T) {
	f, c := newCFClient(t)
	z := f.addZone("beispiel.de")
	ctx := context.Background()
	zone := DNSZone{ID: z.ID, Name: z.Name}

	id1, err := c.AddTXT(ctx, zone, "_acme-challenge.beispiel.de", "wert-1")
	if err != nil || id1 == "" {
		t.Fatal(id1, err)
	}
	id2, err := c.AddTXT(ctx, zone, "_acme-challenge.beispiel.de", "wert-2")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.txt("_acme-challenge.beispiel.de"), ","); got != "wert-1,wert-2" {
		t.Fatalf("Einträge: %s", got)
	}
	// Dasselbe noch einmal: Der vorhandene Eintrag wird verwendet.
	again, err := c.AddTXT(ctx, zone, "_acme-challenge.beispiel.de", "wert-1")
	if err != nil || again != id1 {
		t.Fatalf("doppelter Eintrag: %q %v (erwartet %q)", again, err, id1)
	}
	if err := c.DeleteRecord(ctx, zone, id1); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteRecord(ctx, zone, id1); err != nil { // schon weg: kein Fehler
		t.Fatalf("zweites Löschen: %v", err)
	}
	if err := c.DeleteRecord(ctx, zone, id2); err != nil {
		t.Fatal(err)
	}
	if f.countRecords() != 0 {
		t.Fatalf("es sind %d Einträge übrig", f.countRecords())
	}

	// Aufräumen erfasst nur Einträge mit dem Kommentar dieses Programms.
	z.recs = append(z.recs,
		fakeRec{ID: "fremd1", Type: "TXT", Name: "_acme-challenge.beispiel.de", Content: "fremder-wert", Comment: "von Hand"},
		fakeRec{ID: "alt1", Type: "TXT", Name: "_acme-challenge.beispiel.de", Content: "alt", Comment: acmeRecordComment},
		fakeRec{ID: "alt2", Type: "TXT", Name: "_acme-challenge.anders.beispiel.de", Content: "alt", Comment: acmeRecordComment},
		fakeRec{ID: "a1", Type: "A", Name: "_acme-challenge.beispiel.de", Content: "1.2.3.4", Comment: acmeRecordComment})
	n, err := c.CleanStale(ctx, zone, "_acme-challenge.beispiel.de")
	if err != nil || n != 1 {
		t.Fatalf("CleanStale: %d %v", n, err)
	}
	if got := strings.Join(f.txt("_acme-challenge.beispiel.de"), ","); got != "fremder-wert" {
		t.Fatalf("falsche Einträge entfernt: %s", got)
	}
	if len(f.txt("_acme-challenge.anders.beispiel.de")) != 1 {
		t.Fatal("ein anderer Name wurde angefasst")
	}
}

func TestCloudflareErrors(t *testing.T) {
	f, c := newCFClient(t)
	z := f.addZone("beispiel.de")
	ctx := context.Background()
	zone := DNSZone{ID: z.ID, Name: z.Name}

	// Falscher Token
	bad := newCloudflare("falscher-token-0123456789abcdef")
	_, _, err := bad.Zones(ctx)
	if err == nil || !strings.Contains(err.Error(), "Zugangstoken") {
		t.Errorf("falscher Token: %v", err)
	}
	// Token ohne Schreibrecht
	f.forbidWrite = true
	_, err = c.AddTXT(ctx, zone, "_acme-challenge.beispiel.de", "x")
	if err == nil || !strings.Contains(err.Error(), "Berechtigung") || !strings.Contains(err.Error(), "Bearbeiten") {
		t.Errorf("fehlende Berechtigung: %v", err)
	}
	f.forbidWrite = false
	// CNAME im Weg
	f.cname["_acme-challenge.beispiel.de"] = true
	_, err = c.AddTXT(ctx, zone, "_acme-challenge.beispiel.de", "x")
	if err == nil || !strings.Contains(err.Error(), "CNAME") {
		t.Errorf("CNAME: %v", err)
	}
	delete(f.cname, "_acme-challenge.beispiel.de")
	// Drosselung: wird wiederholt
	f.throttle = 2
	if _, err := c.AddTXT(ctx, zone, "_acme-challenge.beispiel.de", "nach-drossel"); err != nil {
		t.Errorf("nach Drosselung: %v", err)
	}
	// Dauerhaft gedrosselt: verständliche Meldung
	f.throttle = 100
	_, _, err = c.Zones(ctx)
	if err == nil || !strings.Contains(err.Error(), "begrenzt") {
		t.Errorf("dauerhafte Drosselung: %v", err)
	}
	f.throttle = 0
	// Nicht erreichbar
	f.srv.Close()
	_, _, err = newCloudflare(testToken).Zones(ctx)
	var ue *userError
	if !errors.As(err, &ue) || !strings.Contains(err.Error(), "nicht erreichbar") {
		t.Errorf("nicht erreichbar: %v", err)
	}
}

func TestCloudflareAPIOverrideOnlySafeURLs(t *testing.T) {
	for in, want := range map[string]string{
		"":                          cloudflareDefaultAPI,
		"http://127.0.0.1:9/v4/":    "http://127.0.0.1:9/v4",
		"https://cf.example/client": "https://cf.example/client",
		"http://evil.example/v4":    cloudflareDefaultAPI, // Klartext zu fremden Rechnern: nie mit Token
		"ftp://x":                   cloudflareDefaultAPI,
		"%%%":                       cloudflareDefaultAPI,
	} {
		t.Setenv("ZA_CLOUDFLARE_API", in)
		if got := cloudflareAPI(); got != want {
			t.Errorf("%q: %q, erwartet %q", in, got, want)
		}
	}
}

func TestDNSAccountsStoreAndRouting(t *testing.T) {
	t.Setenv("ZA_DATA", t.TempDir())
	t.Setenv("ZA_CLOUDFLARE_TOKEN", "")
	t.Setenv("ZA_CLOUDFLARE_TOKEN_FILE", "")
	f := newFakeCF(t, testToken)
	f.addZone("beispiel.de")
	ctx := context.Background()

	// Eingaben prüfen
	for _, c := range []struct{ name, tok string }{{"", testToken}, {"x", ""}, {"x", "zu kurz"}, {"x", "mit Leerzeichen 0123456789abcdefghij"}, {"a<b", testToken}, {"x", "falscher-token-0123456789abcdef"}} {
		if _, _, _, err := addDNSAccount(ctx, c.name, c.tok); err == nil {
			t.Errorf("%+v hätte abgelehnt werden müssen", c)
		}
	}
	acc, zones, total, err := addDNSAccount(ctx, "Firma", " "+testToken+"\n")
	if err != nil || len(zones) != 1 || total != 1 || acc.Token != "" {
		t.Fatalf("addDNSAccount: %+v %v %d %v", acc, zones, total, err)
	}
	if _, _, _, err := addDNSAccount(ctx, "firma", testToken); err == nil {
		t.Error("doppelter Name hätte abgelehnt werden müssen")
	}
	// Der Token steht nicht im Klartext auf der Platte.
	b, _ := os.ReadFile(dnsAccountsPath())
	if strings.Contains(string(b), testToken) {
		t.Fatal("Token liegt im Klartext in der Datei")
	}
	got, ok := getDNSAccount(acc.ID)
	if !ok {
		t.Fatal("Zugang nicht gefunden")
	}
	if tok, err := dnsAccountToken(got); err != nil || tok != testToken {
		t.Fatalf("Token entschlüsseln: %q %v", tok, err)
	}

	// Zugang aus der Umgebung steht vorn und lässt sich nicht löschen.
	t.Setenv("ZA_CLOUDFLARE_TOKEN", testToken)
	list := listDNSAccounts()
	if len(list) != 2 || list[0].ID != envAccountID || !list[0].FromEnv {
		t.Fatalf("Liste: %+v", list)
	}
	if err := removeDNSAccount(envAccountID); err == nil {
		t.Error("Umgebungszugang darf nicht löschbar sein")
	}
	t.Setenv("ZA_CLOUDFLARE_TOKEN", "")
	f2 := t.TempDir() + "/token"
	_ = os.WriteFile(f2, []byte(testToken+"\n"), 0o600)
	t.Setenv("ZA_CLOUDFLARE_TOKEN_FILE", f2)
	if l := listDNSAccounts(); len(l) != 2 || !l[0].FromEnv {
		t.Fatalf("Token aus Datei: %+v", l)
	}
	t.Setenv("ZA_CLOUDFLARE_TOKEN_FILE", "")

	// Weiterleitung: Zugang gewählt / automatisch
	r, err := newDNSRouter("")
	if err != nil {
		t.Fatal(err)
	}
	loc, err := r.locate(ctx, "_acme-challenge.www.beispiel.de")
	if err != nil || loc.zone.Name != "beispiel.de" || loc.acct.acc.ID != acc.ID {
		t.Fatalf("locate: %+v %v", loc, err)
	}
	if _, err := r.locate(ctx, "_acme-challenge.fehlt.example"); err == nil || !strings.Contains(err.Error(), "keine passende Zone") {
		t.Errorf("unbekannte Zone: %v", err)
	}
	if _, err := newDNSRouter("cf-gibtsnicht"); err == nil {
		t.Error("unbekannter Zugang hätte scheitern müssen")
	}

	// Löschen nur, wenn kein Zertifikat den Zugang nutzt.
	p := &Profile{ID: "x.beispiel.de", Domains: []string{"x.beispiel.de"}, Method: "dns", DNSAccount: acc.ID}
	if err := saveProfile(p); err != nil {
		t.Fatal(err)
	}
	if err := removeDNSAccount(acc.ID); err == nil || !strings.Contains(err.Error(), "x.beispiel.de") {
		t.Errorf("Löschen trotz Benutzung: %v", err)
	}
	_ = os.RemoveAll(profileDir(p.ID))

	// Automatik-Modus (kein Zugang gewählt): Der letzte Zugang bleibt geschützt, mit einem zweiten darf einer gehen.
	pa := &Profile{ID: "auto.beispiel.de", Domains: []string{"auto.beispiel.de"}, Method: "dns"}
	if err := saveProfile(pa); err != nil {
		t.Fatal(err)
	}
	if err := removeDNSAccount(acc.ID); err == nil || !strings.Contains(err.Error(), "auto.beispiel.de") || !strings.Contains(err.Error(), "letzte Zugang") {
		t.Errorf("Löschen des letzten Zugangs trotz Automatik-Zertifikat: %v", err)
	}
	if len(listDNSAccounts()) != 1 {
		t.Fatal("Zugang wurde trotz Fehler entfernt")
	}
	second, _, _, err := addDNSAccount(ctx, "Zweiter", testToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := removeDNSAccount(acc.ID); err != nil {
		t.Fatalf("Löschen mit zweitem Zugang: %v", err)
	}
	_ = os.RemoveAll(profileDir(pa.ID))
	if err := removeDNSAccount(second.ID); err != nil {
		t.Fatal(err)
	}
	if len(listDNSAccounts()) != 0 {
		t.Fatal("Zugang ist noch da")
	}
	if _, err := newDNSRouter(""); err == nil || !strings.Contains(err.Error(), "kein DNS-Zugang") {
		t.Errorf("ohne Zugang: %v", err)
	}
}

func TestRoutingAcrossAccountsPerZone(t *testing.T) {
	t.Setenv("ZA_DATA", t.TempDir())
	t.Setenv("ZA_CLOUDFLARE_TOKEN", "")
	// Zwei Cloudflare-Konten mit je eigener Zone, aber derselben API-Attrappe: Der Token entscheidet, was sichtbar ist.
	f := newFakeCF(t, testToken)
	f.addZone("eins.de")
	ctx := context.Background()
	if _, _, _, err := addDNSAccount(ctx, "Konto 1", testToken); err != nil {
		t.Fatal(err)
	}
	r, err := newDNSRouter("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.locate(ctx, "_acme-challenge.eins.de"); err != nil {
		t.Fatal(err)
	}
	// Ungültiger Token bei einem Zugang: Fehler nennt den Zugang.
	f.token = "anderer-token-0123456789abcdefgh"
	r2, _ := newDNSRouter("")
	if _, err := r2.locate(ctx, "_acme-challenge.eins.de"); err == nil || !strings.Contains(err.Error(), "Konto 1") || !strings.Contains(err.Error(), "Zugangstoken") {
		t.Errorf("Fehler nennt den Zugang nicht: %v", err)
	}
}

func TestPlaceWaitCleanup(t *testing.T) {
	t.Setenv("ZA_DATA", t.TempDir())
	t.Setenv("ZA_CLOUDFLARE_TOKEN", "")
	f := newFakeCF(t, testToken)
	f.addZone("eins.de")
	f.addZone("zwei.org")
	ctx := context.Background()
	if _, _, _, err := addDNSAccount(ctx, "Konto", testToken); err != nil {
		t.Fatal(err)
	}
	router, err := newDNSRouter("")
	if err != nil {
		t.Fatal(err)
	}
	recs := []DNSRecord{
		{Name: "_acme-challenge.eins.de", Values: []string{"a", "b"}},
		{Name: "_acme-challenge.www.zwei.org", Values: []string{"c"}},
	}
	rep := &collectReporter{id: "t"}

	// Das Warten fragt die Nameserver; erst der dritte Versuch zeigt alles.
	var calls atomic.Int32
	old, oldEvery := authTXT, dnsPollEvery
	defer func() { authTXT, dnsPollEvery = old, oldEvery }()
	dnsPollEvery = time.Millisecond
	authTXT = func(_ context.Context, ns []string, name string) ([]string, error) {
		if len(ns) == 0 {
			t.Errorf("keine Nameserver für %s", name)
		}
		if calls.Add(1) < 3 {
			return nil, nil
		}
		return f.txt(name), nil
	}
	pl, err := placeRecords(ctx, router, recs, rep)
	if err != nil {
		t.Fatal(err)
	}
	if f.countRecords() != 3 {
		t.Fatalf("angelegt: %d", f.countRecords())
	}
	if err := pl.waitVisible(ctx, rep); err != nil {
		t.Fatal(err)
	}
	if calls.Load() < 3 {
		t.Errorf("zu früh fertig: %d Abfragen", calls.Load())
	}
	n, failed := pl.cleanup(ctx, rep)
	if n != 3 || len(failed) != 0 || f.countRecords() != 0 {
		t.Fatalf("aufgeräumt: %d, Fehler %v, übrig %d", n, failed, f.countRecords())
	}
	if n, _ := pl.cleanup(ctx, rep); n != 0 { // zweiter Aufruf tut nichts
		t.Errorf("zweites Aufräumen löschte %d", n)
	}

	// Scheitert ein Eintrag, wird zurückgerollt, was schon angelegt war.
	f.cname["_acme-challenge.www.zwei.org"] = true
	if _, err := placeRecords(ctx, router, recs, rep); err == nil {
		t.Fatal("CNAME hätte scheitern müssen")
	}
	if f.countRecords() != 0 {
		t.Fatalf("Rückbau unvollständig: %d Einträge", f.countRecords())
	}
	delete(f.cname, "_acme-challenge.www.zwei.org")

	// Nicht auslieferbar: nach der Höchstdauer eine klare Meldung.
	dnsPollMaxOld := dnsPollMax
	dnsPollMax = 20 * time.Millisecond
	defer func() { dnsPollMax = dnsPollMaxOld }()
	authTXT = func(context.Context, []string, string) ([]string, error) { return []string{"anderer"}, nil }
	pl, err = placeRecords(ctx, router, recs[:1], rep)
	if err != nil {
		t.Fatal(err)
	}
	err = pl.waitVisible(ctx, rep)
	if err == nil || !strings.Contains(err.Error(), "nicht ausgeliefert") {
		t.Errorf("Zeitüberschreitung: %v", err)
	}
	pl.cleanup(ctx, rep)

	// Direkte Abfrage unmöglich: kurze feste Wartezeit statt Fehler.
	fbOld := dnsFallbackWait
	dnsFallbackWait = 5 * time.Millisecond
	defer func() { dnsFallbackWait = fbOld }()
	calls.Store(0)
	authTXT = func(context.Context, []string, string) ([]string, error) {
		calls.Add(1)
		return nil, errors.New("i/o timeout")
	}
	pl, _ = placeRecords(ctx, router, recs[:1], rep)
	if err := pl.waitVisible(ctx, rep); err != nil {
		t.Errorf("Rückfall auf Wartezeit: %v", err)
	}
	if calls.Load() != 3 {
		t.Errorf("Abfragen vor dem Rückfall: %d", calls.Load())
	}
	pl.cleanup(ctx, rep)

	// Abbruch von außen
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	authTXT = func(context.Context, []string, string) ([]string, error) { return nil, nil }
	pl, _ = placeRecords(ctx, router, recs[:1], rep)
	if err := pl.waitVisible(cctx, rep); err == nil {
		t.Error("Abbruch hätte erkannt werden müssen")
	}
	pl.cleanup(ctx, rep)
}

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

func TestGroupRecords(t *testing.T) {
	ch := []*dnsChallenge{
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
