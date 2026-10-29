package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBaseName(t *testing.T) {
	cases := map[string]string{
		"":                 "www.beispiel.de",
		"  ":               "www.beispiel.de",
		"mein-zert":        "mein-zert",
		"mein-zert.pfx":    "mein-zert",
		"Mein-Zert.PFX":    "Mein-Zert",
		"web.beispiel.de":  "web.beispiel.de", // „.de“ ist keine bekannte Endung
		"server.crt":       "server",
		"server.key":       "server",
		"anforderung.csr":  "anforderung",
		"zert.p12":         "zert",
		"wildcard.cer.cer": "wildcard.cer",
	}
	for in, want := range cases {
		if got := baseName(in, "www.beispiel.de"); got != want {
			t.Errorf("baseName(%q) = %q, erwartet %q", in, got, want)
		}
	}
	if got := baseName("", "*.beispiel.de"); got != "_.beispiel.de" {
		t.Errorf("Wildcard-Name: %q", got)
	}
}

func TestPlanOutputs(t *testing.T) {
	names := func(o []OutputSpec) string {
		var s []string
		for _, x := range o {
			s = append(s, x.Kind+"="+x.Name+map[bool]string{true: "(" + x.Enc + ")", false: ""}[x.Enc != ""])
		}
		return strings.Join(s, " ")
	}
	cases := []struct {
		kinds  []string
		format string
		want   string
	}{
		{nil, "", "pfx=a.pfx"},
		{[]string{"csr", "key", "pfx", "cert", "chain", "fullchain"}, "crt", "pfx=a.pfx cert=a.crt chain=a-chain.crt fullchain=a-fullchain.crt key=a.key csr=a.csr"},
		{[]string{"cert", "chain", "fullchain"}, "cer", "cert=a.cer chain=a-chain.cer fullchain=a-fullchain.cer"},
		{[]string{"cert", "chain", "fullchain"}, "pem", "cert=a.pem chain=a-chain.pem fullchain=a-fullchain.pem"},
		{[]string{"cert", "chain"}, "cer-der", "cert=a.cer(der) chain=a-chain.pem"},
		{[]string{"cert", "cert", "csr"}, "", "cert=a.crt csr=a.csr"},
	}
	for _, c := range cases {
		o, err := planOutputs(c.kinds, c.format, "a")
		if err != nil {
			t.Fatalf("%v: %v", c.kinds, err)
		}
		if got := names(o); got != c.want {
			t.Errorf("%v/%s:\n got  %s\n want %s", c.kinds, c.format, got, c.want)
		}
	}
	if _, err := planOutputs([]string{"foo"}, "", "a"); err == nil {
		t.Error("unbekannte Dateiart wurde akzeptiert")
	}
	if _, err := planOutputs([]string{"cert"}, "der", "a"); err == nil {
		t.Error("unbekanntes Format wurde akzeptiert")
	}
}

func TestBuildProfileOutputs(t *testing.T) {
	t.Setenv("ZA_DATA", t.TempDir())
	base := CreateRequest{Domains: "www.beispiel.de", TargetDir: filepath.Join(t.TempDir(), "z"), Server: "staging"}

	// ohne PFX braucht es kein Passwort
	r := base
	r.Outputs = []string{"cert", "key", "csr"}
	p, err := buildProfile(r)
	if err != nil {
		t.Fatalf("ohne PFX: %v", err)
	}
	if p.hasOutput("pfx") || !p.hasOutput("csr") || len(p.Outputs) != 3 {
		t.Errorf("Ausgaben: %+v", p.Outputs)
	}
	// mit PFX schon
	r.Outputs = []string{"pfx", "cert"}
	if _, err := buildProfile(r); err == nil || !strings.Contains(err.Error(), "Passwort") {
		t.Errorf("PFX ohne Passwort: %v", err)
	}
	r.Password = "geheim"
	p, err = buildProfile(r)
	if err != nil || p.FileName != "www.beispiel.de.pfx" {
		t.Errorf("PFX mit Passwort: %v %+v", err, p)
	}
	// eigener Name mit Endung wird bereinigt
	r.FileName = "Mein Server.CRT"
	p, err = buildProfile(r)
	if err != nil || p.Outputs[0].Name != "Mein Server.pfx" || p.Outputs[1].Name != "Mein Server.crt" {
		t.Errorf("Eigener Name: %v %+v", err, p.Outputs)
	}
	// ältere Einrichtung ohne „outputs“
	old := &Profile{Domains: []string{"x.de"}, FileName: "alt.pfx"}
	if o := old.outputs(); len(o) != 1 || o[0].Kind != "pfx" || o[0].Name != "alt.pfx" || !old.hasOutput("pfx") {
		t.Errorf("Standard für alte Einrichtung: %+v", o)
	}
}

func TestRenderOutputs(t *testing.T) {
	// zwei Zertifikate aus dem Testbestand erzeugen wir mit openssl nicht; stattdessen Dummy-Kette mit zwei Blöcken
	ca := selfSigned(t, "Test CA")
	leaf := selfSigned(t, "www.beispiel.de")
	chain := append(pemOf(leaf), pemOf(ca)...)
	d := outputData{Chain: chain, Key: []byte("KEY"), CSR: []byte("CSR"), PFX: []byte("PFX")}

	b, _ := OutputSpec{Kind: "cert"}.render(d)
	if !bytes.Equal(b, pemOf(leaf)) {
		t.Error("cert (PEM) ist nicht das erste Zertifikat")
	}
	der, _ := OutputSpec{Kind: "cert", Enc: "der"}.render(d)
	if c, err := x509.ParseCertificate(der); err != nil || c.Subject.CommonName != "www.beispiel.de" {
		t.Errorf("cert (DER): %v", err)
	}
	b, _ = OutputSpec{Kind: "chain"}.render(d)
	if !bytes.Equal(b, pemOf(ca)) {
		t.Error("chain enthält nicht nur die Zwischenzertifikate")
	}
	if b, _ := (OutputSpec{Kind: "fullchain"}).render(d); !bytes.Equal(b, chain) {
		t.Error("fullchain weicht ab")
	}
	if b, _ := (OutputSpec{Kind: "key"}).render(d); string(b) != "KEY" {
		t.Error("key")
	}
	if b, _ := (OutputSpec{Kind: "csr"}).render(d); string(b) != "CSR" {
		t.Error("csr")
	}
	// keine Zwischenzertifikate: chain wird übersprungen
	if b, err := (OutputSpec{Kind: "chain"}).render(outputData{Chain: pemOf(leaf)}); b != nil || err != nil {
		t.Errorf("chain ohne Zwischenzertifikate: %v %v", b, err)
	}
}

func TestSyncOutputsWritesAndSkips(t *testing.T) {
	leaf := selfSigned(t, "www.beispiel.de")
	ca := selfSigned(t, "Test CA")
	p := &Profile{TargetDir: filepath.Join(t.TempDir(), "neu", "ziel"), Domains: []string{"www.beispiel.de"}}
	outs, _ := planOutputs([]string{"cert", "chain", "fullchain", "key", "csr"}, "crt", "x")
	p.Outputs = outs
	d := outputData{Chain: append(pemOf(leaf), pemOf(ca)...), Key: []byte("KEY"), CSR: []byte("CSR")}
	all, written, err := syncOutputs(p, d)
	if err != nil || len(all) != 5 || len(written) != 5 {
		t.Fatalf("erster Lauf: %v %v %v", err, all, written)
	}
	for _, f := range all {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("fehlt: %s", f)
		}
	}
	if entries, _ := os.ReadDir(p.TargetDir); len(entries) != 5 {
		t.Errorf("Zielordner enthält %d statt 5 Dateien (Hilfsdateien übrig?)", len(entries))
	}
	_, written, err = syncOutputs(p, d)
	if err != nil || len(written) != 0 {
		t.Errorf("zweiter Lauf schreibt erneut: %v %v", err, written)
	}
	d.Key = []byte("KEY2")
	_, written, _ = syncOutputs(p, d)
	if len(written) != 1 || written[0] != "x.key" {
		t.Errorf("nur der Schlüssel hätte sich ändern dürfen: %v", written)
	}
}

// ---------- gegen Pebble ----------

func TestPebbleOutputsAllKinds(t *testing.T) {
	pebbleOnly(t)
	req := baseReq(t, "ausgabe.pebble-test.example www.ausgabe.pebble-test.example")
	req.Outputs = []string{"pfx", "cert", "chain", "fullchain", "key", "csr"}
	req.CertFormat = "cer-der"
	req.FileName = "mein-server.pfx"
	p, res, _, err := create(t, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 6 {
		t.Fatalf("Dateien: %v", res.Files)
	}
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(p.TargetDir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return b
	}
	// Zertifikat als DER (.cer)
	leaf, err := x509.ParseCertificate(read("mein-server.cer"))
	if err != nil {
		t.Fatalf("mein-server.cer ist kein DER-Zertifikat: %v", err)
	}
	if len(leaf.DNSNames) != 2 {
		t.Errorf("Namen: %v", leaf.DNSNames)
	}
	// Kette = alles außer dem Zertifikat selbst
	chain, err := parseCertsPEM(read("mein-server-chain.pem"))
	if err != nil || len(chain) < 1 {
		t.Fatalf("Kette: %v", err)
	}
	full, err := parseCertsPEM(read("mein-server-fullchain.pem"))
	if err != nil || len(full) != len(chain)+1 || !full[0].Equal(leaf) {
		t.Errorf("fullchain passt nicht zu Zertifikat + Kette")
	}
	// Schlüssel passt zum Zertifikat (OpenSSL vergleicht die Modulus-Werte)
	keyMod := openssl(t, string(read("mein-server.key")), "rsa", "-noout", "-modulus")
	certMod := openssl(t, string(pemOf(leaf)), "x509", "-noout", "-modulus")
	if keyMod != certMod {
		t.Error("Schlüssel und Zertifikat passen nicht zusammen")
	}
	// Anforderung: gültig, richtige Namen, passt zum Schlüssel
	blk, _ := pem.Decode(read("mein-server.csr"))
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		t.Fatal("mein-server.csr ist keine PEM-Anforderung")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("Anforderung ungültig: %v", err)
	}
	if len(csr.DNSNames) != 2 || csr.DNSNames[0] != "ausgabe.pebble-test.example" {
		t.Errorf("Namen in der Anforderung: %v", csr.DNSNames)
	}
	csrMod := openssl(t, string(read("mein-server.csr")), "req", "-noout", "-modulus")
	if csrMod != certMod {
		t.Error("Anforderung und Zertifikat haben verschiedene Schlüssel")
	}
	// PFX mit Umlaut-Passwort lesbar
	out := openssl(t, "", "pkcs12", "-in", filepath.Join(p.TargetDir, "mein-server.pfx"), "-passin", "pass:Müller-Pa$$wort 1!", "-legacy", "-nokeys", "-clcerts")
	if !strings.Contains(out, "BEGIN CERTIFICATE") {
		t.Error("PFX nicht lesbar")
	}

	// Erneuern (erzwungen) ersetzt alle Dateien
	oldSerial := leaf.SerialNumber.String()
	res2, err := renewProfile(context.Background(), p.ID, true, newJob(p.ID))
	if err != nil || res2.Result != "erneuert" {
		t.Fatalf("Erneuern: %v %+v", err, res2)
	}
	leaf2, err := x509.ParseCertificate(read("mein-server.cer"))
	if err != nil || leaf2.SerialNumber.String() == oldSerial {
		t.Errorf("Zertifikat wurde nicht ausgetauscht: %v", err)
	}
	if !bytes.Contains(read("mein-server-fullchain.pem"), pemOf(leaf2)) {
		t.Error("fullchain enthält das neue Zertifikat nicht")
	}
	// Übersicht listet alle Dateien als vorhanden
	for _, v := range listProfiles() {
		if v.ID != p.ID {
			continue
		}
		if len(v.Files) != 6 {
			t.Errorf("Übersicht: %d Dateien", len(v.Files))
		}
		for _, f := range v.Files {
			if !f.Found {
				t.Errorf("Übersicht: %s fehlt", f.Name)
			}
		}
	}
}

func TestPebbleWithoutPfxNeedsNoPassword(t *testing.T) {
	pebbleOnly(t)
	req := baseReq(t, "ohnepfx.pebble-test.example")
	req.Password = ""
	req.Outputs = []string{"cert", "key", "csr"}
	req.CertFormat = "pem"
	p, res, j, err := create(t, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 3 {
		t.Fatalf("Dateien: %v", res.Files)
	}
	if _, err := os.Stat(filepath.Join(p.TargetDir, "ohnepfx.pebble-test.example.pem")); err != nil {
		t.Error("cert .pem fehlt")
	}
	if entries, _ := filepath.Glob(filepath.Join(p.TargetDir, "*.pfx")); len(entries) != 0 {
		t.Error("es wurde trotzdem eine PFX geschrieben")
	}
	if _, err := os.Stat(filepath.Join(profileDir(p.ID), "pfx.secret")); err == nil {
		t.Error("ohne PFX darf kein Passwort gespeichert werden")
	}
	for _, s := range j.view().Steps {
		if s.Key == "pfx" {
			t.Error("Schritt „PFX erzeugen“ wird angezeigt, obwohl keine PFX gewünscht ist")
		}
	}
	// Die Aufgabe ruft „renew“ auf: das muss ohne Passwort funktionieren
	if _, err := renewProfile(context.Background(), p.ID, false, newJob(p.ID)); err != nil {
		t.Errorf("Erneuerung ohne PFX: %v", err)
	}
}

// ---------- Testhelfer ----------

func selfSigned(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key := genTestKey(t)
	tmpl := &x509.Certificate{SerialNumber: bigFrom(int64(len(cn)) + 7), Subject: pkixName(cn), NotBefore: nowMinus(), NotAfter: nowPlus()}
	der, err := x509.CreateCertificate(randReader(), tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}
