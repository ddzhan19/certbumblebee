package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeNames(t *testing.T) {
	got, err := normalizeNames("Intranet  10.0.0.5, *.Firma.LOCAL\nserver.example.com [::1] 10.0.0.5 srv_01.intern.")
	if err != nil {
		t.Fatal(err)
	}
	want := "intranet|10.0.0.5|*.firma.local|server.example.com|::1|srv_01.intern"
	if strings.Join(got, "|") != want {
		t.Errorf("got %v\nwant %s", got, want)
	}
	for _, bad := range []string{"", "  ", "http://x.de", "a b/c", "-x.de", "x..de", "ex@mple.de", "*.*.de", strings.Repeat("a", 64) + ".de"} {
		if _, err := normalizeNames(bad); err == nil {
			t.Errorf("%q wurde akzeptiert", bad)
		}
	}
	// ACME-Domains bleiben streng
	for _, bad := range []string{"intranet", "10.0.0.5"} {
		if _, err := normalizeDomains(bad); err == nil {
			t.Errorf("normalizeDomains hat %q akzeptiert", bad)
		}
	}
}

func TestSlugAndBaseForSelfSignedNames(t *testing.T) {
	for in, want := range map[string]string{
		"*.firma.local": "wildcard.firma.local",
		"::1":           "1",
		"fe80::1":       "fe80__1",
		"10.0.0.5":      "10.0.0.5",
		"intranet":      "intranet",
	} {
		if got := slugID(in); got != want || !validID(got) {
			t.Errorf("slugID(%q) = %q, erwartet %q (gültig=%v)", in, got, want, validID(got))
		}
	}
	if got := baseName("", "fe80::1"); got != "fe80--1" {
		t.Errorf("baseName IPv6: %q", got)
	}
	if got := baseName("", "*.firma.local"); got != "_.firma.local" {
		t.Errorf("baseName Wildcard: %q", got)
	}
}

func TestSelfSignedLifecycle(t *testing.T) {
	t.Setenv("ZA_DATA", t.TempDir())
	req := CreateRequest{
		Domains: "server.example.com intranet 10.0.0.5 *.firma.local", Method: "selfsigned", ValidDays: 730,
		TargetDir: filepath.Join(t.TempDir(), "ziel"), Password: "Müller-Pa$$wort 1!",
		Outputs: []string{"pfx", "cert", "chain", "fullchain", "key", "csr"}, CertFormat: "crt",
		AutoRenew: true, TaskTime: "04:15", RunAs: "system", KeyBits: 2048,
		Server: "custom", CustomURL: "https://nicht.erreichbar.example/dir", Email: "x@example.org", Firewall: true,
	}
	p, res, j, err := create(t, req)
	if err != nil {
		t.Fatalf("Einrichten: %v", err)
	}
	if p.Method != "selfsigned" || p.ValidDays != 730 || p.ServerKind != "selfsigned" || p.DirectoryURL != "" || p.Email != "" || p.Firewall {
		t.Errorf("Profil: %+v", p)
	}
	if res.Result != "ausgestellt" || !res.Issued || res.Cert == nil || !res.Cert.SelfSigned {
		t.Fatalf("Ergebnis: %+v", res)
	}
	// Nur die nötigen Schritte, kein Konto/Webserver/Bestellung
	for _, s := range j.view().Steps {
		switch s.Key {
		case "vorbereitung", "konto", "bestellung", "pruefung":
			t.Errorf("Schritt „%s“ gehört nicht zu selbstsignierten Zertifikaten", s.Key)
		}
	}
	if stepState(j, "zertifikat") != "ok" || stepState(j, "pfx") != "ok" || stepState(j, "ziel") != "ok" {
		t.Errorf("Schritte: %+v", j.view().Steps)
	}
	if _, err := os.Stat(filepath.Join(profileDir(p.ID), "account.key")); err == nil {
		t.Error("ein selbstsigniertes Zertifikat braucht keinen Konto-Schlüssel")
	}
	// Zwischenzertifikate gibt es nicht: „chain“ wird übergangen, es bleiben 5 Dateien
	if len(p.Outputs) != 5 || p.hasOutput("chain") || len(res.Files) != 5 {
		t.Fatalf("Dateien: %v", res.Files)
	}
	if _, err := os.Stat(filepath.Join(p.TargetDir, "server.example.com-chain.crt")); err == nil {
		t.Error("leere Kette wurde geschrieben")
	}
	if _, err := buildProfile(CreateRequest{Domains: "x.local", Method: "selfsigned", TargetDir: p.TargetDir, Outputs: []string{"chain"}}); err == nil {
		t.Error("nur „Zwischenzertifikate“ hätte abgelehnt werden müssen")
	}
	crtPEM, _ := os.ReadFile(filepath.Join(p.TargetDir, "server.example.com.crt"))
	blk, _ := pem.Decode(crtPEM)
	if blk == nil {
		t.Fatal("kein PEM")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// Selbstsigniert: prüft sich selbst
	pool := x509.NewCertPool()
	pool.AddCert(c)
	if _, err := c.Verify(x509.VerifyOptions{Roots: pool, DNSName: "intranet", CurrentTime: time.Now()}); err != nil {
		t.Errorf("Prüfung gegen sich selbst: %v", err)
	}
	if err := c.VerifyHostname("server.example.com"); err != nil {
		t.Error(err)
	}
	if err := c.VerifyHostname("10.0.0.5"); err != nil {
		t.Errorf("IP-Adresse fehlt im Zertifikat: %v", err)
	}
	if err := c.VerifyHostname("test.firma.local"); err != nil {
		t.Errorf("Wildcard fehlt: %v", err)
	}
	if c.VerifyHostname("anders.example") == nil {
		t.Error("Zertifikat gilt für einen fremden Namen")
	}
	if len(c.IPAddresses) != 1 || !c.IPAddresses[0].Equal(net.ParseIP("10.0.0.5")) {
		t.Errorf("IP-SANs: %v", c.IPAddresses)
	}
	days := c.NotAfter.Sub(c.NotBefore).Hours() / 24
	if days < 729 || days > 731 {
		t.Errorf("Gültigkeit %.1f Tage statt 730", days)
	}
	if c.IsCA || !c.BasicConstraintsValid || c.KeyUsage&x509.KeyUsageDigitalSignature == 0 || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("Verwendungszwecke: CA=%v KU=%v EKU=%v", c.IsCA, c.KeyUsage, c.ExtKeyUsage)
	}
	if c.SerialNumber.Sign() <= 0 || c.SerialNumber.BitLen() < 64 {
		t.Errorf("Seriennummer: %v", c.SerialNumber)
	}
	if c.Subject.CommonName != "server.example.com" {
		t.Errorf("Subject: %v", c.Subject)
	}
	// Schlüssel und Anforderung passen zum Zertifikat (OpenSSL)
	keyPEM, _ := os.ReadFile(filepath.Join(p.TargetDir, "server.example.com.key"))
	certMod := openssl(t, string(crtPEM), "x509", "-noout", "-modulus")
	if openssl(t, string(keyPEM), "rsa", "-noout", "-modulus") != certMod {
		t.Error("Schlüssel passt nicht zum Zertifikat")
	}
	csrPEM, _ := os.ReadFile(filepath.Join(p.TargetDir, "server.example.com.csr"))
	if out := openssl(t, string(csrPEM), "req", "-noout", "-verify", "-text"); !strings.Contains(out, "IP Address:10.0.0.5") || !strings.Contains(out, "DNS:intranet") || !strings.Contains(out, "DNS:*.firma.local") {
		t.Errorf("CSR ohne die erwarteten Namen:\n%s", out)
	}
	if openssl(t, string(csrPEM), "req", "-noout", "-modulus") != certMod {
		t.Error("Anforderung passt nicht zum Schlüssel")
	}
	// fullchain = nur das Zertifikat; PFX lesbar
	full, _ := os.ReadFile(filepath.Join(p.TargetDir, "server.example.com-fullchain.crt"))
	if !bytes.Equal(full, crtPEM) {
		t.Error("fullchain weicht vom Zertifikat ab")
	}
	if out := openssl(t, "", "pkcs12", "-in", filepath.Join(p.TargetDir, "server.example.com.pfx"), "-passin", "pass:Müller-Pa$$wort 1!", "-legacy", "-nokeys"); !strings.Contains(out, "BEGIN CERTIFICATE") {
		t.Error("PFX nicht lesbar")
	}

	// Erneuern: noch nicht fällig, dann erzwungen
	r2, err := renewProfile(context.Background(), p.ID, false, newJob(p.ID))
	if err != nil || r2.Result != "nicht-faellig" || r2.Issued {
		t.Fatalf("Erneuerung ohne Bedarf: %v %+v", err, r2)
	}
	r3, err := renewProfile(context.Background(), p.ID, true, newJob(p.ID))
	if err != nil || r3.Result != "erneuert" || !r3.Written {
		t.Fatalf("Erneuerung erzwungen: %v %+v", err, r3)
	}
	c2PEM, _ := os.ReadFile(filepath.Join(p.TargetDir, "server.example.com.crt"))
	blk2, _ := pem.Decode(c2PEM)
	c2, _ := x509.ParseCertificate(blk2.Bytes)
	if c2.SerialNumber.Cmp(c.SerialNumber) == 0 {
		t.Error("Zertifikat wurde nicht ausgetauscht")
	}
	if r3.Cert.Fingerprint == res.Cert.Fingerprint {
		t.Error("Fingerabdruck unverändert")
	}
	// Übersicht
	found := false
	for _, v := range listProfiles() {
		if v.ID == p.ID {
			found = true
			if v.Method != "selfsigned" || v.Cert == nil || !v.Cert.SelfSigned || len(v.Files) != 5 {
				t.Errorf("Übersicht: %+v", v)
			}
			if len(v.Cert.DNSNames) != 4 {
				t.Errorf("Namen in der Übersicht: %v", v.Cert.DNSNames)
			}
		}
	}
	if !found {
		t.Error("Einrichtung fehlt in der Übersicht")
	}
	// Löschen
	if err := deleteProfile(p.ID, newJob(p.ID)); err != nil {
		t.Fatal(err)
	}
}

func TestSelfSignedDueRenewalAndChangedNames(t *testing.T) {
	t.Setenv("ZA_DATA", t.TempDir())
	req := CreateRequest{
		Domains: "intern.local", Method: "selfsigned", ValidDays: 30, TargetDir: filepath.Join(t.TempDir(), "z"),
		Outputs: []string{"cert", "key"}, CertFormat: "pem", KeyBits: 2048,
	}
	p, res, _, err := create(t, req)
	if err != nil || res.Result != "ausgestellt" {
		t.Fatalf("%v %+v", err, res)
	}
	// ohne PFX braucht die Erneuerung kein Passwort; 30 Tage Laufzeit: 10 Tage vor Ablauf fällig -> noch nicht
	if r, err := renewProfile(context.Background(), p.ID, false, newJob(p.ID)); err != nil || r.Result != "nicht-faellig" {
		t.Fatalf("%v %+v", err, r)
	}
	// Name geändert -> neues Zertifikat
	p2, err := loadProfile(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	p2.Domains = []string{"intern.local", "10.1.2.3"}
	if err := saveProfile(p2); err != nil {
		t.Fatal(err)
	}
	r, err := renewProfile(context.Background(), p.ID, false, newJob(p.ID))
	if err != nil || r.Result != "erneuert" {
		t.Fatalf("Namenswechsel: %v %+v", err, r)
	}
	b, _ := os.ReadFile(filepath.Join(p.TargetDir, "intern.local.pem"))
	blk, _ := pem.Decode(b)
	c, _ := x509.ParseCertificate(blk.Bytes)
	if c.VerifyHostname("10.1.2.3") != nil {
		t.Error("neue IP-Adresse fehlt")
	}
	// Ablaufnah: Zertifikat mit 30 Tagen, das in 5 Tagen abläuft, wird bei Prüfung erneuert
	if !renewDue(c, c.NotAfter.Add(-5*24*time.Hour)) || renewDue(c, c.NotAfter.Add(-20*24*time.Hour)) {
		t.Error("Fälligkeit bei 30 Tagen Laufzeit")
	}
}

func TestBuildProfileSelfSignedValidation(t *testing.T) {
	t.Setenv("ZA_DATA", t.TempDir())
	base := CreateRequest{Domains: "x.local", Method: "selfsigned", TargetDir: filepath.Join(t.TempDir(), "z"), Password: "pw"}
	for _, d := range []int{10, 4000, -1} {
		r := base
		r.ValidDays = d
		if _, err := buildProfile(r); err == nil || !strings.Contains(err.Error(), "Gültigkeit") {
			t.Errorf("%d Tage wurden akzeptiert: %v", d, err)
		}
	}
	r := base
	p, err := buildProfile(r)
	if err != nil || p.ValidDays != 365 {
		t.Errorf("Standard-Gültigkeit: %v %+v", err, p)
	}
	r.Domains = "::1"
	if p, err := buildProfile(r); err != nil || !validID(p.ID) {
		t.Errorf("IPv6: %v", err)
	}
}
