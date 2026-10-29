package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testChain erzeugt Wurzel, Zwischenzertifikat und Endzertifikat (alle RSA) samt Schlüssel des Endzertifikats.
func testChain(t *testing.T) (leaf, inter, root *x509.Certificate, leafKey *rsa.PrivateKey) {
	t.Helper()
	mk := func(cn string, parent *x509.Certificate, parentKey *rsa.PrivateKey, ca bool, serial int64) (*x509.Certificate, *rsa.PrivateKey) {
		k := genTestKey(t)
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: ca,
		}
		if ca {
			tpl.KeyUsage |= x509.KeyUsageCertSign
		} else {
			tpl.DNSNames = []string{"www.beispiel.test"}
		}
		signer, signKey := tpl, k
		if parent != nil {
			signer, signKey = parent, parentKey
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &k.PublicKey, signKey)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c, k
	}
	root, rootKey := mk("Test Wurzel", nil, nil, true, 1)
	inter, interKey := mk("Test Zwischen", root, rootKey, true, 2)
	leaf, leafKey = mk("www.beispiel.test", inter, interKey, false, 3)
	return
}

func pkcs8PEM(t *testing.T, k crypto.PrivateKey) []byte {
	t.Helper()
	b, err := keyToPKCS8PEM(k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOrderChainAndPemToPFXRoundtrip(t *testing.T) {
	leaf, inter, root, key := testChain(t)
	// bewusst durcheinander
	mixed := certsToPEM([]*x509.Certificate{root, leaf, inter})

	for _, format := range []string{"compat", "aes"} {
		res, err := pemToPFX(mixed, pkcs8PEM(t, key), "", "Pä$$wort-ß 1", format)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if res.Count != 3 || !res.Leaf.Equal(leaf) {
			t.Fatalf("%s: Reihenfolge falsch (Anzahl %d)", format, res.Count)
		}
		c, err := openPFX(res.PFX, "Pä$$wort-ß 1")
		if err != nil {
			t.Fatalf("%s: öffnen: %v", format, err)
		}
		if len(c.Certs) != 3 || !c.Certs[0].Equal(leaf) || !c.Certs[1].Equal(inter) || !c.Certs[2].Equal(root) {
			t.Fatalf("%s: Kette im PFX nicht geordnet", format)
		}
		if c.Key == nil || !bytes.Contains(c.KeyPEM, []byte("BEGIN PRIVATE KEY")) {
			t.Fatalf("%s: Schlüssel fehlt", format)
		}
		if bytes.Count(c.FullchainPEM, []byte("BEGIN CERTIFICATE")) != 3 || bytes.Count(c.ChainPEM, []byte("BEGIN CERTIFICATE")) != 2 || bytes.Count(c.CertPEM, []byte("BEGIN CERTIFICATE")) != 1 {
			t.Fatalf("%s: PEM-Teile falsch", format)
		}
		if _, err := openPFX(res.PFX, "falsch"); err == nil || !strings.Contains(err.Error(), "Passwort") {
			t.Fatalf("%s: falsches Passwort nicht erkannt: %v", format, err)
		}
		if _, err := openPFX([]byte("kein pfx"), "x"); err == nil {
			t.Fatalf("%s: Müll nicht erkannt", format)
		}
	}
}

func TestPemToPFXErrors(t *testing.T) {
	leaf, inter, _, key := testChain(t)
	other := genTestKey(t)
	certs := certsToPEM([]*x509.Certificate{leaf, inter})
	cases := []struct {
		name         string
		certs, key   []byte
		keyPw, pfxPw string
		want         string
	}{
		{"kein Zertifikat", nil, pkcs8PEM(t, key), "", "x", "kein Zertifikat"},
		{"kein Schlüssel", certs, nil, "", "x", "kein privater Schlüssel"},
		{"kein Passwort", certs, pkcs8PEM(t, key), "", "", "Passwort für die PFX"},
		{"falscher Schlüssel", certs, pkcs8PEM(t, other), "", "x", "gehört zu keinem"},
		{"Müll als Zertifikat", []byte("hallo"), pkcs8PEM(t, key), "", "x", "kein Zertifikat gefunden"},
		{"Müll als Schlüssel", certs, []byte("hallo"), "", "x", "kein privater Schlüssel"},
		{"Zeilenumbruch im Passwort", certs, pkcs8PEM(t, key), "", "a\nb", "ungültig"},
	}
	for _, c := range cases {
		_, err := pemToPFX(c.certs, c.key, c.keyPw, c.pfxPw, "compat")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Fehler %v, erwartet Text „%s“", c.name, err, c.want)
		}
	}
}

func TestPemToPFXWithECKey(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "ec.test"}, DNSNames: []string{"ec.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, _ := x509.MarshalECPrivateKey(k)
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})
	res, err := pemToPFX(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ecPEM, "", "pw", "compat")
	if err != nil {
		t.Fatal(err)
	}
	if c, err := openPFX(res.PFX, "pw"); err != nil || len(c.Certs) != 1 {
		t.Fatalf("EC-PFX nicht lesbar: %v", err)
	}
}

func TestParsePrivateKeyEncrypted(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl nicht vorhanden")
	}
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.key")
	openssl(t, "", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", plain)
	plainPEM, _ := os.ReadFile(plain)
	want, err := parsePrivateKeyPEM(plainPEM, "")
	if err != nil {
		t.Fatal(err)
	}

	variants := map[string][]string{
		"aes256-sha256": {"pkcs8", "-topk8", "-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA256"},
		"aes128-sha1":   {"pkcs8", "-topk8", "-v2", "aes-128-cbc", "-v2prf", "hmacWithSHA1"},
		"3des-sha256":   {"pkcs8", "-topk8", "-v2", "des3", "-v2prf", "hmacWithSHA256"},
		"aes256-sha512": {"pkcs8", "-topk8", "-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA512"},
	}
	for name, args := range variants {
		out := filepath.Join(dir, name+".key")
		a := append([]string{}, args...)
		a = append(a, "-in", plain, "-out", out, "-passout", "pass:geheim-ö")
		openssl(t, "", a...)
		b, _ := os.ReadFile(out)
		if !bytes.Contains(b, []byte("ENCRYPTED PRIVATE KEY")) {
			t.Fatalf("%s: nicht verschlüsselt", name)
		}
		got, err := parsePrivateKeyPEM(b, "geheim-ö")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !got.(*rsa.PrivateKey).Equal(want) {
			t.Fatalf("%s: falscher Schlüssel", name)
		}
		if _, err := parsePrivateKeyPEM(b, "falsch"); err == nil || !strings.Contains(err.Error(), "Passwort") {
			t.Fatalf("%s: falsches Passwort: %v", name, err)
		}
		if _, err := parsePrivateKeyPEM(b, ""); err == nil || !strings.Contains(err.Error(), "verschlüsselt") {
			t.Fatalf("%s: fehlendes Passwort: %v", name, err)
		}
	}

	// altes Format mit „Proc-Type: 4,ENCRYPTED“
	trad := filepath.Join(dir, "trad.key")
	openssl(t, "", "genrsa", "-traditional", "-aes256", "-passout", "pass:alt", "-out", trad, "2048")
	b, _ := os.ReadFile(trad)
	if !bytes.Contains(b, []byte("ENCRYPTED")) {
		t.Fatal("altes Format nicht verschlüsselt")
	}
	if _, err := parsePrivateKeyPEM(b, "alt"); err != nil {
		t.Fatalf("altes Format: %v", err)
	}
	if _, err := parsePrivateKeyPEM(b, "neu"); err == nil {
		t.Fatal("altes Format: falsches Passwort nicht erkannt")
	}
}

func TestOpensslReadsOurPFX(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl nicht vorhanden")
	}
	leaf, inter, _, key := testChain(t)
	res, err := pemToPFX(certsToPEM([]*x509.Certificate{leaf, inter}), pkcs8PEM(t, key), "", "Geheim-1", "compat")
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "x.pfx")
	if err := os.WriteFile(f, res.PFX, 0o600); err != nil {
		t.Fatal(err)
	}
	out := openssl(t, "", "pkcs12", "-in", f, "-passin", "pass:Geheim-1", "-nodes", "-legacy")
	if strings.Count(out, "BEGIN CERTIFICATE") != 2 || !strings.Contains(out, "PRIVATE KEY") {
		t.Fatalf("openssl sieht nicht alles:\n%s", out)
	}
}

func TestSaveConverted(t *testing.T) {
	leaf, inter, root, key := testChain(t)
	res, err := pemToPFX(certsToPEM([]*x509.Certificate{leaf, inter, root}), pkcs8PEM(t, key), "", "pw", "compat")
	if err != nil {
		t.Fatal(err)
	}
	c, err := openPFX(res.PFX, "pw")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "aus")
	files, err := saveConverted(c, dir, "mein", []string{"cert", "chain", "fullchain", "key"}, "crt")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, filepath.Base(f))
	}
	want := []string{"mein.crt", "mein-chain.crt", "mein-fullchain.crt", "mein.key"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("Dateien %v, erwartet %v", names, want)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "mein.key")); !bytes.Contains(b, []byte("PRIVATE KEY")) {
		t.Fatal("Schlüsseldatei leer")
	}
	if _, err := saveConverted(c, dir, "", []string{"cert"}, "crt"); err == nil {
		t.Fatal("leerer Name nicht abgelehnt")
	}
	if _, err := saveConverted(c, dir, "x", nil, "crt"); err == nil {
		t.Fatal("keine Auswahl nicht abgelehnt")
	}
	// Datei ohne Zwischenzertifikate: „chain“ wird übergangen
	one, err := pemToPFX(certsToPEM([]*x509.Certificate{root}), pkcs8PEM(t, genTestKey(t)), "", "pw", "compat")
	if err == nil || one != nil {
		t.Fatal("Schlüssel ohne Zertifikat hätte scheitern müssen")
	}
}

func TestGeneratePassword(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		p := generatePassword(16)
		if len(p) != 16 || strings.ContainsAny(p, "0O1lI") || seen[p] {
			t.Fatalf("unbrauchbares Passwort %q", p)
		}
		seen[p] = true
	}
	if len(generatePassword(2)) != 8 {
		t.Fatal("Mindestlänge fehlt")
	}
}
