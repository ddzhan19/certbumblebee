//go:build !windows

package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnixProtect(t *testing.T) {
	t.Setenv("ZA_DATA", t.TempDir())
	t.Setenv("ZA_SECRET_KEY", "")
	t.Setenv("ZA_SECRET_KEY_FILE", "")
	secret := []byte("cf-token-geheim-0123456789")

	enc, err := plat.Protect(secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc, secret) || !strings.HasPrefix(string(enc), protectMagic) {
		t.Fatal("Daten sind nicht verschlüsselt")
	}
	dec, err := plat.Unprotect(enc)
	if err != nil || !bytes.Equal(dec, secret) {
		t.Fatalf("Entschlüsseln: %q %v", dec, err)
	}
	// zweimal verschlüsselt ergibt verschiedene Daten (zufälliger Nonce)
	enc2, _ := plat.Protect(secret)
	if bytes.Equal(enc, enc2) {
		t.Error("gleicher Nonce")
	}
	// Schlüsseldatei: nur für den Besitzer lesbar
	fi, err := os.Stat(filepath.Join(dataDir(), "secret.key"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("Schlüsseldatei: %v %v", fi, err)
	}
	// Manipulierte Daten werden erkannt
	bad := append([]byte(nil), enc...)
	bad[len(bad)-1] ^= 1
	if _, err := plat.Unprotect(bad); err == nil {
		t.Error("Manipulation unbemerkt")
	}
	if _, err := plat.Unprotect([]byte("FAKE1:x")); err == nil {
		t.Error("fremdes Format akzeptiert")
	}
	if _, err := plat.Unprotect(nil); err == nil {
		t.Error("leere Daten akzeptiert")
	}

	// Anderer Schlüssel: nicht lesbar, mit klarer Meldung beim DNS-Zugang
	t.Setenv("ZA_SECRET_KEY", "ein-ganz-anderer-schluessel-0123456789")
	if _, err := plat.Unprotect(enc); err == nil {
		t.Fatal("mit fremdem Schlüssel lesbar")
	}
	acc := DNSAccount{ID: "cf-x", Name: "Alt", Provider: "cloudflare"}
	t.Setenv("ZA_SECRET_KEY", "")
	e1, _ := plat.Protect([]byte("token-token-token-token-1234"))
	acc.Token = base64.StdEncoding.EncodeToString(e1)
	t.Setenv("ZA_SECRET_KEY", "neuer-schluessel-neuer-schluessel-1")
	if _, err := dnsAccountToken(acc); err == nil || !strings.Contains(err.Error(), "ZA_SECRET_KEY") {
		t.Errorf("Meldung bei falschem Schlüssel: %v", err)
	}

	// Schlüssel aus Datei und aus Variable gleichen Werts ergeben denselben Schlüssel
	t.Setenv("ZA_SECRET_KEY", "")
	kf := filepath.Join(t.TempDir(), "key")
	_ = os.WriteFile(kf, []byte("gemeinsamer-schluessel-wert-0000\n"), 0o600)
	t.Setenv("ZA_SECRET_KEY_FILE", kf)
	a, err := plat.Protect(secret)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ZA_SECRET_KEY_FILE", "")
	t.Setenv("ZA_SECRET_KEY", "gemeinsamer-schluessel-wert-0000")
	if d, err := plat.Unprotect(a); err != nil || !bytes.Equal(d, secret) {
		t.Errorf("Datei und Variable sollten denselben Schlüssel ergeben: %v", err)
	}
	t.Setenv("ZA_SECRET_KEY", "")
	t.Setenv("ZA_SECRET_KEY_FILE", filepath.Join(t.TempDir(), "fehlt"))
	if _, err := plat.Protect(secret); err == nil {
		t.Error("fehlende Schlüsseldatei hätte scheitern müssen")
	}
}
