package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func parseCertsPEM(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("keine Zertifikate gefunden")
	}
	return out, nil
}

func parseKeyPEM(b []byte) (crypto.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("kein Schlüssel gefunden")
	}
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	return x509.ParseECPrivateKey(blk.Bytes)
}

// buildPFX erzeugt die PFX-Datei. compat = 3DES (von allen Windows-Versionen lesbar), aes = AES-256.
func buildPFX(keyPEM, chainPEM []byte, password, format string) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("Das PFX-Passwort darf nicht leer sein.")
	}
	key, err := parseKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	certs, err := parseCertsPEM(chainPEM)
	if err != nil {
		return nil, err
	}
	enc := pkcs12.LegacyDES
	if format == "aes" {
		enc = pkcs12.Modern2023
	}
	data, err := enc.Encode(key, certs[0], certs[1:], password)
	if err != nil {
		return nil, err
	}
	// Gegenprobe: Datei muss sich mit dem Passwort wieder öffnen lassen.
	k2, c2, _, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, fmt.Errorf("Die erzeugte PFX-Datei lässt sich nicht wieder öffnen: %v", err)
	}
	if rk, ok := key.(*rsa.PrivateKey); ok {
		if rk2, ok := k2.(*rsa.PrivateKey); !ok || !rk.Equal(rk2) {
			return nil, fmt.Errorf("Die erzeugte PFX-Datei enthält einen abweichenden Schlüssel.")
		}
	}
	if !c2.Equal(certs[0]) {
		return nil, fmt.Errorf("Die erzeugte PFX-Datei enthält ein abweichendes Zertifikat.")
	}
	return data, nil
}

func pfxSignature(chainPEM []byte, password, format string) string {
	h := sha256.New()
	h.Write(chainPEM)
	h.Write([]byte{0})
	h.Write([]byte(password))
	h.Write([]byte{0})
	h.Write([]byte(format))
	return hex.EncodeToString(h.Sum(nil))
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
