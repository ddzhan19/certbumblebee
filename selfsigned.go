package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

const (
	selfSignedDefaultDays = 365
	selfSignedMinDays     = 30
	selfSignedMaxDays     = 3650
)

var hostLabelRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

// normalizeNames prüft die Namen für ein selbstsigniertes Zertifikat. Anders als bei Let’s Encrypt sind
// Hostnamen ohne Endung (z. B. „intranet“), Wildcards (*.firma.local) und IP-Adressen erlaubt.
func normalizeNames(input string) ([]string, error) {
	fields := strings.FieldsFunc(input, func(r rune) bool { return r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == ',' || r == ';' })
	seen := map[string]bool{}
	var out []string
	for _, f := range fields {
		d := strings.ToLower(strings.TrimSpace(f))
		if d == "" {
			continue
		}
		if ip := net.ParseIP(strings.Trim(d, "[]")); ip != nil {
			d = ip.String()
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
			continue
		}
		d = strings.TrimSuffix(d, ".")
		if strings.Contains(d, "://") || strings.ContainsAny(d, "/:@ ") {
			return nil, fmt.Errorf("„%s“ ist kein Name. Bitte nur den Namen ohne http:// oder Pfad eintragen.", d)
		}
		wild := strings.HasPrefix(d, "*.")
		host := strings.TrimPrefix(d, "*.")
		a := host
		if !isASCII(host) { // Umlaut-Domains in Punycode umwandeln (die strenge Prüfung lässt „_“ nicht zu, deshalb nur dann)
			var err error
			if a, err = idna.Lookup.ToASCII(host); err != nil {
				return nil, fmt.Errorf("„%s“ ist kein gültiger Name.", d)
			}
		}
		if a == "" || len(a) > 253 {
			return nil, fmt.Errorf("„%s“ ist kein gültiger Name.", d)
		}
		for _, l := range strings.Split(a, ".") {
			if !hostLabelRe.MatchString(l) {
				return nil, fmt.Errorf("„%s“ ist kein gültiger Name.", d)
			}
		}
		if wild {
			a = "*." + a
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("Bitte mindestens einen Namen oder eine IP-Adresse eintragen.")
	}
	if len(out) > 100 {
		return nil, fmt.Errorf("Es sind höchstens 100 Namen pro Zertifikat möglich.")
	}
	return out, nil
}

// splitNames trennt die Einträge in DNS-Namen und IP-Adressen (für Zertifikat und Anforderung).
func splitNames(names []string) (dns []string, ips []net.IP) {
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, n)
		}
	}
	return
}

// certNames liefert alle Namen eines Zertifikats (DNS und IP) in derselben Schreibweise wie die Einrichtung.
func certNames(c *x509.Certificate) []string {
	out := append([]string(nil), c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func declareSelfSignedSteps(rep Reporter, p *Profile) {
	rep.Declare("zertifikat", "Zertifikat erzeugen und selbst signieren")
	if p.hasOutput("pfx") {
		rep.Declare("pfx", "PFX-Datei erzeugen")
	}
	rep.Declare("ziel", "In den Zielordner speichern")
}

// issueSelfSigned erzeugt Schlüssel und ein selbstsigniertes Zertifikat. Rückgabe wie bei issueCertificate.
func issueSelfSigned(_ context.Context, p *Profile, rep Reporter) (chainPEM, keyPEM, csrPEM []byte, err error) {
	rep.Step("zertifikat", "Zertifikat erzeugen und selbst signieren")
	fail := func(e error) ([]byte, []byte, []byte, error) {
		rep.Fail("zertifikat", e.Error())
		return nil, nil, nil, e
	}
	key, err := rsa.GenerateKey(rand.Reader, p.KeyBits)
	if err != nil {
		return fail(err)
	}
	days := p.ValidDays
	if days == 0 {
		days = selfSignedDefaultDays
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return fail(err)
	}
	serial.Add(serial, big.NewInt(1))
	dns, ips := splitNames(p.Domains)
	cn := p.Domains[0]
	if len(cn) > 64 {
		cn = ""
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fail(err)
	}
	ski := sha1.Sum(pubDER)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-10 * time.Minute),
		NotAfter:              now.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          ski[:],
		DNSNames:              dns,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fail(err)
	}
	var signer crypto.Signer = key
	csr, err := makeCSR(p.Domains, signer)
	if err != nil {
		return fail(err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fail(err)
	}
	chainPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})
	csrPEM = csrToPEM(csr)
	rep.Ok("zertifikat", fmt.Sprintf("selbst signiert, gültig bis %s", tmpl.NotAfter.Local().Format("02.01.2006")))
	return chainPEM, keyPEM, csrPEM, nil
}
