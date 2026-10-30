package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"strings"
)

// OutputSpec beschreibt eine Datei, die im Zielordner liegen soll.
type OutputSpec struct {
	Kind string `json:"kind"`          // pfx | cert | chain | fullchain | key | csr
	Name string `json:"name"`          // Dateiname mit Endung
	Enc  string `json:"enc,omitempty"` // "der" (nur bei cert), sonst PEM
}

var outputOrder = []string{"pfx", "cert", "chain", "fullchain", "key", "csr"}

var knownExts = []string{".pfx", ".p12", ".cer", ".crt", ".pem", ".key", ".csr"}

func outputLabel(kind string) string {
	switch kind {
	case "pfx":
		return "PFX-Datei"
	case "cert":
		return "Zertifikat"
	case "chain":
		return "Zwischenzertifikate"
	case "fullchain":
		return "Zertifikat mit Kette"
	case "key":
		return "Privater Schlüssel"
	case "csr":
		return "Zertifikatsanforderung"
	}
	return kind
}

// outputs liefert die gewünschten Dateien. Ältere Einrichtungen kennen nur die PFX-Datei.
func (p *Profile) outputs() []OutputSpec {
	if len(p.Outputs) > 0 {
		return p.Outputs
	}
	name := p.FileName
	if name == "" && len(p.Domains) > 0 {
		name = p.Domains[0] + ".pfx"
	}
	return []OutputSpec{{Kind: "pfx", Name: name}}
}

func (p *Profile) hasOutput(kind string) bool {
	for _, o := range p.outputs() {
		if o.Kind == kind {
			return true
		}
	}
	return false
}

// baseName macht aus Eingabe und erster Domain den Dateinamen ohne bekannte Endung.
func baseName(input, firstDomain string) string {
	b := strings.TrimSpace(input)
	if b == "" {
		b = strings.NewReplacer(":", "-").Replace(strings.Replace(firstDomain, "*.", "_.", 1))
	}
	lb := strings.ToLower(b)
	for _, e := range knownExts {
		if strings.HasSuffix(lb, e) {
			b = b[:len(b)-len(e)]
			break
		}
	}
	return b
}

// planOutputs prüft die Auswahl und legt die Dateinamen fest.
// certFormat: crt | cer | pem | cer-der (Endung bzw. Format des Zertifikats).
func planOutputs(kinds []string, certFormat, base string) ([]OutputSpec, error) {
	if len(kinds) == 0 {
		kinds = []string{"pfx"}
	}
	want := map[string]bool{}
	for _, k := range kinds {
		ok := false
		for _, o := range outputOrder {
			if o == k {
				ok = true
			}
		}
		if !ok {
			return nil, fmt.Errorf("Unbekannte Dateiart „%s“.", k)
		}
		want[k] = true
	}
	ext, enc := ".crt", ""
	switch certFormat {
	case "", "crt":
	case "cer":
		ext = ".cer"
	case "pem":
		ext = ".pem"
	case "cer-der":
		ext, enc = ".cer", "der"
	default:
		return nil, fmt.Errorf("Unbekanntes Zertifikatsformat „%s“.", certFormat)
	}
	chainExt := ext
	if enc == "der" {
		chainExt = ".pem" // Ketten gibt es nur als Text (mehrere Zertifikate in einer Datei)
	}
	var out []OutputSpec
	for _, k := range outputOrder {
		if !want[k] {
			continue
		}
		switch k {
		case "pfx":
			out = append(out, OutputSpec{Kind: k, Name: base + ".pfx"})
		case "cert":
			out = append(out, OutputSpec{Kind: k, Name: base + ext, Enc: enc})
		case "chain":
			out = append(out, OutputSpec{Kind: k, Name: base + "-chain" + chainExt})
		case "fullchain":
			out = append(out, OutputSpec{Kind: k, Name: base + "-fullchain" + chainExt})
		case "key":
			out = append(out, OutputSpec{Kind: k, Name: base + ".key"})
		case "csr":
			out = append(out, OutputSpec{Kind: k, Name: base + ".csr"})
		}
	}
	return out, nil
}

// makeCSR baut die Zertifikatsanforderung (DER) für die Domains der Einrichtung.
func makeCSR(domains []string, key crypto.Signer) ([]byte, error) {
	cn := domains[0]
	if len(cn) > 64 {
		cn = ""
	}
	dns, ips := splitNames(domains)
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: cn},
		DNSNames:    dns,
		IPAddresses: ips,
	}, key)
}

func csrToPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// outputData sind die Rohdaten, aus denen die Dateien entstehen.
type outputData struct {
	PFX   []byte // fertige PFX-Datei (nur wenn gewünscht)
	Chain []byte // Zertifikat + Zwischenzertifikate (PEM)
	Key   []byte // privater Schlüssel (PEM, PKCS#8)
	CSR   []byte // Anforderung (PEM)
}

// render erzeugt den Inhalt einer Datei. Rückgabe nil, nil: nichts zu schreiben (z. B. keine Zwischenzertifikate).
func (o OutputSpec) render(d outputData) ([]byte, error) {
	switch o.Kind {
	case "pfx":
		return d.PFX, nil
	case "fullchain":
		return d.Chain, nil
	case "key":
		return d.Key, nil
	case "csr":
		return d.CSR, nil
	}
	certs, err := parseCertsPEM(d.Chain)
	if err != nil {
		return nil, err
	}
	switch o.Kind {
	case "cert":
		if o.Enc == "der" {
			return certs[0].Raw, nil
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[0].Raw}), nil
	case "chain":
		var b []byte
		for _, c := range certs[1:] {
			b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
		}
		if len(b) == 0 {
			return nil, nil
		}
		return b, nil
	}
	return nil, fmt.Errorf("Unbekannte Dateiart „%s“.", o.Kind)
}

// syncOutputs legt alle gewünschten Dateien im Ziel ab (lokaler Ordner oder SMB-Freigabe).
// Rückgabe: Pfade aller Dateien und die Namen der Dateien, die neu geschrieben wurden.
func syncOutputs(ctx context.Context, p *Profile, d outputData) (all, written []string, err error) {
	t, err := p.openTarget(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer t.Close()
	return syncTo(t, p, d)
}

// syncTo schreibt die Dateien ins Ziel (erst unter Hilfsnamen, dann umbenennen).
func syncTo(t targetFS, p *Profile, d outputData) (all, written []string, err error) {
	if err := t.MkdirAll(); err != nil {
		hint := "Bitte Pfad und Rechte prüfen (bei Netzwerkfreigaben: Rechte des Kontos, unter dem die Aufgabe läuft)."
		if p.SMB != nil {
			hint = explainSMB(err, p.SMB)
		}
		return nil, nil, uerr(fmt.Sprintf("Der Zielordner „%s“ ist nicht erreichbar oder nicht beschreibbar. %s", p.targetLabel(), hint), err.Error())
	}
	for _, o := range p.outputs() {
		data, rerr := o.render(d)
		if rerr != nil {
			return nil, nil, rerr
		}
		if data == nil {
			continue
		}
		dest := p.targetFile(o.Name)
		all = append(all, dest)
		if old, e := t.ReadFile(o.Name); e == nil && bytes.Equal(old, data) {
			continue
		}
		tmp := o.Name + ".tmp"
		if err := t.WriteFile(tmp, data); err != nil {
			return nil, nil, uerr(fmt.Sprintf("Die Datei „%s“ konnte nicht in „%s“ geschrieben werden. %s", o.Name, p.targetLabel(), p.writeHint(err)), err.Error())
		}
		if err := t.Replace(tmp, o.Name); err != nil {
			_ = t.Remove(tmp)
			return nil, nil, uerr(fmt.Sprintf("Die Datei „%s“ konnte nicht ersetzt werden (wird sie gerade von einem Programm benutzt?).", dest), err.Error())
		}
		written = append(written, o.Name)
	}
	return all, written, nil
}
