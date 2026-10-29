package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// Wildcard-Zertifikate (und alle Fälle ohne Port 80): Die Bestätigung läuft über einen DNS-Eintrag,
// den der Anwender selbst bei seinem DNS-Anbieter anlegt. Das Programm zeigt den Eintrag, prüft ihn
// und holt danach das Zertifikat. Eine automatische Erneuerung gibt es dafür nicht.

// WildRequest sind die Angaben im Wildcard-Dialog.
type WildRequest struct {
	Domains   string
	Server    string // prod | staging | custom
	CustomURL string
	Email     string
	KeyBits   int
}

// DNSRecord ist ein TXT-Eintrag, den der Anwender anlegen muss. Für „*.beispiel.de“ und „beispiel.de“
// zusammen entsteht ein Name mit zwei Werten.
type DNSRecord struct {
	Name    string
	Values  []string
	Domains []string
}

// DNSCheck ist das Ergebnis der Vorabprüfung eines Eintrags.
type DNSCheck struct {
	Record  DNSRecord
	Found   []string // gefundene Werte
	Missing []string // noch fehlende Werte
	Err     error    // Abfrage nicht möglich
}

func (c DNSCheck) Complete() bool { return c.Err == nil && len(c.Missing) == 0 }

type wildChallenge struct {
	authzURI string
	ch       *acme.Challenge
	domain   string // Name ohne „*.“
	wildcard bool
	valid    bool
	name     string
	value    string
}

// WildSession hält die laufende Bestellung zwischen den Schritten des Dialogs.
type WildSession struct {
	Domains    []string
	Records    []DNSRecord
	ServerKind string
	KeyBits    int

	cl     *acme.Client
	order  *acme.Order
	chals  []*wildChallenge
	issued bool
}

// normalizeWildDomains wie normalizeDomains, erlaubt aber „*.“ vor dem Namen.
func normalizeWildDomains(input string) ([]string, error) {
	fields := strings.FieldsFunc(input, func(r rune) bool { return r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == ',' || r == ';' })
	seen := map[string]bool{}
	var out []string
	for _, f := range fields {
		d := strings.ToLower(strings.TrimSpace(f))
		d = strings.TrimSuffix(d, ".")
		if d == "" {
			continue
		}
		prefix := ""
		if strings.HasPrefix(d, "*.") {
			prefix, d = "*.", d[2:]
		}
		if strings.Contains(d, "*") {
			return nil, fmt.Errorf("„%s“: Der Stern ist nur ganz am Anfang erlaubt (*.beispiel.de).", f)
		}
		names, err := normalizeDomains(d)
		if err != nil {
			return nil, err
		}
		full := prefix + names[0]
		if !seen[full] {
			seen[full] = true
			out = append(out, full)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("Bitte mindestens eine Domain eintragen.")
	}
	if len(out) > 100 {
		return nil, fmt.Errorf("Es sind höchstens 100 Domains pro Zertifikat möglich.")
	}
	return out, nil
}

// startWild legt Konto und Bestellung an und ermittelt die nötigen DNS-Einträge.
func startWild(ctx context.Context, req WildRequest, rep Reporter) (*WildSession, error) {
	domains, err := normalizeWildDomains(req.Domains)
	if err != nil {
		return nil, uerr(err.Error(), "")
	}
	kind, dirURL, err := resolveServer(req.Server, req.CustomURL)
	if err != nil {
		return nil, uerr(err.Error(), "")
	}
	email := strings.TrimSpace(req.Email)
	if email != "" && (!emailRe.MatchString(email) || strings.ContainsAny(email, smartQuotes)) {
		return nil, uerr("Die E-Mail-Adresse sieht nicht richtig aus.", "")
	}
	bits := req.KeyBits
	if bits == 0 {
		bits = 2048
	}
	if bits != 2048 && bits != 3072 && bits != 4096 {
		return nil, uerr("Die Schlüssellänge muss 2048, 3072 oder 4096 sein.", "")
	}

	rep.Declare("konto", "Konto beim Zertifikatsanbieter")
	rep.Declare("bestellung", "Zertifikat bestellen")
	rep.Step("konto", "Konto beim Zertifikatsanbieter")
	accKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		rep.Fail("konto", err.Error())
		return nil, err
	}
	w := &WildSession{Domains: domains, ServerKind: kind, KeyBits: bits}
	w.cl = &acme.Client{Key: accKey, DirectoryURL: dirURL, UserAgent: userAgent}
	acct := &acme.Account{}
	if email != "" {
		acct.Contact = []string{"mailto:" + email}
	}
	if _, err := w.cl.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		e := explainACME(err, "", nil)
		rep.Fail("konto", e.Error())
		return nil, e
	}
	rep.Ok("konto", "bereit")

	rep.Step("bestellung", "Zertifikat bestellen")
	ids := make([]acme.AuthzID, len(domains))
	for i, d := range domains {
		ids[i] = acme.AuthzID{Type: "dns", Value: d}
	}
	w.order, err = w.cl.AuthorizeOrder(ctx, ids)
	if err != nil {
		e := explainACME(err, "", nil)
		rep.Fail("bestellung", e.Error())
		return nil, e
	}
	for _, zurl := range w.order.AuthzURLs {
		az, err := w.cl.GetAuthorization(ctx, zurl)
		if err != nil {
			e := explainACME(err, "", nil)
			rep.Fail("bestellung", e.Error())
			return nil, e
		}
		wc := &wildChallenge{authzURI: az.URI, domain: az.Identifier.Value, wildcard: az.Wildcard, valid: az.Status == acme.StatusValid}
		if !wc.valid {
			for _, c := range az.Challenges {
				if c.Type == "dns-01" {
					wc.ch = c
				}
			}
			if wc.ch == nil {
				e := uerr(fmt.Sprintf("Der Zertifikatsanbieter bietet für „%s“ keine Bestätigung per DNS-Eintrag an.", wc.domain), "")
				rep.Fail("bestellung", e.Error())
				return nil, e
			}
			wc.name = "_acme-challenge." + wc.domain
			wc.value, err = w.cl.DNS01ChallengeRecord(wc.ch.Token)
			if err != nil {
				rep.Fail("bestellung", err.Error())
				return nil, err
			}
		}
		w.chals = append(w.chals, wc)
	}
	w.Records = groupRecords(w.chals)
	rep.Ok("bestellung", fmt.Sprintf("%d Eintrag/Einträge nötig", len(w.Records)))
	return w, nil
}

func groupRecords(chals []*wildChallenge) []DNSRecord {
	byName := map[string]*DNSRecord{}
	var names []string
	for _, c := range chals {
		if c.valid {
			continue
		}
		r := byName[c.name]
		if r == nil {
			r = &DNSRecord{Name: c.name}
			byName[c.name] = r
			names = append(names, c.name)
		}
		r.Values = append(r.Values, c.value)
		label := c.domain
		if c.wildcard {
			label = "*." + c.domain
		}
		r.Domains = append(r.Domains, label)
	}
	sort.Strings(names)
	out := make([]DNSRecord, 0, len(names))
	for _, n := range names {
		sort.Strings(byName[n].Values)
		out = append(out, *byName[n])
	}
	return out
}

// ---------- DNS-Prüfung ----------

// Abfrage über DNS-over-HTTPS. So wird der Eintrag so gesehen, wie ihn auch der Zertifikatsanbieter von außen sieht,
// und nicht durch einen internen DNS-Server verfälscht. Für Tests austauschbar.
var dohEndpoints = []string{"https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"}

var dohClient = &http.Client{Timeout: 8 * time.Second}

// lookupTXT liefert die TXT-Werte eines Namens. Erst DNS-over-HTTPS, dann der Namensdienst des Rechners.
func lookupTXT(ctx context.Context, name string) ([]string, error) {
	var lastErr error
	for _, base := range dohEndpoints {
		vals, err := dohTXT(ctx, base, name)
		if err == nil {
			return vals, nil
		}
		lastErr = err
	}
	r := &net.Resolver{}
	vals, err := r.LookupTXT(ctx, name)
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return nil, nil
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, err
	}
	return vals, nil
}

func dohTXT(ctx context.Context, base, name string) ([]string, error) {
	u := base + "?type=TXT&name=" + url.QueryEscape(name)
	rq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	rq.Header.Set("Accept", "application/dns-json")
	rq.Header.Set("User-Agent", userAgent)
	res, err := dohClient.Do(rq)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	var j struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(res.Body).Decode(&j); err != nil {
		return nil, err
	}
	var out []string
	for _, a := range j.Answer {
		if a.Type != 16 {
			continue
		}
		out = append(out, unquoteTXT(a.Data))
	}
	return out, nil
}

// unquoteTXT fügt die Teile eines in Anführungszeichen geschriebenen TXT-Werts zusammen.
func unquoteTXT(d string) string {
	if !strings.Contains(d, `"`) {
		return d
	}
	var b strings.Builder
	in := false
	esc := false
	for _, r := range d {
		switch {
		case esc:
			b.WriteRune(r)
			esc = false
		case in && r == '\\':
			esc = true
		case r == '"':
			in = !in
		case in:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// CheckDNS fragt alle Einträge ab und meldet, was noch fehlt.
func (w *WildSession) CheckDNS(ctx context.Context) []DNSCheck {
	out := make([]DNSCheck, len(w.Records))
	for i, r := range w.Records {
		c := DNSCheck{Record: r}
		got, err := lookupTXT(ctx, r.Name)
		if err != nil {
			c.Err = err
			out[i] = c
			continue
		}
		have := map[string]bool{}
		for _, g := range got {
			have[strings.TrimSpace(g)] = true
		}
		for _, v := range r.Values {
			if have[v] {
				c.Found = append(c.Found, v)
			} else {
				c.Missing = append(c.Missing, v)
			}
		}
		out[i] = c
	}
	return out
}

// ---------- Bestätigen und ausstellen ----------

// Verify lässt den Zertifikatsanbieter die Einträge prüfen.
func (w *WildSession) Verify(ctx context.Context, rep Reporter) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	rep.Declare("pruefung", "Domains bestätigen")
	rep.Step("pruefung", "Domains bestätigen")
	for _, c := range w.chals {
		if c.valid {
			continue
		}
		label := c.domain
		if c.wildcard {
			label = "*." + c.domain
		}
		rep.Note("pruefung", "Prüfe "+label+" …")
		var err error
		if _, err = w.cl.Accept(ctx, c.ch); err == nil {
			_, err = w.cl.WaitAuthorization(ctx, c.authzURI)
		}
		if err != nil {
			e := explainWildAuthz(err, label)
			rep.Fail("pruefung", e.Error())
			return e
		}
		c.valid = true
		rep.Note("pruefung", label+" bestätigt")
	}
	rep.Ok("pruefung", "alle Domains bestätigt")
	return nil
}

func explainWildAuthz(err error, label string) error {
	dom := strings.TrimPrefix(label, "*.")
	var ue *userError
	if errors.As(err, &ue) {
		return err
	}
	var pe *acme.Error
	var ae *acme.AuthorizationError
	if errors.As(err, &ae) {
		for _, e := range ae.Errors {
			if errors.As(e, &pe) {
				break
			}
		}
	} else {
		errors.As(err, &pe)
	}
	if pe != nil {
		t := strings.ToLower(pe.ProblemType)
		if strings.HasSuffix(t, ":unauthorized") || strings.HasSuffix(t, ":dns") {
			return uerr(fmt.Sprintf("Der Zertifikatsanbieter hat den TXT-Eintrag „_acme-challenge.%s“ nicht (oder mit falschem Wert) gefunden. "+
				"Bitte Name und Wert genau wie angezeigt eintragen und etwas warten, bis der DNS-Anbieter den Eintrag ausliefert. "+
				"Diese Bestellung ist damit verbraucht: Bitte von vorn beginnen. Die Werte der Einträge ändern sich dabei.", dom),
				strings.TrimSpace(pe.ProblemType+"\n"+pe.Detail))
		}
	}
	return explainACME(err, dom, nil)
}

// Finish erzeugt Schlüssel und Anforderung und holt das Zertifikat.
func (w *WildSession) Finish(ctx context.Context, rep Reporter) (chainPEM, keyPEM, csrPEM []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	rep.Declare("zertifikat", "Zertifikat abholen")
	rep.Step("zertifikat", "Zertifikat abholen")
	key, err := rsa.GenerateKey(rand.Reader, w.KeyBits)
	if err != nil {
		rep.Fail("zertifikat", err.Error())
		return nil, nil, nil, err
	}
	csr, err := makeCSR(w.Domains, key)
	if err != nil {
		rep.Fail("zertifikat", err.Error())
		return nil, nil, nil, err
	}
	if _, err = w.cl.WaitOrder(ctx, w.order.URI); err != nil {
		e := explainACME(err, "", nil)
		rep.Fail("zertifikat", e.Error())
		return nil, nil, nil, e
	}
	der, _, err := w.cl.CreateCertFromOrder(ctx, w.order, csr, true)
	if err != nil {
		e := explainACME(err, "", nil)
		rep.Fail("zertifikat", e.Error())
		return nil, nil, nil, e
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		rep.Fail("zertifikat", err.Error())
		return nil, nil, nil, err
	}
	if pub, ok := leaf.PublicKey.(*rsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		e := uerr("Das ausgestellte Zertifikat passt nicht zum erzeugten Schlüssel.", "")
		rep.Fail("zertifikat", e.Error())
		return nil, nil, nil, e
	}
	for _, d := range der {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})
	csrPEM = csrToPEM(csr)
	w.issued = true
	rep.Ok("zertifikat", fmt.Sprintf("gültig bis %s", leaf.NotAfter.Local().Format("02.01.2006")))
	return chainPEM, keyPEM, csrPEM, nil
}

// ---------- Speichern ----------

// WildSave beschreibt, was mit dem fertigen Zertifikat geschehen soll.
type WildSave struct {
	TargetDir  string
	FileName   string // ohne Endung, leer = erste Domain
	Outputs    []string
	CertFormat string
	Password   string
	PfxFormat  string
}

// saveWildResult schreibt die gewünschten Dateien und liefert ihre Pfade.
func saveWildResult(domains []string, chainPEM, keyPEM, csrPEM []byte, s WildSave) ([]string, error) {
	dir, err := validatePath(s.TargetDir, osIsWindows(), "Zielordner")
	if err != nil {
		return nil, err
	}
	base := baseName(s.FileName, domains[0])
	outs, err := planOutputs(s.Outputs, s.CertFormat, base)
	if err != nil {
		return nil, err
	}
	p := &Profile{TargetDir: dir, Outputs: outs}
	d := outputData{Chain: chainPEM, Key: keyPEM, CSR: csrPEM}
	if p.hasOutput("pfx") {
		if s.Password == "" {
			return nil, fmt.Errorf("Bitte ein Passwort für die PFX-Datei vergeben.")
		}
		d.PFX, err = buildPFX(keyPEM, chainPEM, s.Password, s.PfxFormat)
		if err != nil {
			return nil, err
		}
	}
	all, _, err := syncOutputs(p, d)
	return all, err
}
