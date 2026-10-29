package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// Bestätigung per DNS-Eintrag (dns-01). Das Programm legt die TXT-Einträge über die API des DNS-Anbieters selbst an,
// wartet, bis sie ausgeliefert werden, lässt sie vom Zertifikatsanbieter prüfen und löscht sie wieder. Damit gehen
// auch Wildcards, und die Erneuerung läuft ohne Zutun.

// DNSRecord ist ein TXT-Eintrag. Für „*.beispiel.de“ und „beispiel.de“ zusammen entsteht ein Name mit zwei Werten.
type DNSRecord struct {
	Name    string
	Values  []string
	Domains []string
}

type dnsChallenge struct {
	authzURI string
	ch       *acme.Challenge
	domain   string // Name ohne „*.“
	wildcard bool
	valid    bool
	name     string
	value    string
}

func (c *dnsChallenge) label() string {
	if c.wildcard {
		return "*." + c.domain
	}
	return c.domain
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

// groupRecords fasst die Bestätigungen zu Einträgen zusammen: ein Name, mehrere Werte.
func groupRecords(chals []*dnsChallenge) []DNSRecord {
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
		r.Domains = append(r.Domains, c.label())
	}
	sort.Strings(names)
	out := make([]DNSRecord, 0, len(names))
	for _, n := range names {
		sort.Strings(byName[n].Values)
		out = append(out, *byName[n])
	}
	return out
}

// dnsOrder ist eine Bestellung, die per DNS bestätigt wird.
type dnsOrder struct {
	cl      *acme.Client
	order   *acme.Order
	chals   []*dnsChallenge
	Records []DNSRecord
}

// newDNSOrder bestellt und ermittelt die nötigen Einträge (Schritt „bestellung“).
func newDNSOrder(ctx context.Context, cl *acme.Client, domains []string, p *Profile, rep Reporter) (*dnsOrder, error) {
	rep.Step("bestellung", "Zertifikat bestellen")
	ids := make([]acme.AuthzID, len(domains))
	for i, d := range domains {
		ids[i] = acme.AuthzID{Type: "dns", Value: d}
	}
	o := &dnsOrder{cl: cl}
	var err error
	if o.order, err = cl.AuthorizeOrder(ctx, ids); err != nil {
		e := explainACME(err, "", p)
		rep.Fail("bestellung", e.Error())
		return nil, e
	}
	for _, zurl := range o.order.AuthzURLs {
		az, err := cl.GetAuthorization(ctx, zurl)
		if err != nil {
			e := explainACME(err, "", p)
			rep.Fail("bestellung", e.Error())
			return nil, e
		}
		c := &dnsChallenge{authzURI: az.URI, domain: az.Identifier.Value, wildcard: az.Wildcard, valid: az.Status == acme.StatusValid}
		if !c.valid {
			for _, ch := range az.Challenges {
				if ch.Type == "dns-01" {
					c.ch = ch
				}
			}
			if c.ch == nil {
				e := uerr(fmt.Sprintf("Der Zertifikatsanbieter bietet für „%s“ keine Bestätigung per DNS-Eintrag an.", c.domain), "")
				rep.Fail("bestellung", e.Error())
				return nil, e
			}
			c.name = "_acme-challenge." + c.domain
			if c.value, err = cl.DNS01ChallengeRecord(c.ch.Token); err != nil {
				rep.Fail("bestellung", err.Error())
				return nil, err
			}
		}
		o.chals = append(o.chals, c)
	}
	o.Records = groupRecords(o.chals)
	rep.Ok("bestellung", fmt.Sprintf("%d Domain(s)", len(domains)))
	return o, nil
}

// verify lässt den Zertifikatsanbieter die Einträge prüfen (Schritt „pruefung“).
func (o *dnsOrder) verify(ctx context.Context, p *Profile, rep Reporter) error {
	rep.Step("pruefung", "Domains bestätigen")
	for _, c := range o.chals {
		if c.valid {
			continue
		}
		rep.Note("pruefung", "Prüfe "+c.label()+" …")
		var err error
		if _, err = o.cl.Accept(ctx, c.ch); err == nil {
			_, err = o.cl.WaitAuthorization(ctx, c.authzURI)
		}
		if err != nil {
			e := explainDNSAuthz(err, c.label(), p)
			rep.Fail("pruefung", e.Error())
			return e
		}
		c.valid = true
		rep.Note("pruefung", c.label()+" bestätigt")
	}
	rep.Ok("pruefung", "alle Domains bestätigt")
	return nil
}

func explainDNSAuthz(err error, label string, p *Profile) error {
	dom := strings.TrimPrefix(label, "*.")
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
			return uerr(fmt.Sprintf("Der Zertifikatsanbieter hat den TXT-Eintrag „_acme-challenge.%s“ nicht (oder mit falschem Wert) gefunden, obwohl er angelegt war. "+
				"Mögliche Ursachen: Die Domain ist bei Cloudflare nicht aktiv (Nameserver stehen noch beim alten Anbieter), oder es gibt eine Delegation (NS/CNAME) für „_acme-challenge“.", dom),
				strings.TrimSpace(pe.ProblemType+"\n"+pe.Detail))
		}
	}
	return explainACME(err, dom, p)
}

// issueDNS stellt ein Zertifikat aus, dessen Domains per DNS-Eintrag bestätigt werden (auch Wildcards).
func issueDNS(ctx context.Context, p *Profile, rep Reporter) (chainPEM, keyPEM, csrPEM []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	cl, err := acmeConnect(ctx, p, rep)
	if err != nil {
		return nil, nil, nil, err
	}
	order, err := newDNSOrder(ctx, cl, p.Domains, p, rep)
	if err != nil {
		return nil, nil, nil, err
	}

	var pl *dnsPlacement
	if len(order.Records) > 0 {
		rep.Step("dns", "DNS-Einträge bei Cloudflare anlegen")
		router, rerr := newDNSRouter(p.DNSAccount)
		if rerr != nil {
			rep.Fail("dns", rerr.Error())
			return nil, nil, nil, rerr
		}
		if pl, err = placeRecords(ctx, router, order.Records, rep); err != nil {
			rep.Fail("dns", err.Error())
			return nil, nil, nil, err
		}
		// Was auch passiert: Die Einträge sollen nicht liegen bleiben.
		defer func() {
			if n, failed := pl.cleanup(context.Background(), rep); n > 0 || len(failed) > 0 {
				appLog(p.ID, "INFO", fmt.Sprintf("DNS-Einträge aufgeräumt: %d entfernt, %d fehlgeschlagen", n, len(failed)))
			}
		}()
		rep.Ok("dns", fmt.Sprintf("%d Eintrag/Einträge angelegt", len(order.Records)))

		rep.Step("dnswarten", "Warten, bis die Einträge ausgeliefert werden")
		if err = pl.waitVisible(ctx, rep); err != nil {
			rep.Fail("dnswarten", err.Error())
			return nil, nil, nil, err
		}
		rep.Ok("dnswarten", "sichtbar")
	} else {
		rep.Ok("dns", "nicht nötig")
		rep.Ok("dnswarten", "nicht nötig")
	}

	if err = order.verify(ctx, p, rep); err != nil {
		return nil, nil, nil, err
	}

	rep.Step("aufraeumen", "DNS-Einträge wieder entfernen")
	if pl != nil {
		n, failed := pl.cleanup(ctx, rep)
		if len(failed) > 0 {
			rep.Ok("aufraeumen", fmt.Sprintf("%d entfernt, %d nicht (siehe Protokoll)", n, len(failed)))
		} else {
			rep.Ok("aufraeumen", fmt.Sprintf("%d entfernt", n))
		}
	} else {
		rep.Ok("aufraeumen", "nichts zu entfernen")
	}

	return acmeFinalize(ctx, cl, order.order, p, rep)
}
