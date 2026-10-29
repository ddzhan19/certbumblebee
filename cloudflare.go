package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Anbindung an die Cloudflare-API (v4). Gebraucht werden nur wenige Aufrufe: Zone zu einem Namen suchen,
// TXT-Eintrag anlegen und wieder löschen. Der Token braucht „Zone – Zone – Lesen“ und „Zone – DNS – Bearbeiten“.

const (
	cloudflareDefaultAPI = "https://api.cloudflare.com/client/v4"
	acmeRecordComment    = "Certbumblebee ACME"
	acmeRecordTTL        = 60
)

// Wartezeit zwischen zwei Versuchen bei Fehlern, die sich von selbst geben (Tests verkürzen sie).
var cfRetryWait = 2 * time.Second

// cloudflareAPI liefert die Adresse der API. ZA_CLOUDFLARE_API ersetzt sie (für Tests und Spiegel), erlaubt sind
// https-Adressen und Adressen auf dem eigenen Rechner.
func cloudflareAPI() string {
	v := strings.TrimRight(strings.TrimSpace(os.Getenv("ZA_CLOUDFLARE_API")), "/")
	if v == "" {
		return cloudflareDefaultAPI
	}
	u, err := url.Parse(v)
	loopback := err == nil && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost")
	if err != nil || u.Host == "" || (u.Scheme != "https" && !loopback) {
		return cloudflareDefaultAPI
	}
	return v
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfEnvelope struct {
	Success    bool            `json:"success"`
	Errors     []cfError       `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		PerPage    int `json:"per_page"`
		TotalPages int `json:"total_pages"`
		TotalCount int `json:"total_count"`
	} `json:"result_info"`
}

// cfAPIError ist eine Fehlerantwort der API.
type cfAPIError struct {
	Status int
	Errors []cfError
}

func (e *cfAPIError) Error() string {
	var parts []string
	for _, x := range e.Errors {
		parts = append(parts, fmt.Sprintf("%s (%d)", x.Message, x.Code))
	}
	if len(parts) == 0 {
		return "HTTP " + strconv.Itoa(e.Status)
	}
	return "HTTP " + strconv.Itoa(e.Status) + ": " + strings.Join(parts, "; ")
}

func (e *cfAPIError) hasCode(codes ...int) bool {
	for _, x := range e.Errors {
		for _, c := range codes {
			if x.Code == c {
				return true
			}
		}
	}
	return false
}

func (e *cfAPIError) mentions(s string) bool {
	for _, x := range e.Errors {
		if strings.Contains(strings.ToLower(x.Message), s) {
			return true
		}
	}
	return false
}

type cloudflare struct {
	token string
	base  string
	hc    *http.Client

	mu    sync.Mutex
	zones map[string]*DNSZone // Suchergebnisse je Name; nil = es gibt keine solche Zone
}

func newCloudflare(token string) *cloudflare {
	return &cloudflare{token: strings.TrimSpace(token), base: cloudflareAPI(), hc: &http.Client{Timeout: 30 * time.Second}, zones: map[string]*DNSZone{}}
}

func (c *cloudflare) Kind() string { return "cloudflare" }

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// call führt einen Aufruf aus. Bei Netzfehlern, Drosselung (429) und Serverfehlern gibt es bis zu drei weitere Versuche.
func (c *cloudflare) call(ctx context.Context, method, path string, q url.Values, body any, out any) (*cfEnvelope, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return nil, err
		}
	}
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	for attempt := 0; ; attempt++ {
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, u, rd)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := c.hc.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if attempt < 3 {
				if e := sleepCtx(ctx, cfRetryWait*time.Duration(attempt+1)); e != nil {
					return nil, e
				}
				continue
			}
			return nil, uerr("Cloudflare ist nicht erreichbar. Bitte die Internetverbindung (Port 443 nach api.cloudflare.com) prüfen.", err.Error())
		}
		b, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
		res.Body.Close()
		if (res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500) && attempt < 3 {
			wait := cfRetryWait * time.Duration(attempt+1)
			if s, e := strconv.Atoi(res.Header.Get("Retry-After")); e == nil && s > 0 && s <= 30 {
				wait = time.Duration(s) * time.Second
			}
			if e := sleepCtx(ctx, wait); e != nil {
				return nil, e
			}
			continue
		}
		var env cfEnvelope
		_ = json.Unmarshal(b, &env)
		if res.StatusCode/100 == 2 && env.Success {
			if out != nil && len(env.Result) > 0 {
				if err := json.Unmarshal(env.Result, out); err != nil {
					return nil, fmt.Errorf("Antwort von Cloudflare nicht lesbar: %v", err)
				}
			}
			return &env, nil
		}
		return &env, &cfAPIError{Status: res.StatusCode, Errors: env.Errors}
	}
}

// cfExplain macht aus einem API-Fehler eine Meldung, die sagt, was zu tun ist.
func cfExplain(err error, what string) error {
	if err == nil {
		return nil
	}
	var ue *userError
	if errors.As(err, &ue) {
		return err
	}
	var ae *cfAPIError
	if errors.As(err, &ae) {
		switch {
		case ae.Status == http.StatusUnauthorized || ae.hasCode(9109, 6111, 9106, 9103):
			return uerr("Cloudflare lehnt den Zugangstoken ab (ungültig, abgelaufen oder gelöscht). Bitte unter „DNS-Zugänge“ einen neuen Token hinterlegen.", ae.Error())
		case ae.Status == http.StatusForbidden || ae.hasCode(10000):
			return uerr("Der Cloudflare-Token hat dafür keine Berechtigung. Er braucht „Zone → Zone → Lesen“ und „Zone → DNS → Bearbeiten“ für die betroffene Zone.", ae.Error())
		case ae.Status == http.StatusTooManyRequests:
			return uerr("Cloudflare begrenzt gerade die Anfragen. Bitte in einigen Minuten erneut versuchen.", ae.Error())
		}
		msg := what + " bei Cloudflare ist fehlgeschlagen"
		if len(ae.Errors) > 0 {
			msg += ": " + ae.Errors[0].Message
		}
		return uerr(msg+".", ae.Error())
	}
	return uerr(what+" bei Cloudflare ist fehlgeschlagen.", err.Error())
}

type cfZone struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	NameServers []string `json:"name_servers"`
}

func (z cfZone) toZone() DNSZone {
	return DNSZone{ID: z.ID, Name: strings.ToLower(z.Name), NameServers: z.NameServers}
}

// Zones listet Zonen, die der Token sehen darf (erste Seite), und nennt die Gesamtzahl. Dient dem Test des Tokens.
func (c *cloudflare) Zones(ctx context.Context) ([]DNSZone, int, error) {
	var zs []cfZone
	env, err := c.call(ctx, http.MethodGet, "/zones", url.Values{"per_page": {"50"}, "page": {"1"}}, nil, &zs)
	if err != nil {
		return nil, 0, cfExplain(err, "Das Abfragen der Zonen")
	}
	out := make([]DNSZone, 0, len(zs))
	for _, z := range zs {
		out = append(out, z.toZone())
	}
	total := env.ResultInfo.TotalCount
	if total < len(out) {
		total = len(out)
	}
	return out, total, nil
}

func (c *cloudflare) zoneByName(ctx context.Context, name string) (*DNSZone, error) {
	c.mu.Lock()
	z, ok := c.zones[name]
	c.mu.Unlock()
	if ok {
		return z, nil
	}
	var zs []cfZone
	if _, err := c.call(ctx, http.MethodGet, "/zones", url.Values{"name": {name}, "per_page": {"5"}}, nil, &zs); err != nil {
		return nil, cfExplain(err, "Das Suchen der Zone „"+name+"“")
	}
	var found *DNSZone
	for _, x := range zs {
		if strings.EqualFold(x.Name, name) {
			zz := x.toZone()
			found = &zz
			break
		}
	}
	c.mu.Lock()
	c.zones[name] = found
	c.mu.Unlock()
	return found, nil
}

// FindZone sucht die Zone, in der ein Name liegt: erst die genaueste (Unterzone), dann immer weniger Teile.
// nil, nil heißt: Dieser Zugang kennt keine passende Zone.
func (c *cloudflare) FindZone(ctx context.Context, fqdn string) (*DNSZone, error) {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), "."), ".")
	for i := 0; i+1 < len(labels); i++ {
		z, err := c.zoneByName(ctx, strings.Join(labels[i:], "."))
		if err != nil {
			return nil, err
		}
		if z != nil {
			return z, nil
		}
	}
	return nil, nil
}

type cfRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Comment string `json:"comment"`
}

func (c *cloudflare) findTXT(ctx context.Context, zone DNSZone, name, value string) ([]cfRecord, error) {
	q := url.Values{"type": {"TXT"}, "name": {name}, "per_page": {"100"}}
	if value != "" {
		q.Set("content", value)
	}
	var rs []cfRecord
	if _, err := c.call(ctx, http.MethodGet, "/zones/"+zone.ID+"/dns_records", q, nil, &rs); err != nil {
		return nil, cfExplain(err, "Das Abfragen der DNS-Einträge")
	}
	return rs, nil
}

// AddTXT legt einen TXT-Eintrag an und liefert dessen Kennung. Gibt es genau diesen Eintrag schon, wird er verwendet.
func (c *cloudflare) AddTXT(ctx context.Context, zone DNSZone, name, value string) (string, error) {
	body := map[string]any{"type": "TXT", "name": name, "content": value, "ttl": acmeRecordTTL, "comment": acmeRecordComment}
	var rec cfRecord
	_, err := c.call(ctx, http.MethodPost, "/zones/"+zone.ID+"/dns_records", nil, body, &rec)
	if err == nil {
		return rec.ID, nil
	}
	var ae *cfAPIError
	if errors.As(err, &ae) {
		if ae.hasCode(81057, 81058) || ae.mentions("already exists") && !ae.mentions("cname") {
			if rs, e := c.findTXT(ctx, zone, name, value); e == nil && len(rs) > 0 {
				return rs[0].ID, nil
			}
		}
		if ae.hasCode(81053, 81054) || ae.mentions("cname") {
			return "", uerr(fmt.Sprintf("Bei Cloudflare gibt es für „%s“ schon einen CNAME-Eintrag. Neben einem CNAME ist kein TXT-Eintrag möglich. "+
				"Bitte den CNAME entfernen oder die Domain mit einem anderen Verfahren bestätigen.", name), ae.Error())
		}
	}
	return "", cfExplain(err, "Das Anlegen des DNS-Eintrags „"+name+"“")
}

// DeleteRecord löscht einen Eintrag. Ist er schon weg, ist das in Ordnung.
func (c *cloudflare) DeleteRecord(ctx context.Context, zone DNSZone, id string) error {
	_, err := c.call(ctx, http.MethodDelete, "/zones/"+zone.ID+"/dns_records/"+url.PathEscape(id), nil, nil, nil)
	var ae *cfAPIError
	if errors.As(err, &ae) && (ae.Status == http.StatusNotFound || ae.hasCode(81044)) {
		return nil
	}
	return cfExplain(err, "Das Löschen des DNS-Eintrags")
}

// CleanStale entfernt TXT-Einträge mit genau diesem Namen, die dieses Programm früher angelegt und nicht mehr
// gelöscht hat (z. B. nach einem Absturz). Fremde Einträge bleiben unberührt: Erkannt wird nur am Kommentar.
func (c *cloudflare) CleanStale(ctx context.Context, zone DNSZone, name string) (int, error) {
	rs, err := c.findTXT(ctx, zone, name, "")
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range rs {
		if r.Comment != acmeRecordComment {
			continue
		}
		if err := c.DeleteRecord(ctx, zone, r.ID); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
