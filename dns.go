package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// DNSZone ist eine Zone beim DNS-Anbieter, z. B. „beispiel.de“.
type DNSZone struct {
	ID          string
	Name        string
	NameServers []string
}

// DNSProvider setzt und entfernt die TXT-Einträge für die Bestätigung. Bisher gibt es Cloudflare.
type DNSProvider interface {
	Kind() string
	Zones(ctx context.Context) ([]DNSZone, int, error)
	FindZone(ctx context.Context, fqdn string) (*DNSZone, error)
	AddTXT(ctx context.Context, zone DNSZone, name, value string) (string, error)
	DeleteRecord(ctx context.Context, zone DNSZone, id string) error
	CleanStale(ctx context.Context, zone DNSZone, name string) (int, error)
}

// ---------- DNS-Zugänge (Tokens) ----------

// DNSAccount ist ein hinterlegter Zugang zu einem DNS-Anbieter. Der Token liegt nur geschützt auf der Platte
// (Windows: DPAPI, Linux/Container: AES-256-GCM).
type DNSAccount struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Provider string    `json:"provider"`
	Created  time.Time `json:"created"`
	Token    string    `json:"token,omitempty"`
	FromEnv  bool      `json:"-"`
}

const envAccountID = "umgebung"

var (
	dnsMu      sync.Mutex
	tokenRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{20,200}$`)
	accNameBad = regexp.MustCompile("[\\x00-\\x1f<>\"']")
)

func dnsAccountsPath() string { return filepath.Join(dataDir(), "dns-accounts.json") }

func loadStoredAccounts() ([]DNSAccount, error) {
	b, err := os.ReadFile(dnsAccountsPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var accts []DNSAccount
	if err := json.Unmarshal(b, &accts); err != nil {
		return nil, fmt.Errorf("Die Datei mit den DNS-Zugängen ist beschädigt: %v", err)
	}
	return accts, nil
}

// envToken liest den Token aus ZA_CLOUDFLARE_TOKEN oder (für Docker-Secrets) aus der Datei ZA_CLOUDFLARE_TOKEN_FILE.
func envToken() string {
	if v := strings.TrimSpace(os.Getenv("ZA_CLOUDFLARE_TOKEN")); v != "" {
		return v
	}
	if f := strings.TrimSpace(os.Getenv("ZA_CLOUDFLARE_TOKEN_FILE")); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

// listDNSAccounts liefert alle Zugänge; ein Zugang aus der Umgebung steht zuerst.
func listDNSAccounts() []DNSAccount {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	return listDNSAccountsLocked()
}

func listDNSAccountsLocked() []DNSAccount {
	stored, _ := loadStoredAccounts()
	var out []DNSAccount
	if envToken() != "" {
		out = append(out, DNSAccount{ID: envAccountID, Name: "Aus der Umgebung (ZA_CLOUDFLARE_TOKEN)", Provider: "cloudflare", FromEnv: true})
	}
	sort.SliceStable(stored, func(i, j int) bool { return stored[i].Created.Before(stored[j].Created) })
	return append(out, stored...)
}

func getDNSAccount(id string) (DNSAccount, bool) {
	for _, a := range listDNSAccounts() {
		if a.ID == id {
			return a, true
		}
	}
	return DNSAccount{}, false
}

func dnsAccountToken(a DNSAccount) (string, error) {
	if a.FromEnv {
		return envToken(), nil
	}
	raw, err := base64.StdEncoding.DecodeString(a.Token)
	if err != nil {
		return "", fmt.Errorf("Der gespeicherte Token von „%s“ ist beschädigt.", a.Name)
	}
	pt, err := plat.Unprotect(raw)
	if err != nil {
		return "", uerr(fmt.Sprintf("Der gespeicherte Token von „%s“ lässt sich nicht entschlüsseln. Er ist nur mit dem Schlüssel lesbar, mit dem er gespeichert wurde (Container: ZA_SECRET_KEY bzw. die Schlüsseldatei im Datenordner). Bitte den Token neu hinterlegen.", a.Name), err.Error())
	}
	return string(pt), nil
}

func validateToken(t string) (string, error) {
	t = strings.TrimSpace(t)
	if t == "" {
		return "", fmt.Errorf("Bitte den API-Token eintragen.")
	}
	if !tokenRe.MatchString(t) {
		return "", fmt.Errorf("Der Token sieht nicht richtig aus. Cloudflare-API-Token bestehen aus Buchstaben, Ziffern, „-“ und „_“ (meist 40 Zeichen). Ein „Global API Key“ wird nicht unterstützt, bitte einen API-Token anlegen.")
	}
	return t, nil
}

func providerFor(a DNSAccount) (DNSProvider, error) {
	if a.Provider != "cloudflare" {
		return nil, fmt.Errorf("Der DNS-Anbieter „%s“ wird nicht unterstützt.", a.Provider)
	}
	tok, err := dnsAccountToken(a)
	if err != nil {
		return nil, err
	}
	return newCloudflare(tok), nil
}

// addDNSAccount legt einen Zugang an. Der Token wird vorher gegen Cloudflare geprüft.
func addDNSAccount(ctx context.Context, name, token string) (DNSAccount, []DNSZone, int, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return DNSAccount{}, nil, 0, fmt.Errorf("Bitte dem Zugang einen Namen geben, z. B. „Cloudflare Firma“.")
	}
	if len([]rune(name)) > 60 || accNameBad.MatchString(name) {
		return DNSAccount{}, nil, 0, fmt.Errorf("Der Name ist ungültig (höchstens 60 Zeichen, keine Anführungszeichen oder Sonderzeichen wie < >).")
	}
	token, err := validateToken(token)
	if err != nil {
		return DNSAccount{}, nil, 0, err
	}
	zones, total, err := newCloudflare(token).Zones(ctx)
	if err != nil {
		return DNSAccount{}, nil, 0, err
	}
	if len(zones) == 0 {
		return DNSAccount{}, nil, 0, uerr("Der Token ist gültig, sieht aber keine einzige Zone. Beim Anlegen des Tokens muss unter „Zonenressourcen“ die Zone (oder „Alle Zonen“) gewählt sein.", "")
	}
	enc, err := plat.Protect([]byte(token))
	if err != nil {
		return DNSAccount{}, nil, 0, fmt.Errorf("Der Token konnte nicht geschützt gespeichert werden: %v", err)
	}
	dnsMu.Lock()
	defer dnsMu.Unlock()
	stored, err := loadStoredAccounts()
	if err != nil {
		return DNSAccount{}, nil, 0, err
	}
	for _, a := range stored {
		if strings.EqualFold(a.Name, name) {
			return DNSAccount{}, nil, 0, fmt.Errorf("Es gibt schon einen Zugang mit dem Namen „%s“.", name)
		}
	}
	if err := os.MkdirAll(dataDir(), 0o755); err != nil {
		return DNSAccount{}, nil, 0, err
	}
	_ = plat.SecureDir(dataDir(), "")
	acc := DNSAccount{ID: "cf-" + randomHex(4), Name: name, Provider: "cloudflare", Created: time.Now().Truncate(time.Second), Token: base64.StdEncoding.EncodeToString(enc)}
	stored = append(stored, acc)
	if err := writeJSON(dnsAccountsPath(), stored); err != nil {
		return DNSAccount{}, nil, 0, err
	}
	acc.Token = ""
	return acc, zones, total, nil
}

// removeDNSAccount löscht einen Zugang, sofern kein Zertifikat ihn ausdrücklich benutzt.
func removeDNSAccount(id string) error {
	if id == envAccountID {
		return fmt.Errorf("Dieser Zugang kommt aus der Umgebungsvariable ZA_CLOUDFLARE_TOKEN und lässt sich nur dort ändern.")
	}
	if users := profilesUsingAccount(id); len(users) > 0 {
		return fmt.Errorf("Der Zugang wird noch von diesen Zertifikaten benutzt: %s. Bitte erst dort einen anderen wählen oder die Zertifikate entfernen.", strings.Join(users, ", "))
	}
	// Zertifikate im Automatik-Modus suchen ihre Zone in allen Zugängen. Der letzte Zugang darf deshalb nicht weg.
	if auto := profilesOnAutoDNS(); len(auto) > 0 {
		others := 0
		for _, a := range listDNSAccounts() {
			if a.ID != id {
				others++
			}
		}
		if others == 0 {
			return fmt.Errorf("Das ist der letzte Zugang, und diese Zertifikate suchen ihre Zone automatisch darin: %s. Bitte erst die Zertifikate entfernen oder einen anderen Zugang hinterlegen.", strings.Join(auto, ", "))
		}
	}
	dnsMu.Lock()
	defer dnsMu.Unlock()
	stored, err := loadStoredAccounts()
	if err != nil {
		return err
	}
	var keep []DNSAccount
	found := false
	for _, a := range stored {
		if a.ID == id {
			found = true
			continue
		}
		keep = append(keep, a)
	}
	if !found {
		return fmt.Errorf("Diesen Zugang gibt es nicht.")
	}
	if keep == nil {
		keep = []DNSAccount{}
	}
	return writeJSON(dnsAccountsPath(), keep)
}

// profilesOnAutoDNS liefert die Zertifikate mit Methode „dns“, die keinen bestimmten Zugang gewählt haben.
func profilesOnAutoDNS() []string {
	var out []string
	for _, pid := range listProfileIDs() {
		if p, err := loadProfile(pid); err == nil && p.Method == "dns" && p.DNSAccount == "" {
			out = append(out, pid)
		}
	}
	return out
}

func profilesUsingAccount(id string) []string {
	var out []string
	for _, pid := range listProfileIDs() {
		if p, err := loadProfile(pid); err == nil && p.Method == "dns" && p.DNSAccount == id {
			out = append(out, pid)
		}
	}
	return out
}

// ---------- Zone zu einem Namen finden ----------

type dnsAcct struct {
	acc  DNSAccount
	prov DNSProvider
}

type dnsLoc struct {
	acct *dnsAcct
	zone DNSZone
}

// dnsRouter findet für jeden Namen den Zugang und die Zone, in der der Eintrag angelegt werden muss.
type dnsRouter struct {
	accts []*dnsAcct
	cache map[string]*dnsLoc
}

// newDNSRouter nimmt entweder den gewählten Zugang oder (leer) alle und sucht je Zone den passenden.
func newDNSRouter(accountID string) (*dnsRouter, error) {
	all := listDNSAccounts()
	var use []DNSAccount
	for _, a := range all {
		if accountID == "" || a.ID == accountID {
			use = append(use, a)
		}
	}
	if accountID != "" && len(use) == 0 {
		return nil, uerr("Der gewählte DNS-Zugang existiert nicht mehr. Bitte unter „DNS-Zugänge“ prüfen oder beim Zertifikat einen anderen wählen.", "")
	}
	if len(use) == 0 {
		return nil, uerr("Es ist noch kein DNS-Zugang hinterlegt. Bitte unter „DNS-Zugänge“ einen Cloudflare-Token eintragen.", "")
	}
	r := &dnsRouter{cache: map[string]*dnsLoc{}}
	for _, a := range use {
		prov, err := providerFor(a)
		if err != nil {
			return nil, err
		}
		r.accts = append(r.accts, &dnsAcct{acc: a, prov: prov})
	}
	return r, nil
}

func (r *dnsRouter) locate(ctx context.Context, fqdn string) (*dnsLoc, error) {
	if loc, ok := r.cache[fqdn]; ok {
		return loc, nil
	}
	var problems []string
	for _, a := range r.accts {
		z, err := a.prov.FindZone(ctx, fqdn)
		if err != nil {
			problems = append(problems, fmt.Sprintf("Zugang „%s“: %s", a.acc.Name, err.Error()))
			continue
		}
		if z != nil {
			loc := &dnsLoc{acct: a, zone: *z}
			r.cache[fqdn] = loc
			return loc, nil
		}
	}
	dom := strings.TrimPrefix(fqdn, "_acme-challenge.")
	if len(problems) == len(r.accts) {
		return nil, uerr(fmt.Sprintf("Für „%s“ ließ sich die Zone bei Cloudflare nicht ermitteln. %s", dom, strings.Join(problems, " ")), "")
	}
	msg := fmt.Sprintf("Für „%s“ gibt es bei den hinterlegten Cloudflare-Zugängen keine passende Zone. "+
		"Die Domain muss bei Cloudflare als Zone angelegt sein (Nameserver bei der Registrierungsstelle auf Cloudflare umgestellt), und der Token muss diese Zone sehen dürfen.", dom)
	if len(problems) > 0 {
		msg += " " + strings.Join(problems, " ")
	}
	return nil, uerr(msg, "")
}

// ---------- Einträge setzen, abwarten, aufräumen ----------

// Abfrage der zuständigen DNS-Server, für Tests austauschbar.
var authTXT = queryAuthTXT

// Takt und Höchstdauer beim Warten darauf, dass die Einträge bei den DNS-Servern des Anbieters stehen.
var (
	dnsPollEvery    = 3 * time.Second
	dnsPollMax      = 2 * time.Minute
	dnsFallbackWait = 20 * time.Second
)

// queryAuthTXT fragt die zuständigen Nameserver direkt (nicht den Resolver des Rechners, der Antworten zwischenspeichert).
func queryAuthTXT(ctx context.Context, nameservers []string, name string) ([]string, error) {
	if len(nameservers) == 0 {
		return nil, fmt.Errorf("keine Nameserver bekannt")
	}
	var vals []string
	var lastErr error
	answered := false
	for _, ns := range nameservers {
		ns := ns
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 4 * time.Second}
			return d.DialContext(ctx, network, net.JoinHostPort(ns, "53"))
		}}
		qctx, cancel := context.WithTimeout(ctx, 6*time.Second)
		v, err := r.LookupTXT(qctx, name+".")
		cancel()
		if err != nil {
			var de *net.DNSError
			if errors.As(err, &de) && de.IsNotFound {
				answered = true
				continue
			}
			lastErr = err
			continue
		}
		answered = true
		vals = append(vals, v...)
	}
	if !answered {
		return nil, lastErr
	}
	return vals, nil
}

type placedRecord struct {
	rec  DNSRecord
	loc  *dnsLoc
	ids  []string
	gone bool
}

// dnsPlacement hält die angelegten Einträge, damit sie nach der Bestätigung wieder verschwinden.
type dnsPlacement struct {
	items []*placedRecord
}

// placeRecords legt alle Einträge in der jeweils passenden Zone an. Bei einem Fehler wird zurückgerollt.
func placeRecords(ctx context.Context, r *dnsRouter, recs []DNSRecord, rep Reporter) (*dnsPlacement, error) {
	pl := &dnsPlacement{}
	for _, rec := range recs {
		loc, err := r.locate(ctx, rec.Name)
		if err != nil {
			pl.cleanup(context.Background(), rep)
			return nil, err
		}
		it := &placedRecord{rec: rec, loc: loc}
		pl.items = append(pl.items, it)
		if n, err := loc.acct.prov.CleanStale(ctx, loc.zone, rec.Name); err != nil {
			rep.Logf("Alte Einträge bei „%s“ ließen sich nicht prüfen: %v", rec.Name, err)
		} else if n > 0 {
			rep.Logf("%d alter Eintrag von früheren Läufen bei „%s“ entfernt", n, rec.Name)
		}
		for _, v := range rec.Values {
			id, err := loc.acct.prov.AddTXT(ctx, loc.zone, rec.Name, v)
			if err != nil {
				pl.cleanup(context.Background(), rep)
				return nil, err
			}
			it.ids = append(it.ids, id)
		}
		rep.Note("dns", fmt.Sprintf("%s → Zone %s", rec.Name, loc.zone.Name))
	}
	return pl, nil
}

// waitVisible wartet, bis die Nameserver des Anbieters die Einträge ausliefern. Lassen sie sich nicht abfragen
// (z. B. UDP 53 gesperrt), wird stattdessen kurz gewartet.
func (pl *dnsPlacement) waitVisible(ctx context.Context, rep Reporter) error {
	deadline := time.Now().Add(dnsPollMax)
	for _, it := range pl.items {
		fails := 0
		for {
			got, err := authTXT(ctx, it.loc.zone.NameServers, it.rec.Name)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				fails++
				if fails >= 3 {
					rep.Note("dnswarten", "Die DNS-Server von Cloudflare lassen sich von hier nicht direkt abfragen, ich warte stattdessen kurz.")
					rep.Logf("Direkte DNS-Abfrage nicht möglich: %v", err)
					if e := sleepCtx(ctx, dnsFallbackWait); e != nil {
						return e
					}
					break
				}
			} else {
				fails = 0
				have := map[string]bool{}
				for _, g := range got {
					have[strings.TrimSpace(g)] = true
				}
				all := true
				for _, v := range it.rec.Values {
					if !have[v] {
						all = false
					}
				}
				if all {
					break
				}
			}
			if time.Now().After(deadline) {
				return uerr(fmt.Sprintf("Der Eintrag „%s“ wird von den DNS-Servern von Cloudflare nicht ausgeliefert, obwohl er angelegt wurde. Bitte in der Cloudflare-Oberfläche prüfen, ob die Zone „%s“ aktiv ist.", it.rec.Name, it.loc.zone.Name), "")
			}
			if e := sleepCtx(ctx, dnsPollEvery); e != nil {
				return e
			}
		}
	}
	return nil
}

// cleanup löscht die angelegten Einträge (mehrfach aufrufbar).
func (pl *dnsPlacement) cleanup(ctx context.Context, rep Reporter) (removed int, failed []string) {
	for _, it := range pl.items {
		if it.gone {
			continue
		}
		it.gone = true
		for _, id := range it.ids {
			if err := it.loc.acct.prov.DeleteRecord(ctx, it.loc.zone, id); err != nil {
				failed = append(failed, it.rec.Name)
				rep.Logf("Der Eintrag „%s“ ließ sich nicht löschen: %v", it.rec.Name, err)
				continue
			}
			removed++
		}
	}
	return removed, failed
}
