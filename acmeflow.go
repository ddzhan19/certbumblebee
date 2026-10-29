package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// Reporter nimmt Fortschritt entgegen (Oberfläche, Konsole und Protokoll).
type Reporter interface {
	Declare(key, label string)
	Step(key, label string)
	Note(key, note string)
	Ok(key, note string)
	Fail(key, msg string)
	Logf(format string, a ...any)
}

// userError ist ein Fehler mit verständlicher Meldung und optionalen technischen Details.
type userError struct{ Msg, Tech string }

func (e *userError) Error() string { return e.Msg }

func uerr(msg, tech string) error { return &userError{Msg: msg, Tech: tech} }

func httpPort() string {
	if v := os.Getenv("ZA_HTTP_PORT"); v != "" {
		return v
	}
	return "80"
}

// ---------- Eingebauter Miniwebserver für die HTTP-01-Bestätigung ----------

type challengeServer struct {
	srv  *http.Server
	mu   sync.RWMutex
	resp map[string]string
	rep  Reporter
}

func startChallengeServer(rep Reporter) (*challengeServer, error) {
	ln, err := net.Listen("tcp", ":"+httpPort())
	if err != nil {
		return nil, err
	}
	cs := &challengeServer{resp: map[string]string{}, rep: rep}
	cs.srv = &http.Server{Handler: cs, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = cs.srv.Serve(ln) }()
	return cs, nil
}

func (c *challengeServer) set(urlPath, body string) {
	c.mu.Lock()
	c.resp[urlPath] = body
	c.mu.Unlock()
}

func (c *challengeServer) del(urlPath string) {
	c.mu.Lock()
	delete(c.resp, urlPath)
	c.mu.Unlock()
}

func (c *challengeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.RLock()
	body, ok := c.resp[r.URL.Path]
	c.mu.RUnlock()
	if !ok || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	if r.Method == http.MethodGet {
		_, _ = io.WriteString(w, body)
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	c.rep.Logf("Die Bestätigungsdatei wurde abgerufen (von %s).", host)
}

func (c *challengeServer) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = c.srv.Shutdown(ctx)
}

// ---------- Webroot-Modus: Datei in den Ordner eines vorhandenen Webservers legen ----------

const iisWebConfig = `<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <staticContent>
      <clear />
      <mimeMap fileExtension="." mimeType="text/plain" />
    </staticContent>
  </system.webServer>
</configuration>
`

func challengeDir(root string) string {
	return filepath.Join(root, ".well-known", "acme-challenge")
}

func prepareWebroot(roots []string) error {
	for _, r := range roots {
		d := challengeDir(r)
		if err := os.MkdirAll(d, 0o755); err != nil {
			return uerr(fmt.Sprintf("Im Webordner „%s“ lässt sich kein Unterordner anlegen. Bitte Pfad und Schreibrechte prüfen.", r), err.Error())
		}
		cfg := filepath.Join(d, "web.config")
		if _, err := os.Stat(cfg); err != nil {
			// IIS liefert Dateien ohne Endung sonst nicht aus. Für andere Webserver ist die Datei harmlos.
			_ = os.WriteFile(cfg, []byte(iisWebConfig), 0o644)
		}
	}
	return nil
}

func writeWebrootChallenge(roots []string, token, body string) (func(), error) {
	var written []string
	cleanup := func() {
		for _, f := range written {
			_ = os.Remove(f)
		}
	}
	for _, r := range roots {
		f := filepath.Join(challengeDir(r), token)
		if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
			cleanup()
			return nil, uerr(fmt.Sprintf("Die Bestätigungsdatei konnte nicht in „%s“ abgelegt werden.", r), err.Error())
		}
		written = append(written, f)
	}
	return cleanup, nil
}

// ---------- Konto ----------

func loadOrCreateAccountKey(id string) (*ecdsa.PrivateKey, error) {
	path := filepath.Join(profileDir(id), "account.key")
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk != nil {
			if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
				return k, nil
			}
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

// ---------- Ausstellung ----------

func declareSteps(rep Reporter, p *Profile) {
	if p.Method == "selfsigned" {
		declareSelfSignedSteps(rep, p)
		return
	}
	switch p.Method {
	case "dns":
		rep.Declare("konto", "Konto beim Zertifikatsanbieter")
		rep.Declare("bestellung", "Zertifikat bestellen")
		rep.Declare("dns", "DNS-Einträge bei Cloudflare anlegen")
		rep.Declare("dnswarten", "Warten, bis die Einträge ausgeliefert werden")
		rep.Declare("pruefung", "Domains bestätigen")
		rep.Declare("aufraeumen", "DNS-Einträge wieder entfernen")
	case "webroot":
		rep.Declare("vorbereitung", "Webordner prüfen")
		rep.Declare("konto", "Konto beim Zertifikatsanbieter")
		rep.Declare("bestellung", "Zertifikat bestellen")
		rep.Declare("pruefung", "Domains bestätigen")
	default:
		rep.Declare("vorbereitung", "Eingebauten Webserver starten (Port "+httpPort()+")")
		rep.Declare("konto", "Konto beim Zertifikatsanbieter")
		rep.Declare("bestellung", "Zertifikat bestellen")
		rep.Declare("pruefung", "Domains bestätigen")
	}
	rep.Declare("zertifikat", "Zertifikat abholen")
	if p.hasOutput("pfx") {
		rep.Declare("pfx", "PFX-Datei erzeugen")
	}
	rep.Declare("ziel", "In den Zielordner speichern")
}

func issueCertificate(ctx context.Context, p *Profile, rep Reporter) (chainPEM, keyPEM, csrPEM []byte, err error) {
	switch p.Method {
	case "selfsigned":
		return issueSelfSigned(ctx, p, rep)
	case "dns":
		return issueDNS(ctx, p, rep)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	// 1. Vorbereitung: Webserver oder Webordner
	var cs *challengeServer
	if p.Method == "webroot" {
		rep.Step("vorbereitung", "Webordner prüfen")
		if err := prepareWebroot(p.Webroot); err != nil {
			rep.Fail("vorbereitung", err.Error())
			return nil, nil, nil, err
		}
		rep.Ok("vorbereitung", fmt.Sprintf("%d Ordner bereit", len(p.Webroot)))
	} else {
		rep.Step("vorbereitung", "Eingebauten Webserver starten (Port "+httpPort()+")")
		cs, err = startChallengeServer(rep)
		if err != nil {
			e := uerr(fmt.Sprintf("Port %s ist auf diesem Server belegt oder gesperrt. Läuft hier schon ein Webserver (z. B. IIS oder nginx), bitte „Vorhandener Webserver“ als Methode wählen.", httpPort()), err.Error())
			rep.Fail("vorbereitung", e.Error())
			return nil, nil, nil, e
		}
		defer cs.Close()
		rep.Ok("vorbereitung", "läuft")
	}

	// 2. Konto
	cl, err := acmeConnect(ctx, p, rep)
	if err != nil {
		return nil, nil, nil, err
	}

	// 3. Bestellung
	rep.Step("bestellung", "Zertifikat bestellen")
	ids := make([]acme.AuthzID, len(p.Domains))
	for i, d := range p.Domains {
		ids[i] = acme.AuthzID{Type: "dns", Value: d}
	}
	order, err := cl.AuthorizeOrder(ctx, ids)
	if err != nil {
		e := explainACME(err, "", p)
		rep.Fail("bestellung", e.Error())
		return nil, nil, nil, e
	}
	rep.Ok("bestellung", fmt.Sprintf("%d Domain(s)", len(p.Domains)))

	// 4. Domains bestätigen (HTTP-01)
	rep.Step("pruefung", "Domains bestätigen")
	for _, zurl := range order.AuthzURLs {
		az, err := cl.GetAuthorization(ctx, zurl)
		if err != nil {
			e := explainACME(err, "", p)
			rep.Fail("pruefung", e.Error())
			return nil, nil, nil, e
		}
		dom := az.Identifier.Value
		if az.Status == acme.StatusValid {
			rep.Note("pruefung", dom+" war schon bestätigt")
			continue
		}
		var ch *acme.Challenge
		for _, c := range az.Challenges {
			if c.Type == "http-01" {
				ch = c
				break
			}
		}
		if ch == nil {
			e := uerr(fmt.Sprintf("Der Zertifikatsanbieter bietet für „%s“ keine Bestätigung per Datei (HTTP) an.", dom), "")
			rep.Fail("pruefung", e.Error())
			return nil, nil, nil, e
		}
		body, err := cl.HTTP01ChallengeResponse(ch.Token)
		if err != nil {
			rep.Fail("pruefung", err.Error())
			return nil, nil, nil, err
		}
		urlPath := cl.HTTP01ChallengePath(ch.Token)
		var cleanup func()
		if p.Method == "webroot" {
			cleanup, err = writeWebrootChallenge(p.Webroot, ch.Token, body)
			if err != nil {
				rep.Fail("pruefung", err.Error())
				return nil, nil, nil, err
			}
		} else {
			cs.set(urlPath, body)
			cleanup = func() { cs.del(urlPath) }
		}
		rep.Note("pruefung", "Prüfe "+dom+" …")
		if _, err = cl.Accept(ctx, ch); err == nil {
			_, err = cl.WaitAuthorization(ctx, az.URI)
		}
		cleanup()
		if err != nil {
			e := explainACME(err, dom, p)
			rep.Fail("pruefung", e.Error())
			return nil, nil, nil, e
		}
		rep.Note("pruefung", dom+" bestätigt")
	}
	rep.Ok("pruefung", "alle Domains bestätigt")

	// 5. Schlüssel, Anforderung, Zertifikat
	return acmeFinalize(ctx, cl, order, p, rep)
}

// acmeConnect meldet das Konto des Profils beim Zertifikatsanbieter an (Schritt „konto“).
func acmeConnect(ctx context.Context, p *Profile, rep Reporter) (*acme.Client, error) {
	rep.Step("konto", "Konto beim Zertifikatsanbieter")
	accKey, err := loadOrCreateAccountKey(p.ID)
	if err != nil {
		rep.Fail("konto", err.Error())
		return nil, err
	}
	cl := &acme.Client{Key: accKey, DirectoryURL: p.DirectoryURL, UserAgent: userAgent}
	acct := &acme.Account{}
	if p.Email != "" {
		acct.Contact = []string{"mailto:" + p.Email}
	}
	if _, err := cl.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		e := explainACME(err, "", p)
		rep.Fail("konto", e.Error())
		return nil, e
	}
	rep.Ok("konto", "bereit")
	return cl, nil
}

// acmeFinalize erzeugt Schlüssel und Anforderung und holt das Zertifikat (Schritt „zertifikat“).
func acmeFinalize(ctx context.Context, cl *acme.Client, order *acme.Order, p *Profile, rep Reporter) (chainPEM, keyPEM, csrPEM []byte, err error) {
	rep.Step("zertifikat", "Zertifikat abholen")
	key, err := rsa.GenerateKey(rand.Reader, p.KeyBits)
	if err != nil {
		rep.Fail("zertifikat", err.Error())
		return nil, nil, nil, err
	}
	csr, err := makeCSR(p.Domains, key)
	if err != nil {
		rep.Fail("zertifikat", err.Error())
		return nil, nil, nil, err
	}
	if _, err = cl.WaitOrder(ctx, order.URI); err != nil {
		e := explainACME(err, "", p)
		rep.Fail("zertifikat", e.Error())
		return nil, nil, nil, e
	}
	der, _, err := cl.CreateCertFromOrder(ctx, order, csr, true)
	if err != nil {
		e := explainACME(err, "", p)
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
	rep.Ok("zertifikat", fmt.Sprintf("gültig bis %s", leaf.NotAfter.Local().Format("02.01.2006")))
	return chainPEM, keyPEM, csrPEM, nil
}

// ---------- Verständliche Fehlermeldungen ----------

func explainACME(err error, domain string, p *Profile) error {
	if err == nil {
		return nil
	}
	var ue *userError
	if errors.As(err, &ue) {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return uerr("Der Vorgang hat zu lange gedauert und wurde abgebrochen.", err.Error())
	}
	if errors.Is(err, context.Canceled) {
		return uerr("Der Vorgang wurde abgebrochen.", "")
	}
	var ae *acme.AuthorizationError
	if errors.As(err, &ae) {
		dom := ae.Identifier
		if dom == "" {
			dom = domain
		}
		for _, e := range ae.Errors {
			var pe *acme.Error
			if errors.As(e, &pe) {
				return explainProblem(pe, dom, p)
			}
		}
		return uerr(fmt.Sprintf("Die Domain „%s“ konnte nicht bestätigt werden.", dom), err.Error())
	}
	var pe *acme.Error
	if errors.As(err, &pe) {
		return explainProblem(pe, domain, p)
	}
	var oe *acme.OrderError
	if errors.As(err, &oe) {
		tech := err.Error()
		if oe.Problem != nil {
			return explainProblem(oe.Problem, domain, p)
		}
		return uerr("Der Zertifikatsanbieter hat die Bestellung abgelehnt (Status „"+oe.Status+"“).", tech)
	}
	var ne net.Error
	if errors.As(err, &ne) || strings.Contains(err.Error(), "dial tcp") || strings.Contains(err.Error(), "no such host") {
		return uerr("Der Zertifikatsanbieter ist von diesem Server aus nicht erreichbar. Bitte Internetverbindung, Firewall und Proxy prüfen.", err.Error())
	}
	return uerr(err.Error(), "")
}

// dnsHint weist auf die Bestätigung per DNS-Eintrag hin. Sie braucht weder Port 80 noch einen A-Eintrag.
const dnsHint = " Alternative: die Bestätigung per DNS-Eintrag. Sie braucht weder Port 80 noch einen öffentlichen A-Eintrag und funktioniert auch für normale Domains. Dafür die Methode „DNS (Cloudflare)“ wählen, wenn die Domain bei Cloudflare liegt, sonst den Tab „Wildcard / DNS (manuell)“ (ohne automatische Erneuerung)."

func explainProblem(pe *acme.Error, dom string, p *Profile) error {
	t := strings.ToLower(pe.ProblemType)
	tech := strings.TrimSpace(fmt.Sprintf("%s\n%s", pe.ProblemType, pe.Detail))
	hostPart := ""
	if dom != "" {
		hostPart = " für „" + dom + "“"
	}
	switch {
	case strings.HasSuffix(t, ":connection"), strings.Contains(pe.Detail, "Timeout during connect"), strings.Contains(pe.Detail, "Connection refused"):
		if p != nil && p.Method == "webroot" {
			return uerr("Der Zertifikatsanbieter konnte"+hostPart+" keinen Webserver auf Port 80 erreichen. Die Domain muss im Internet auf diesen Webserver zeigen und Port 80 muss von außen offen sein."+dnsHint, tech)
		}
		return uerr("Der Zertifikatsanbieter konnte"+hostPart+" diesen Server nicht auf Port 80 erreichen. Bitte prüfen: Zeigt die Domain (DNS) auf die öffentliche Adresse dieses Servers? Ist Port 80 in der Firewall und im Router/der Firewall des Netzwerks auf diesen Server weitergeleitet?"+dnsHint, tech)
	case strings.HasSuffix(t, ":unauthorized"):
		return uerr("Der Zertifikatsanbieter hat"+hostPart+" nicht die erwartete Bestätigungsdatei erhalten. Die Domain zeigt vermutlich auf einen anderen Server oder ein anderer Webserver beantwortet die Anfrage.", tech)
	case strings.HasSuffix(t, ":dns"):
		return uerr("Die Domain"+strings.TrimPrefix(hostPart, " für")+" konnte nicht aufgelöst werden. Der öffentliche DNS-Eintrag (A- oder AAAA-Eintrag) fehlt oder ist falsch."+dnsHint, tech)
	case strings.HasSuffix(t, ":ratelimited"):
		return uerr("Der Zertifikatsanbieter hat die Anfrage wegen zu vieler Versuche begrenzt. Bitte später erneut versuchen. Zum Ausprobieren eignet sich „Let’s Encrypt Test“.", tech)
	case strings.HasSuffix(t, ":rejectedidentifier"), strings.HasSuffix(t, ":invalididentifier"):
		return uerr("Der Zertifikatsanbieter stellt für diese Domain"+strings.TrimPrefix(hostPart, " für")+" kein Zertifikat aus (öffentlich nicht erreichbare oder nicht erlaubte Domain).", tech)
	case strings.HasSuffix(t, ":invalidcontact"), strings.HasSuffix(t, ":unsupportedcontact"):
		return uerr("Die E-Mail-Adresse wurde vom Zertifikatsanbieter nicht akzeptiert.", tech)
	case strings.HasSuffix(t, ":caa"):
		return uerr("Ein CAA-Eintrag der Domain"+strings.TrimPrefix(hostPart, " für")+" verbietet diesem Anbieter die Ausstellung.", tech)
	case strings.HasSuffix(t, ":servererror"), strings.HasSuffix(t, ":serverinternal"):
		return uerr("Beim Zertifikatsanbieter ist ein Fehler aufgetreten. Bitte später erneut versuchen.", tech)
	}
	msg := "Der Zertifikatsanbieter hat die Anfrage abgelehnt."
	if pe.Detail != "" {
		msg += " " + pe.Detail
	}
	return uerr(msg, tech)
}

// ---------- Zeitpunkt der Erneuerung ----------

func renewDue(c *x509.Certificate, now time.Time) bool {
	life := c.NotAfter.Sub(c.NotBefore)
	window := life / 3
	if window > 30*24*time.Hour {
		window = 30 * 24 * time.Hour
	}
	return now.After(c.NotAfter.Add(-window))
}

func sameDomains(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]bool{}
	for _, x := range a {
		m[strings.ToLower(x)] = true
	}
	for _, y := range b {
		if !m[strings.ToLower(y)] {
			return false
		}
	}
	return true
}
