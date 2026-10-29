package main

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// CreateRequest ist die Eingabe aus der Oberfläche.
type CreateRequest struct {
	Domains      string   `json:"domains"`
	Method       string   `json:"method"`
	Webroot      string   `json:"webroot"`
	DNSAccount   string   `json:"dnsAccount"` // nur Methode „dns“: Zugang, leer = je Zone automatisch
	ValidDays    int      `json:"validDays"`  // nur selbstsigniert: Gültigkeit in Tagen
	TargetDir    string   `json:"targetDir"`
	FileName     string   `json:"fileName"`   // Dateiname ohne Endung (optional)
	Outputs      []string `json:"outputs"`    // pfx, cert, chain, fullchain, key, csr
	CertFormat   string   `json:"certFormat"` // crt | cer | pem | cer-der
	Password     string   `json:"password"`
	Server       string   `json:"server"`
	CustomURL    string   `json:"customUrl"`
	Email        string   `json:"email"`
	KeyBits      int      `json:"keyBits"`
	PfxFormat    string   `json:"pfxFormat"`
	AutoRenew    bool     `json:"autoRenew"`
	TaskTime     string   `json:"taskTime"`
	RunAs        string   `json:"runAs"` // system | user
	User         string   `json:"user"`
	UserPassword string   `json:"userPassword"`
	TaskName     string   `json:"taskName"`
	Firewall     bool     `json:"firewall"`
	Replace      bool     `json:"replace"`
}

var (
	errExists   = errors.New("Für diese Domain gibt es schon eine Einrichtung.")
	timeRe      = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)
	accountRe   = regexp.MustCompile(`^([A-Za-z0-9._-]+\\[A-Za-z0-9._$ -]+|[A-Za-z0-9._-]+@[A-Za-z0-9.-]+)$`)
	badNameRe   = regexp.MustCompile("[\\\\/:*?\"<>|'\u0000-\u001f" + smartQuotes + "]")
	emailRe     = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	taskNameBad = badNameRe
)

func ruleName(id string) string { return "Certbumblebee Port 80 (" + id + ")" }

// resolveServer wählt den Zertifikatsanbieter: prod, staging oder eine eigene ACME-Adresse.
func resolveServer(kind, customURL string) (string, string, error) {
	switch kind {
	case "staging":
		return "staging", dirStaging, nil
	case "custom":
		u, err := url.Parse(strings.TrimSpace(customURL))
		loopback := err == nil && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost")
		if err != nil || u.Host == "" || (u.Scheme != "https" && !loopback) {
			return "", "", fmt.Errorf("Eigener ACME-Server: Bitte die https-Adresse des Verzeichnisses angeben.")
		}
		return "custom", u.String(), nil
	}
	return "prod", dirProd, nil
}

// buildProfile prüft die Eingaben und baut daraus das Profil. Fehler sind für Menschen formuliert.
func buildProfile(req CreateRequest) (*Profile, error) {
	var domains []string
	var err error
	switch req.Method {
	case "selfsigned":
		domains, err = normalizeNames(req.Domains)
	case "dns":
		domains, err = normalizeWildDomains(req.Domains)
	default:
		domains, err = normalizeDomains(req.Domains)
	}
	if err != nil {
		return nil, err
	}
	win := plat.IsWindows()
	p := &Profile{Domains: domains, Created: time.Now().Truncate(time.Second)}
	p.ID = slugID(domains[0])
	if !validID(p.ID) {
		return nil, fmt.Errorf("Aus der Domain „%s“ lässt sich keine Kennung bilden.", domains[0])
	}

	switch req.Method {
	case "webroot":
		p.Method = "webroot"
		seen := map[string]bool{}
		for _, l := range strings.Split(strings.ReplaceAll(req.Webroot, "\r", ""), "\n") {
			if strings.TrimSpace(l) == "" {
				continue
			}
			v, err := validatePath(l, win, "Ordner des Webservers")
			if err != nil {
				return nil, err
			}
			if !seen[v] {
				seen[v] = true
				p.Webroot = append(p.Webroot, v)
			}
		}
		if len(p.Webroot) == 0 {
			return nil, fmt.Errorf("Ordner des Webservers: Bitte mindestens einen Ordner angeben (z. B. C:\\inetpub\\wwwroot).")
		}
	case "dns":
		p.Method = "dns"
		p.DNSAccount = strings.TrimSpace(req.DNSAccount)
		accts := listDNSAccounts()
		if len(accts) == 0 {
			return nil, fmt.Errorf("Für „DNS (Cloudflare)“ muss zuerst ein Zugang hinterlegt werden: Reiter „DNS-Zugänge“, dort den Cloudflare-Token eintragen.")
		}
		if p.DNSAccount != "" {
			found := false
			for _, a := range accts {
				found = found || a.ID == p.DNSAccount
			}
			if !found {
				return nil, fmt.Errorf("Der gewählte DNS-Zugang existiert nicht.")
			}
		}
	case "selfsigned":
		p.Method = "selfsigned"
		p.ValidDays = req.ValidDays
		if p.ValidDays == 0 {
			p.ValidDays = selfSignedDefaultDays
		}
		if p.ValidDays < selfSignedMinDays || p.ValidDays > selfSignedMaxDays {
			return nil, fmt.Errorf("Die Gültigkeit muss zwischen %d und %d Tagen liegen.", selfSignedMinDays, selfSignedMaxDays)
		}
	case "standalone", "":
		p.Method = "standalone"
	default:
		return nil, fmt.Errorf("Unbekannte Methode.")
	}

	if p.TargetDir, err = validatePath(req.TargetDir, win, "Zielordner"); err != nil {
		return nil, err
	}
	base := baseName(req.FileName, domains[0])
	if base == "" || badNameRe.MatchString(base) || len(base) > 110 {
		return nil, fmt.Errorf("Dateiname: Bitte einen einfachen Namen ohne \\ / : * ? \" < > | und Anführungszeichen verwenden.")
	}
	kinds := req.Outputs
	if p.Method == "selfsigned" { // ein selbstsigniertes Zertifikat hat keine Zwischenzertifikate
		kinds = nil
		for _, k := range req.Outputs {
			if k != "chain" {
				kinds = append(kinds, k)
			}
		}
		if len(req.Outputs) > 0 && len(kinds) == 0 {
			return nil, fmt.Errorf("Bitte mindestens eine Datei auswählen. Zwischenzertifikate gibt es bei selbstsignierten Zertifikaten nicht.")
		}
	}
	outs, err := planOutputs(kinds, req.CertFormat, base)
	if err != nil {
		return nil, err
	}
	p.Outputs = outs
	p.FileName = outs[0].Name
	for _, o := range outs {
		if o.Kind == "pfx" {
			p.FileName = o.Name
		}
	}
	if p.hasOutput("pfx") && req.Password == "" {
		return nil, fmt.Errorf("Bitte ein Passwort für die PFX-Datei vergeben.")
	}
	if len(req.Password) > 100 || strings.ContainsAny(req.Password, "\x00\r\n") {
		return nil, fmt.Errorf("Das PFX-Passwort ist ungültig (höchstens 100 Zeichen, keine Zeilenumbrüche).")
	}

	if p.Method == "selfsigned" {
		p.ServerKind = "selfsigned"
	} else if p.ServerKind, p.DirectoryURL, err = resolveServer(req.Server, req.CustomURL); err != nil {
		return nil, err
	}

	if p.Method != "selfsigned" {
		p.Email = strings.TrimSpace(req.Email)
	}
	if p.Email != "" && (!emailRe.MatchString(p.Email) || strings.ContainsAny(p.Email, smartQuotes)) {
		return nil, fmt.Errorf("Die E-Mail-Adresse sieht nicht richtig aus.")
	}

	p.KeyBits = req.KeyBits
	if p.KeyBits == 0 {
		p.KeyBits = 2048
	}
	if p.KeyBits != 2048 && p.KeyBits != 3072 && p.KeyBits != 4096 {
		return nil, fmt.Errorf("Die Schlüssellänge muss 2048, 3072 oder 4096 sein.")
	}
	switch req.PfxFormat {
	case "aes":
		p.PfxFormat = "aes"
	default:
		p.PfxFormat = "compat"
	}

	p.Task = TaskConfig{Enabled: req.AutoRenew, Time: "03:00", RunAs: "SYSTEM"}
	if p.Task.Enabled {
		if t := strings.TrimSpace(req.TaskTime); t != "" {
			p.Task.Time = t
		}
		if !timeRe.MatchString(p.Task.Time) {
			return nil, fmt.Errorf("Uhrzeit: Bitte im Format HH:MM angeben, z. B. 03:00.")
		}
		if req.RunAs == "user" {
			acc := strings.TrimSpace(req.User)
			if !accountRe.MatchString(acc) {
				return nil, fmt.Errorf("Konto: Bitte als DOMÄNE\\Benutzer oder Benutzer@domäne angeben.")
			}
			if win && req.UserPassword == "" {
				return nil, fmt.Errorf("Für das Konto „%s“ wird das Windows-Passwort benötigt, damit die Aufgabe laufen kann.", acc)
			}
			p.Task.RunAs = acc
		}
		p.Task.Name = strings.TrimSpace(req.TaskName)
		if p.Task.Name == "" {
			p.Task.Name = "Certbumblebee Erneuerung " + p.ID
		}
		if taskNameBad.MatchString(p.Task.Name) || len(p.Task.Name) > 200 {
			return nil, fmt.Errorf("Aufgabenname: Bitte ohne \\ / : * ? \" < > | und Anführungszeichen.")
		}
		if win && plat.IsMappedDrive(p.TargetDir) {
			return nil, fmt.Errorf("„%s“ liegt auf einem zugeordneten Netzlaufwerk. Die automatische Aufgabe sieht solche Laufwerke nicht. Bitte den UNC-Pfad verwenden, z. B. \\\\server\\freigabe\\ordner.", p.TargetDir)
		}
	}
	p.Firewall = req.Firewall && p.Method == "standalone" && win
	return p, nil
}

// ---------- Ausstellen / Erneuern ----------

type CertInfo struct {
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	Issuer      string    `json:"issuer"`
	Subject     string    `json:"subject"`
	Serial      string    `json:"serial"`
	Fingerprint string    `json:"fingerprint"`
	DNSNames    []string  `json:"dnsNames"`
	KeyBits     int       `json:"keyBits"`
	SelfSigned  bool      `json:"selfSigned"`
}

func bytesEqualRaw(a, b []byte) bool { return string(a) == string(b) }

func certInfoFrom(c *x509.Certificate) *CertInfo {
	sum := sha256.Sum256(c.Raw)
	fp := strings.ToUpper(hex.EncodeToString(sum[:]))
	var parts []string
	for i := 0; i < len(fp); i += 2 {
		parts = append(parts, fp[i:i+2])
	}
	issuer := c.Issuer.CommonName
	if issuer == "" && len(c.Issuer.Organization) > 0 {
		issuer = c.Issuer.Organization[0]
	}
	bits := 0
	type sizer interface{ Size() int }
	if k, ok := c.PublicKey.(sizer); ok {
		bits = k.Size() * 8
	}
	return &CertInfo{NotBefore: c.NotBefore, NotAfter: c.NotAfter, Issuer: issuer, Subject: c.Subject.CommonName,
		Serial: strings.ToUpper(c.SerialNumber.Text(16)), Fingerprint: strings.Join(parts, ":"), DNSNames: certNames(c), KeyBits: bits,
		SelfSigned: bytesEqualRaw(c.RawIssuer, c.RawSubject) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil}
}

func loadCertInfo(id string) *CertInfo {
	b, err := os.ReadFile(filepath.Join(profileDir(id), "fullchain.pem"))
	if err != nil {
		return nil
	}
	cs, err := parseCertsPEM(b)
	if err != nil {
		return nil
	}
	return certInfoFrom(cs[0])
}

type RunResult struct {
	Result  string    `json:"result"` // ausgestellt | erneuert | nicht-faellig
	Issued  bool      `json:"issued"`
	Written bool      `json:"written"`
	Target  string    `json:"target"` // Zielordner
	Files   []string  `json:"files"`  // Pfade der abgelegten Dateien
	Cert    *CertInfo `json:"cert,omitempty"`
	Message string    `json:"message"`
}

func runProfile(ctx context.Context, p *Profile, pw string, force bool, rep Reporter) (res *RunResult, err error) {
	declareSteps(rep, p)
	dir := profileDir(p.ID)
	chainPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	csrPath := filepath.Join(dir, "request.csr.pem")
	pfxPath := filepath.Join(dir, "current.pfx")
	st := loadState(p.ID)
	defer func() {
		st.LastRun = time.Now()
		if err != nil {
			st.LastResult, st.LastMessage = "fehler", err.Error()
		} else {
			st.LastResult, st.LastMessage = res.Result, res.Message
		}
		_ = saveState(p.ID, st)
		if err != nil {
			appLog(p.ID, "ERROR", "Lauf fehlgeschlagen: "+err.Error())
		} else {
			appLog(p.ID, "INFO", "Lauf beendet: "+res.Message)
		}
	}()

	var cur *x509.Certificate
	if b, e := os.ReadFile(chainPath); e == nil {
		if cs, e := parseCertsPEM(b); e == nil {
			cur = cs[0]
		}
	}
	if _, e := os.Stat(keyPath); e != nil {
		cur = nil // ohne Schlüssel ist das alte Zertifikat nicht nutzbar
	}

	now := time.Now()
	reason := ""
	switch {
	case force:
		reason = "Erneuerung wurde erzwungen."
	case cur == nil:
		reason = "Es gibt noch kein Zertifikat, erstelle ein neues."
	case !sameDomains(certNames(cur), p.Domains):
		reason = "Die Namen haben sich geändert, erstelle ein neues Zertifikat."
	case renewDue(cur, now):
		reason = fmt.Sprintf("Das Zertifikat läuft am %s ab, erneuere es.", cur.NotAfter.Local().Format("02.01.2006"))
	}

	res = &RunResult{Target: p.TargetDir}
	if reason != "" {
		rep.Logf("%s", reason)
		chain, key, csr, ierr := issueCertificate(ctx, p, rep)
		if ierr != nil {
			return nil, ierr
		}
		if err = writeFileAtomic(keyPath, key, 0o600); err != nil {
			return nil, err
		}
		if err = writeFileAtomic(csrPath, csr, 0o600); err != nil {
			return nil, err
		}
		if err = writeFileAtomic(chainPath, chain, 0o600); err != nil {
			return nil, err
		}
		res.Issued = true
		if cur == nil {
			res.Result = "ausgestellt"
		} else {
			res.Result = "erneuert"
		}
	} else {
		steps := []string{"vorbereitung", "konto", "bestellung", "pruefung", "zertifikat"}
		switch p.Method {
		case "selfsigned":
			steps = []string{"zertifikat"}
		case "dns":
			steps = []string{"konto", "bestellung", "dns", "dnswarten", "pruefung", "aufraeumen", "zertifikat"}
		}
		for _, k := range steps {
			rep.Ok(k, "nicht nötig")
		}
		rep.Logf("Zertifikat gültig bis %s, Erneuerung noch nicht fällig.", cur.NotAfter.Local().Format("02.01.2006"))
		res.Result = "nicht-faellig"
	}

	chainBytes, rerr := os.ReadFile(chainPath)
	if rerr != nil {
		return nil, rerr
	}
	keyBytes, rerr := os.ReadFile(keyPath)
	if rerr != nil {
		return nil, rerr
	}
	data := outputData{Chain: chainBytes, Key: keyBytes}
	if p.hasOutput("pfx") {
		rep.Step("pfx", "PFX-Datei erzeugen")
		sig := pfxSignature(chainBytes, pw, p.PfxFormat)
		if _, e := os.Stat(pfxPath); e != nil || st.PfxSig != sig {
			pfxBytes, berr := buildPFX(keyBytes, chainBytes, pw, p.PfxFormat)
			if berr != nil {
				rep.Fail("pfx", berr.Error())
				return nil, berr
			}
			if err = writeFileAtomic(pfxPath, pfxBytes, 0o600); err != nil {
				rep.Fail("pfx", err.Error())
				return nil, err
			}
			st.PfxSig = sig
			rep.Ok("pfx", "erzeugt")
		} else {
			rep.Ok("pfx", "bereits aktuell")
		}
		if data.PFX, rerr = os.ReadFile(pfxPath); rerr != nil {
			return nil, rerr
		}
	}
	if p.hasOutput("csr") {
		data.CSR, _ = os.ReadFile(csrPath)
		if len(data.CSR) == 0 { // Einrichtung ohne gespeicherte Anforderung: aus dem Schlüssel neu bauen
			if k, kerr := parseKeyPEM(keyBytes); kerr == nil {
				if signer, ok := k.(crypto.Signer); ok {
					if der, e := makeCSR(p.Domains, signer); e == nil {
						data.CSR = csrToPEM(der)
					}
				}
			}
		}
	}

	rep.Step("ziel", "In den Zielordner speichern")
	all, written, serr := syncOutputs(p, data)
	if serr != nil {
		rep.Fail("ziel", serr.Error())
		return nil, serr
	}
	res.Files = all
	res.Written = len(written) > 0
	if res.Written {
		st.SyncedAt = time.Now()
		rep.Ok("ziel", fmt.Sprintf("%s in „%s“", filesText(len(written)), p.TargetDir))
	} else {
		rep.Ok("ziel", fmt.Sprintf("%s in „%s“ waren schon aktuell", filesText(len(all)), p.TargetDir))
	}

	res.Cert = loadCertInfo(p.ID)
	until := ""
	if res.Cert != nil {
		until = res.Cert.NotAfter.Local().Format("02.01.2006")
	}
	switch res.Result {
	case "ausgestellt":
		res.Message = "Zertifikat ausgestellt, gültig bis " + until + "."
	case "erneuert":
		res.Message = "Zertifikat erneuert, gültig bis " + until + "."
	default:
		res.Message = "Zertifikat gültig bis " + until + ", Erneuerung noch nicht fällig."
		if res.Written {
			res.Message += " Dateien im Zielordner aktualisiert."
		}
	}
	return res, nil
}

// renewProfile wird von der Aufgabe („renew“) und der Oberfläche benutzt.
func renewProfile(ctx context.Context, id string, force bool, rep Reporter) (*RunResult, error) {
	unlock, err := lockProfile(id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	p, err := loadProfile(id)
	if err != nil {
		return nil, err
	}
	pw := ""
	if p.hasOutput("pfx") {
		if pw, err = loadSecret(id); err != nil {
			return nil, err
		}
	}
	return runProfile(ctx, p, pw, force, rep)
}

// createProfile richtet alles ein und stellt das erste Zertifikat aus. Bei Fehlern wird nichts zurückgelassen.
func createProfile(ctx context.Context, p *Profile, req CreateRequest, rep Reporter) (res *RunResult, err error) {
	self, _ := os.Executable()
	rep.Declare("einrichtung", "Arbeitsordner einrichten")
	if p.Firewall {
		rep.Declare("firewall", "Windows-Firewall: Port 80 erlauben")
	}
	declareSteps(rep, p)
	if p.Task.Enabled {
		rep.Declare("aufgabe", "Aufgabe in der Aufgabenplanung anlegen")
	}

	existed := false
	if _, e := os.Stat(filepath.Join(profileDir(p.ID), "profile.json")); e == nil {
		existed = true
		if !req.Replace {
			return nil, errExists
		}
	}
	unlock, err := lockProfile(p.ID)
	if err != nil {
		return nil, err
	}
	unlockDone := false
	defer func() {
		if !unlockDone {
			unlock()
		}
	}()

	// 1. Arbeitsordner, Rechte, Programmkopie
	rep.Step("einrichtung", "Arbeitsordner einrichten")
	if existed {
		if old, e := loadProfile(p.ID); e == nil {
			removeExternal(old, rep)
		}
		_ = os.RemoveAll(profileDir(p.ID))
	}
	if err = os.MkdirAll(dataDir(), 0o755); err != nil {
		rep.Fail("einrichtung", err.Error())
		return nil, uerr("Der Arbeitsordner konnte nicht angelegt werden. Bitte das Programm als Administrator starten.", err.Error())
	}
	extra := ""
	if p.Task.Enabled && p.Task.RunAs != "SYSTEM" {
		extra = p.Task.RunAs
	}
	if err = plat.SecureDir(dataDir(), extra); err != nil {
		rep.Fail("einrichtung", err.Error())
		return nil, uerr("Die Zugriffsrechte für den Arbeitsordner konnten nicht gesetzt werden.", err.Error())
	}
	exe, err := plat.InstallSelf(dataDir())
	if err != nil {
		rep.Fail("einrichtung", err.Error())
		return nil, uerr("Das Programm konnte nicht in den Arbeitsordner kopiert werden (nötig, damit die Aufgabe es später starten kann).", err.Error())
	}
	if err = os.MkdirAll(profileDir(p.ID), 0o755); err != nil {
		return nil, err
	}
	if err = saveProfile(p); err != nil {
		return nil, err
	}
	if p.hasOutput("pfx") {
		if err = saveSecret(p.ID, req.Password); err != nil {
			return nil, err
		}
	}
	// Zielordner vorab prüfen: Ein falscher Pfad soll auffallen, bevor eine Bestellung beim Anbieter läuft.
	if _, terr := testWrite(p.TargetDir); terr != nil {
		err = uerr(fmt.Sprintf("Zielordner „%s“: %s", p.TargetDir, strings.TrimSuffix(terr.Error(), ".")+". Bitte Pfad und Rechte prüfen (bei Netzwerkfreigaben die Rechte des Kontos, unter dem die Aufgabe läuft)."), terr.Error())
		rep.Fail("einrichtung", err.Error())
		rollbackEarly := func() { _ = os.RemoveAll(profileDir(p.ID)) }
		rollbackEarly()
		return nil, err
	}
	rep.Ok("einrichtung", dataDir())

	rolledBack := false
	rollback := func() {
		if rolledBack {
			return
		}
		rolledBack = true
		removeExternal(p, rep)
		_ = os.RemoveAll(profileDir(p.ID))
	}
	defer func() {
		if err != nil {
			rollback()
		}
	}()

	// 2. Firewall (für den Lauf jetzt und für die Aufgabe später)
	if p.Firewall {
		rep.Step("firewall", "Windows-Firewall: Port 80 erlauben")
		if fe := plat.FirewallAdd(ruleName(p.ID), exe); fe != nil {
			rep.Fail("firewall", fe.Error())
			rep.Logf("Hinweis: Die Firewall-Regel konnte nicht angelegt werden. Port 80 muss dann von Hand freigegeben sein.")
		} else {
			if self != "" && !strings.EqualFold(self, exe) {
				_ = plat.FirewallAdd(ruleName(p.ID)+" (Start)", self)
			}
			rep.Ok("firewall", "Regel angelegt")
		}
	}

	// 3. Ausstellen
	res, err = runProfile(ctx, p, req.Password, true, rep)
	if self != "" && p.Firewall {
		_ = plat.FirewallRemove(ruleName(p.ID) + " (Start)")
	}
	if err != nil {
		return nil, err
	}

	// 4. Aufgabe
	if p.Task.Enabled {
		rep.Step("aufgabe", "Aufgabe in der Aufgabenplanung anlegen")
		spec := TaskSpec{Name: p.Task.Name, ExePath: exe, Args: "renew --id " + p.ID, WorkDir: dataDir(), Time: p.Task.Time, RunAs: p.Task.RunAs}
		if p.Task.RunAs != "SYSTEM" {
			spec.Password = req.UserPassword
		}
		if te := plat.TaskRegister(spec); te != nil {
			err = uerr("Das Zertifikat wurde ausgestellt, aber die Aufgabe in der Aufgabenplanung konnte nicht angelegt werden.", te.Error())
			rep.Fail("aufgabe", te.Error())
			return nil, err
		}
		rep.Ok("aufgabe", fmt.Sprintf("täglich um %s Uhr (%s)", p.Task.Time, p.Task.RunAs))
	}
	unlockDone = true
	unlock()
	return res, nil
}

// removeExternal entfernt Aufgabe und Firewall-Regeln eines Profils (nicht die PFX im Zielordner).
func removeExternal(p *Profile, rep Reporter) {
	if p.Task.Enabled && p.Task.Name != "" {
		if ok, _ := plat.TaskExists(p.Task.Name); ok {
			if err := plat.TaskDelete(p.Task.Name); err != nil {
				rep.Logf("Die Aufgabe „%s“ konnte nicht entfernt werden: %v", p.Task.Name, err)
			} else {
				rep.Logf("Aufgabe „%s“ entfernt.", p.Task.Name)
			}
		}
	}
	if p.Firewall {
		_ = plat.FirewallRemove(ruleName(p.ID))
		_ = plat.FirewallRemove(ruleName(p.ID) + " (Start)")
	}
}

func deleteProfile(id string, rep Reporter) error {
	unlock, err := lockProfile(id)
	if err != nil {
		return err
	}
	defer unlock()
	p, err := loadProfile(id)
	if err != nil {
		return err
	}
	removeExternal(p, rep)
	_ = os.Remove(filepath.Join(profileDir(id), "run.lock"))
	if err := os.RemoveAll(profileDir(id)); err != nil {
		return err
	}
	appLog(id, "INFO", "Einrichtung gelöscht (die PFX-Datei im Zielordner bleibt erhalten).")
	return nil
}

// ---------- Übersicht ----------

type TaskView struct {
	Enabled bool   `json:"enabled"`
	Name    string `json:"name"`
	Time    string `json:"time"`
	RunAs   string `json:"runAs"`
	Exists  bool   `json:"exists"`
}

type FileView struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	Name  string `json:"name"`
	Path  string `json:"path"`
	Found bool   `json:"found"`
}

func filesText(n int) string {
	if n == 1 {
		return "1 Datei"
	}
	return fmt.Sprintf("%d Dateien", n)
}

type ProfileView struct {
	ID          string     `json:"id"`
	Domains     []string   `json:"domains"`
	Method      string     `json:"method"`
	Webroot     []string   `json:"webroot,omitempty"`
	DNSAccount  string     `json:"dnsAccount,omitempty"`
	DNSName     string     `json:"dnsName,omitempty"`
	TargetDir   string     `json:"targetDir"`
	FileName    string     `json:"fileName"`
	TargetFile  string     `json:"targetFile"`
	TargetFound bool       `json:"targetFound"`
	Files       []FileView `json:"files"`
	ServerKind  string     `json:"serverKind"`
	PfxFormat   string     `json:"pfxFormat"`
	Cert        *CertInfo  `json:"cert,omitempty"`
	DaysLeft    int        `json:"daysLeft"`
	LastRun     *time.Time `json:"lastRun,omitempty"`
	LastResult  string     `json:"lastResult"`
	LastMessage string     `json:"lastMessage"`
	Task        TaskView   `json:"task"`
}

func listProfiles() []ProfileView {
	ids := listProfileIDs()
	out := make([]ProfileView, len(ids))
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			p, err := loadProfile(id)
			if err != nil {
				out[i] = ProfileView{ID: id, LastResult: "fehler", LastMessage: err.Error()}
				return
			}
			st := loadState(id)
			v := ProfileView{ID: id, Domains: p.Domains, Method: p.Method, Webroot: p.Webroot, DNSAccount: p.DNSAccount, TargetDir: p.TargetDir, FileName: p.FileName,
				TargetFile: filepath.Join(p.TargetDir, p.FileName), ServerKind: p.ServerKind, PfxFormat: p.PfxFormat,
				LastResult: st.LastResult, LastMessage: st.LastMessage,
				Task: TaskView{Enabled: p.Task.Enabled, Name: p.Task.Name, Time: p.Task.Time, RunAs: p.Task.RunAs}}
			if !st.LastRun.IsZero() {
				t := st.LastRun
				v.LastRun = &t
			}
			v.TargetFile = filepath.Join(p.TargetDir, p.outputs()[0].Name)
			for _, o := range p.outputs() {
				fv := FileView{Kind: o.Kind, Label: outputLabel(o.Kind), Name: o.Name, Path: filepath.Join(p.TargetDir, o.Name)}
				if _, err := os.Stat(fv.Path); err == nil {
					fv.Found = true
				}
				v.Files = append(v.Files, fv)
			}
			v.TargetFound = len(v.Files) > 0 && v.Files[0].Found
			if p.Method == "dns" {
				v.DNSName = "alle Zugänge (je Zone)"
				if a, ok := getDNSAccount(p.DNSAccount); p.DNSAccount != "" {
					v.DNSName = "(gelöscht)"
					if ok {
						v.DNSName = a.Name
					}
				}
			}
			if ci := loadCertInfo(id); ci != nil {
				v.Cert = ci
				v.DaysLeft = int(time.Until(ci.NotAfter).Hours() / 24)
			}
			if p.Task.Enabled {
				v.Task.Exists, _ = plat.TaskExists(p.Task.Name)
			}
			out[i] = v
		}(i, id)
	}
	wg.Wait()
	return out
}
