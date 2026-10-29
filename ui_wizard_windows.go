//go:build windows

package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Assistent „Neues Zertifikat“: Was – Dateien – Erneuerung – Ausstellen.

const (
	wzWhat = iota + 1
	wzFiles
	wzRenew
	wzRun
)

type wizard struct {
	w     *wnd
	page  int
	title *ctl
	sub   *ctl
	back  *ctl
	next  *ctl
	abort *ctl

	// Seite 1
	domains, webroot, days              *ctl
	rStandalone, rWebroot, rSelf        *ctl
	lWebroot, lDays, hSelf, hStandalone *ctl
	bWebBrowse, bPort80, port80Res      *ctl
	// Seite 2
	out *outputsPanel
	// Seite 3
	auto, fw                                          *ctl
	time, taskName                                    *ctl
	rSystem, rUser                                    *ctl
	user, userPw                                      *ctl
	lblTime, lblName, lblRun, lblUser, lblPw, hSystem *ctl
	srv, customURL, email, bits, tos, tosRead         *ctl
	lblSrv, lblURL, lblMail, lblBits                  *ctl
	// Seite 4
	summary *ctl
	panel   *jobPanel

	running bool
	failed  bool
	created string
	req     CreateRequest
}

var wizardTitles = map[int][2]string{
	wzWhat:  {"Wofür soll das Zertifikat gelten?", "Namen und Art des Zertifikats festlegen"},
	wzFiles: {"Wohin sollen die Dateien?", "Zielordner und gewünschte Dateien festlegen"},
	wzRenew: {"Erneuerung und Anbieter", "Zertifikate laufen ab. Hier legen Sie fest, wie sie erneuert werden"},
	wzRun:   {"Zertifikat wird erstellt", ""},
}

// showWizard öffnet den Assistenten. Rückgabe: Kennung der neuen Einrichtung oder leer.
func showWizard(owner *wnd) string {
	wz := &wizard{}
	w := newWindow(owner, "Neues Zertifikat", 700, 556, false)
	wz.w = w

	// Kopfzeile
	w.band(0, 0, 700, 64)
	wz.title = w.label(20, 10, 660, 24, "")
	wz.title.white = true
	wz.title.setFont(2)
	wz.sub = w.label(20, 38, 660, 18, "")
	wz.sub.white = true
	w.line(0, 64, 700)

	wz.buildWhat()
	wz.buildFiles()
	wz.buildRenew()
	wz.buildRun()

	// Fußzeile
	w.at = 0
	w.line(0, 506, 700)
	wz.back = w.button(406, 516, 90, 28, "< Zurück", wz.goBack)
	wz.next = w.button(502, 516, 90, 28, "Weiter >", wz.goNext)
	wz.abort = w.button(604, 516, 84, 28, "Abbrechen", func() { w.requestClose() })
	w.defID = wz.next.id
	w.cmd[idCancel] = func(int) { w.requestClose() }
	w.onClose = func() bool { return !wz.running }

	wz.syncMethod()
	wz.syncRenew()
	wz.out.pfxToggle()
	wz.show(wzWhat)
	wz.domains.focus()
	w.showModal()
	return wz.created
}

func (wz *wizard) method() string {
	switch {
	case wz.rWebroot.checked():
		return "webroot"
	case wz.rSelf.checked():
		return "selfsigned"
	}
	return "standalone"
}

// ---------- Seite 1: Namen und Art ----------

func (wz *wizard) buildWhat() {
	w := wz.w
	w.at = wzWhat
	w.label(20, 80, 660, 18, "Domains oder Namen (eine pro Zeile):")
	wz.domains = w.memo(20, 100, 660, 70, false)
	wz.domains.cue("beispiel.de\r\nwww.beispiel.de")
	w.label(20, 182, 660, 18, "Wie soll das Zertifikat entstehen?")
	wz.rStandalone = w.radio(28, 204, 650, 22, "Let’s Encrypt, mit eingebautem Webserver (Port 80 muss aus dem Internet erreichbar sein)", true, wz.syncMethod)
	wz.rWebroot = w.radio(28, 228, 650, 22, "Let’s Encrypt, mit vorhandenem Webserver (z. B. IIS): Die Datei kommt in dessen Webordner", false, wz.syncMethod)
	wz.rSelf = w.radio(28, 252, 650, 22, "Selbstsigniert, ohne Anbieter (für interne Dienste; auch IP-Adressen möglich)", false, wz.syncMethod)
	wz.rStandalone.setChecked(true)

	// je nach Art
	wz.bPort80 = w.button(28, 290, 130, 26, "Port 80 prüfen", wz.checkPort80)
	wz.bPort80.startGroup()
	wz.port80Res = w.label(168, 295, 510, 36, "")
	wz.lWebroot = w.label(20, 288, 660, 18, "Ordner des Webservers (einer pro Zeile, z. B. C:\\inetpub\\wwwroot):")
	wz.lWebroot.startGroup()
	wz.webroot = w.memo(20, 308, 556, 52, false)
	wz.bWebBrowse = w.button(584, 308, 96, 26, "Durchsuchen …", func() {
		if d := pickFolder(w, "Ordner des Webservers wählen", ""); d != "" {
			t := wz.webroot.trimmed()
			if t != "" {
				t += "\n"
			}
			wz.webroot.setText(t + d)
		}
	})
	wz.lDays = w.label(20, 292, 130, 18, "Gültigkeit in Tagen:")
	wz.lDays.startGroup()
	wz.days = w.edit(160, 289, 70, 24, "365")
	wz.hSelf = w.label(20, 324, 660, 54, "Browser und Programme vertrauen selbstsignierten Zertifikaten nicht von sich aus. Man muss sie auf den Geräten als vertrauenswürdig eintragen. Dafür kostet es nichts und braucht kein Internet.")
	wz.hStandalone = w.label(20, 440, 660, 40, "Wildcard-Zertifikate (*.beispiel.de) und Domains ohne erreichbaren Port 80 gibt es im Hauptfenster unter „Wildcard / DNS“.")
	wz.hStandalone.page = wzWhat
}

func (wz *wizard) syncMethod() {
	m := wz.method()
	wz.bPort80.show(m == "standalone")
	wz.port80Res.show(m == "standalone")
	for _, c := range []*ctl{wz.lWebroot, wz.webroot, wz.bWebBrowse} {
		c.show(m == "webroot")
	}
	for _, c := range []*ctl{wz.lDays, wz.days, wz.hSelf} {
		c.show(m == "selfsigned")
	}
	if wz.out != nil {
		wz.out.setChainAllowed(m != "selfsigned")
	}
	if wz.srv != nil {
		wz.syncRenew()
	}
}

func (wz *wizard) checkPort80() {
	ok, msg := checkPort80()
	wz.port80Res.setText(msg)
	if ok {
		wz.port80Res.setColor(0x00008000)
	} else {
		wz.port80Res.setColor(0x000000C0)
	}
	wz.port80Res.setText(msg)
}

// ---------- Seite 2: Dateien ----------

func (wz *wizard) buildFiles() {
	wz.w.at = wzFiles
	wz.out = newOutputsPanel(wz.w, 20, 80, "Das PFX-Passwort wird auf diesem Rechner geschützt gespeichert (damit die automatische Erneuerung die Datei neu bauen kann). Bitte trotzdem notieren: Man braucht es beim Import der PFX-Datei.")
}

// ---------- Seite 3: Erneuerung und Anbieter ----------

func (wz *wizard) buildRenew() {
	w := wz.w
	w.at = wzRenew
	wz.auto = w.check(20, 80, 660, 22, "Automatisch erneuern (Aufgabe in der Windows-Aufgabenplanung)", wz.syncRenew)
	wz.auto.setChecked(true)
	wz.lblTime = w.label(44, 114, 120, 18, "Uhrzeit, täglich:")
	wz.time = w.edit(170, 110, 60, 24, "03:00")
	wz.lblName = w.label(256, 114, 170, 18, "Name der Aufgabe (optional):")
	wz.taskName = w.edit(430, 110, 250, 24, "")
	wz.lblRun = w.label(44, 148, 120, 18, "Ausführen als:")
	wz.rSystem = w.radio(170, 146, 400, 22, "SYSTEM-Konto (empfohlen)", true, wz.syncRenew)
	wz.rUser = w.radio(170, 170, 110, 22, "Benutzerkonto:", false, wz.syncRenew)
	wz.rSystem.setChecked(true)
	wz.user = w.edit(284, 168, 170, 24, "")
	wz.user.startGroup()
	wz.user.cue("DOMÄNE\\Benutzer")
	wz.lblPw = w.label(466, 172, 66, 18, "Passwort:")
	wz.userPw = w.password(534, 168, 146, 24)
	wz.hSystem = w.label(170, 196, 510, 34, "Bei Netzwerkfreigaben als Ziel braucht das SYSTEM-Konto Schreibrechte für das Computerkonto (DOMÄNE\\COMPUTER$).")
	wz.fw = w.check(20, 236, 660, 22, "Port 80 in der Windows-Firewall für die Erneuerung freigeben", nil)
	wz.fw.setChecked(true)
	w.line(20, 268, 660)

	wz.lblSrv = w.label(20, 284, 140, 18, "Zertifikatsanbieter:")
	wz.srv = w.combo(170, 280, 510, []string{"Let’s Encrypt (echte Zertifikate)", "Let’s Encrypt Test (zum Ausprobieren, nicht vertrauenswürdig)", "Eigener ACME-Server …"}, wz.syncRenew)
	wz.lblURL = w.label(20, 316, 140, 18, "Adresse (https):")
	wz.customURL = w.edit(170, 312, 510, 24, "")
	wz.customURL.cue("https://ca.beispiel.de/acme/directory")
	wz.lblMail = w.label(20, 350, 140, 18, "E-Mail-Adresse (optional):")
	wz.email = w.edit(170, 346, 510, 24, "")
	wz.email.cue("Hinweise des Anbieters, z. B. bei Problemen")
	wz.lblBits = w.label(20, 384, 140, 18, "Schlüssellänge:")
	wz.bits = w.combo(170, 380, 200, []string{"RSA 2048 (Standard)", "RSA 3072", "RSA 4096 (langsamer)"}, nil)
	wz.tos = w.check(20, 420, 520, 22, "Ich akzeptiere die Nutzungsbedingungen des Zertifikatsanbieters.", nil)
	wz.tosRead = w.button(548, 417, 132, 26, "Bedingungen lesen", func() { shellOpen("https://letsencrypt.org/repository/") })
}

func (wz *wizard) syncRenew() {
	self := wz.method() == "selfsigned"
	on := wz.auto.checked()
	for _, c := range []*ctl{wz.lblTime, wz.time, wz.lblName, wz.taskName, wz.lblRun, wz.rSystem, wz.rUser, wz.hSystem} {
		c.enable(on)
	}
	user := on && wz.rUser.checked()
	wz.user.enable(user)
	wz.userPw.enable(user)
	wz.lblPw.enable(user)
	wz.fw.show(wz.method() == "standalone")
	wz.fw.enable(on)
	le := !self
	custom := le && wz.srv.comboIndex() == 2
	for _, c := range []*ctl{wz.lblSrv, wz.srv, wz.lblMail, wz.email, wz.tos, wz.tosRead} {
		c.show(le)
	}
	wz.lblURL.show(custom)
	wz.customURL.show(custom)
}

// ---------- Seite 4: Ausstellen ----------

func (wz *wizard) buildRun() {
	w := wz.w
	w.at = wzRun
	wz.summary = w.label(20, 78, 660, 56, "")
	wz.panel = newJobPanel(w, 20, 140, 660, 354, 170)
}

// ---------- Ablauf ----------

func (wz *wizard) show(p int) {
	wz.page = p
	wz.w.setPage(p)
	t := wizardTitles[p]
	wz.title.setText(t[0])
	wz.sub.setText(t[1])
	wz.back.enable(p > wzWhat && p < wzRun)
	wz.back.show(p < wzRun || wz.failed)
	switch p {
	case wzRenew:
		wz.next.setText("Erstellen")
	default:
		wz.next.setText("Weiter >")
	}
	wz.next.show(p < wzRun)
	wz.abort.setText("Abbrechen")
}

func (wz *wizard) goBack() {
	switch wz.page {
	case wzRun:
		wz.failed = false
		wz.show(wzRenew)
	default:
		wz.show(wz.page - 1)
	}
}

func (wz *wizard) goNext() {
	w := wz.w
	switch wz.page {
	case wzWhat:
		if len(lines(wz.domains.text())) == 0 {
			warnBox(w, "Bitte mindestens einen Namen (Domain) eintragen.")
			wz.domains.focus()
			return
		}
		if wz.method() == "webroot" && len(lines(wz.webroot.text())) == 0 {
			warnBox(w, "Bitte den Ordner des Webservers angeben (z. B. C:\\inetpub\\wwwroot).")
			wz.webroot.focus()
			return
		}
		wz.show(wzFiles)
	case wzFiles:
		if msg := wz.out.check(); msg != "" {
			warnBox(w, msg)
			return
		}
		wz.show(wzRenew)
	case wzRenew:
		wz.start()
	}
}

func (wz *wizard) request() CreateRequest {
	ov := wz.out.value()
	days, _ := strconv.Atoi(strings.TrimSpace(wz.days.text()))
	req := CreateRequest{
		Domains: wz.domains.text(), Method: wz.method(), Webroot: wz.webroot.text(), ValidDays: days,
		TargetDir: ov.Dir, FileName: ov.Name, Outputs: ov.Kinds, CertFormat: ov.CertFormat, Password: ov.Password, PfxFormat: ov.PfxFormat,
		Email: wz.email.trimmed(), AutoRenew: wz.auto.checked(), TaskTime: wz.time.trimmed(), TaskName: wz.taskName.trimmed(),
		Firewall: wz.fw.checked(),
	}
	switch wz.srv.comboIndex() {
	case 1:
		req.Server = "staging"
	case 2:
		req.Server, req.CustomURL = "custom", wz.customURL.trimmed()
	default:
		req.Server = "prod"
	}
	switch wz.bits.comboIndex() {
	case 1:
		req.KeyBits = 3072
	case 2:
		req.KeyBits = 4096
	default:
		req.KeyBits = 2048
	}
	if wz.rUser.checked() {
		req.RunAs, req.User, req.UserPassword = "user", wz.user.trimmed(), wz.userPw.text()
	} else {
		req.RunAs = "system"
	}
	return req
}

func (wz *wizard) start() {
	w := wz.w
	req := wz.request()
	if req.Method != "selfsigned" && !wz.tos.checked() {
		warnBox(w, "Bitte die Nutzungsbedingungen des Zertifikatsanbieters akzeptieren (Häkchen setzen).")
		return
	}
	p, err := buildProfile(req)
	if err != nil {
		warnBox(w, err.Error())
		return
	}
	if _, e := os.Stat(filepath.Join(profileDir(p.ID), "profile.json")); e == nil {
		if !askBox(w, "Für diesen Namen gibt es schon eine Einrichtung.\n\nSoll sie ersetzt werden? (Aufgabe, Einstellungen und Zertifikat werden dann neu erstellt.)") {
			return
		}
		req.Replace = true
	}
	if p.Task.Enabled && !plat.IsElevated() {
		warnBox(w, "Für die automatische Erneuerung braucht das Programm Administratorrechte. Bitte das Programm neu starten und die Abfrage bestätigen, oder die automatische Erneuerung abwählen.")
		return
	}

	wz.req = req
	wz.failed = false
	wz.running = true
	wz.summary.setText(summaryText(p))
	wz.show(wzRun)
	wz.title.setText("Zertifikat wird erstellt …")
	wz.abort.enable(false)
	wz.back.show(false)

	job := newJob(p.ID)
	go func() {
		res, err := createProfile(context.Background(), p, req, job)
		job.finish(err, res)
	}()
	wz.panel.start(job, formatRunResult, func(v jobView) {
		wz.running = false
		wz.abort.enable(true)
		if v.State == "ok" {
			wz.created = p.ID
			wz.title.setText("Fertig")
			wz.sub.setText("Das Zertifikat ist eingerichtet")
			wz.abort.setText("Fertig")
			w.defID = wz.abort.id
			wz.abort.focus()
		} else {
			wz.failed = true
			wz.title.setText("Das hat nicht geklappt")
			wz.sub.setText("Die Meldung unten sagt, woran es lag. Mit „Zurück“ lassen sich die Angaben ändern")
			wz.back.show(true)
			wz.back.enable(true)
			wz.abort.setText("Schließen")
		}
	})
}

func summaryText(p *Profile) string {
	var sb strings.Builder
	sb.WriteString("Namen: " + strings.Join(p.Domains, ", ") + "\n")
	switch p.Method {
	case "selfsigned":
		sb.WriteString("Art: selbstsigniert\n")
	case "webroot":
		sb.WriteString("Art: Let’s Encrypt über vorhandenen Webserver\n")
	default:
		sb.WriteString("Art: Let’s Encrypt mit eingebautem Webserver\n")
	}
	sb.WriteString("Ziel: " + p.TargetDir)
	return sb.String()
}
