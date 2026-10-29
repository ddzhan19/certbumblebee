//go:build windows

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"crypto/x509"
)

// Dialog „Wildcard / DNS“: Bestätigung per DNS-Eintrag, den der Anwender selbst anlegt.

const (
	wdInfo = iota + 1
	wdFiles
	wdPrep
	wdDNS
	wdRun
)

var wildTitles = map[int][2]string{
	wdInfo:  {"Wildcard- oder DNS-Zertifikat", "Bestätigung der Domain über einen DNS-Eintrag"},
	wdFiles: {"Wohin sollen die Dateien?", "Zielordner und gewünschte Dateien festlegen"},
	wdPrep:  {"Bestellung wird vorbereitet …", ""},
	wdDNS:   {"DNS-Einträge anlegen", "Beweisen Sie, dass die Domain Ihnen gehört"},
	wdRun:   {"Zertifikat wird ausgestellt …", ""},
}

type flatRecord struct{ name, value, domains string }

type wildIssued struct{ chain, key, csr []byte }

type wildDone struct {
	files   []string
	leaf    *x509.Certificate
	staging bool
}

type wildDlg struct {
	w                 *wnd
	page              int
	title, sub        *ctl
	back, next, abort *ctl
	domains           *ctl
	srv, customURL    *ctl
	email, bits       *ctl
	tos               *ctl
	lblURL            *ctl
	out               *outputsPanel
	prep, run         *jobPanel
	recs              *ctl
	recInfo           *ctl
	bCheck            *ctl
	sess              *WildSession
	flat              []flatRecord
	allVisible        bool
	checked           bool
	issued            *wildIssued
	running, failed   bool
}

func showWildDialog(owner *wnd) {
	d := &wildDlg{}
	w := newWindow(owner, "Wildcard / DNS", 700, 556, false)
	d.w = w
	w.band(0, 0, 700, 64)
	d.title = w.label(20, 10, 660, 24, "")
	d.title.white = true
	d.title.setFont(2)
	d.sub = w.label(20, 38, 660, 18, "")
	d.sub.white = true
	w.line(0, 64, 700)

	d.buildInfo()
	w.at = wdFiles
	d.out = newOutputsPanel(w, 20, 80, "Das PFX-Passwort wird nirgends gespeichert. Bitte notieren: Man braucht es beim Import der PFX-Datei.")
	w.at = wdPrep
	d.prep = newJobPanel(w, 20, 78, 660, 410, 190)
	d.buildDNS()
	w.at = wdRun
	d.run = newJobPanel(w, 20, 78, 660, 410, 190)

	w.at = 0
	w.line(0, 506, 700)
	d.back = w.button(406, 516, 90, 28, "< Zurück", d.goBack)
	d.next = w.button(502, 516, 90, 28, "Weiter >", d.goNext)
	d.abort = w.button(604, 516, 84, 28, "Abbrechen", func() { w.requestClose() })
	w.defID = d.next.id
	w.cmd[idCancel] = func(int) { w.requestClose() }
	w.onClose = func() bool {
		if d.running {
			return false
		}
		if d.issued != nil && d.page != wdRun {
			return askBox(w, "Das Zertifikat wurde ausgestellt, aber noch nicht gespeichert. Der private Schlüssel geht beim Schließen verloren.\n\nTrotzdem schließen?")
		}
		return true
	}
	d.out.pfxToggle()
	d.syncServer()
	d.show(wdInfo)
	d.domains.focus()
	w.showModal()
}

func (d *wildDlg) buildInfo() {
	w := d.w
	w.at = wdInfo
	w.label(20, 78, 660, 70, "Für ein Wildcard-Zertifikat (*.beispiel.de) und für Domains, die von außen nicht über Port 80 erreichbar sind, bestätigt Let’s Encrypt die Domain über einen DNS-Eintrag. Diesen Eintrag legen Sie bei Ihrem DNS-Anbieter selbst an. Das Programm zeigt ihn an und prüft ihn. Eine automatische Erneuerung gibt es dafür nicht: Etwa alle 60 Tage muss der Vorgang wiederholt werden.")
	w.label(20, 156, 660, 18, "Domains (eine pro Zeile):")
	d.domains = w.memo(20, 176, 660, 66, false)
	d.domains.cue("*.beispiel.de\r\nbeispiel.de")
	w.label(20, 248, 660, 18, "Die Hauptdomain (beispiel.de) gehört nicht zur Wildcard und muss extra eingetragen werden.")
	w.label(20, 286, 140, 18, "Zertifikatsanbieter:")
	d.srv = w.combo(170, 282, 510, []string{"Let’s Encrypt (echte Zertifikate)", "Let’s Encrypt Test (zum Ausprobieren, nicht vertrauenswürdig)", "Eigener ACME-Server …"}, d.syncServer)
	d.lblURL = w.label(20, 318, 140, 18, "Adresse (https):")
	d.customURL = w.edit(170, 314, 510, 24, "")
	d.customURL.cue("https://ca.beispiel.de/acme/directory")
	w.label(20, 352, 140, 18, "E-Mail (optional):")
	d.email = w.edit(170, 348, 510, 24, "")
	w.label(20, 386, 140, 18, "Schlüssellänge:")
	d.bits = w.combo(170, 382, 200, []string{"RSA 2048 (Standard)", "RSA 3072", "RSA 4096 (langsamer)"}, nil)
	d.tos = w.check(20, 424, 520, 22, "Ich akzeptiere die Nutzungsbedingungen des Zertifikatsanbieters.", nil)
	w.button(548, 421, 132, 26, "Bedingungen lesen", func() { shellOpen("https://letsencrypt.org/repository/") })
}

func (d *wildDlg) syncServer() {
	custom := d.srv.comboIndex() == 2
	d.lblURL.show(custom)
	d.customURL.show(custom)
}

func (d *wildDlg) buildDNS() {
	w := d.w
	w.at = wdDNS
	w.label(20, 78, 660, 68, "Legen Sie bei Ihrem DNS-Anbieter für jede Zeile einen TXT-Eintrag an: Name und Wert genau wie angezeigt. Gehören mehrere Werte zum selben Namen, legen Sie mehrere TXT-Einträge mit diesem Namen an. Der DNS-Anbieter braucht nach dem Speichern oft einige Minuten.")
	d.recs = w.list(20, 150, 660, 170, true, []string{"Name (TXT)", "Wert", "Prüfung"}, []int{250, 280, 110})
	d.recs.onActivate(func() { d.copyCell(1) })
	w.button(20, 328, 120, 28, "Name kopieren", func() { d.copyCell(0) })
	w.button(148, 328, 120, 28, "Wert kopieren", func() { d.copyCell(1) })
	w.button(276, 328, 120, 28, "Alles kopieren", d.copyAll)
	d.bCheck = w.button(404, 328, 150, 28, "Einträge prüfen", d.checkDNS)
	d.recInfo = w.label(20, 368, 660, 54, "")
	w.label(20, 440, 660, 40, "Dieses Fenster bitte offen lassen. Der private Schlüssel existiert nur hier, bis die Dateien gespeichert sind.")
}

// ---------- Ablauf ----------

func (d *wildDlg) show(p int) {
	d.page = p
	d.w.setPage(p)
	t := wildTitles[p]
	d.title.setText(t[0])
	d.sub.setText(t[1])
	d.back.show(p > wdInfo && p != wdPrep && p != wdRun || d.failed)
	d.back.enable(true)
	d.next.show(p == wdInfo || p == wdFiles || p == wdDNS)
	switch p {
	case wdFiles:
		d.next.setText("Weiter >")
	case wdDNS:
		d.next.setText("Bestätigen")
	default:
		d.next.setText("Weiter >")
	}
	d.abort.setText("Abbrechen")
	d.abort.enable(!d.running)
}

func (d *wildDlg) goBack() {
	switch d.page {
	case wdPrep, wdDNS:
		d.failed = false
		d.sess = nil
		d.show(wdFiles)
	case wdRun:
		d.failed = false
		if d.issued != nil { // nur das Speichern ist schiefgegangen
			d.show(wdFiles)
			return
		}
		d.sess = nil
		d.show(wdInfo)
	default:
		d.show(d.page - 1)
	}
}

func (d *wildDlg) goNext() {
	w := d.w
	switch d.page {
	case wdInfo:
		if _, err := normalizeWildDomains(d.domains.text()); err != nil {
			warnBox(w, err.Error())
			d.domains.focus()
			return
		}
		if !d.tos.checked() {
			warnBox(w, "Bitte die Nutzungsbedingungen des Zertifikatsanbieters akzeptieren (Häkchen setzen).")
			return
		}
		d.show(wdFiles)
	case wdFiles:
		if msg := d.out.check(); msg != "" {
			warnBox(w, msg)
			return
		}
		if d.issued != nil {
			d.save()
			return
		}
		d.prepare()
	case wdDNS:
		d.verify()
	}
}

func (d *wildDlg) wildRequest() WildRequest {
	r := WildRequest{Domains: d.domains.text(), Email: d.email.trimmed()}
	switch d.srv.comboIndex() {
	case 1:
		r.Server = "staging"
	case 2:
		r.Server, r.CustomURL = "custom", d.customURL.trimmed()
	default:
		r.Server = "prod"
	}
	switch d.bits.comboIndex() {
	case 1:
		r.KeyBits = 3072
	case 2:
		r.KeyBits = 4096
	default:
		r.KeyBits = 2048
	}
	return r
}

// prepare legt Konto und Bestellung an und holt die nötigen DNS-Einträge.
func (d *wildDlg) prepare() {
	req := d.wildRequest()
	d.running, d.failed = true, false
	d.show(wdPrep)
	d.back.show(false)
	d.abort.enable(false)
	job := newJob("wild")
	go func() {
		s, err := startWild(context.Background(), req, job)
		job.finish(err, s)
	}()
	d.prep.start(job, func(any) string { return "Bestellung angelegt." }, func(v jobView) {
		d.running = false
		if v.State == "ok" {
			d.sess, _ = v.Result.(*WildSession)
			d.fillRecords()
			d.show(wdDNS)
			return
		}
		d.failed = true
		d.title.setText("Das hat nicht geklappt")
		d.back.show(true)
		d.abort.enable(true)
	})
}

func (d *wildDlg) fillRecords() {
	d.recs.clearRows()
	d.flat = nil
	d.checked, d.allVisible = false, false
	for _, r := range d.sess.Records {
		for _, v := range r.Values {
			dom := strings.Join(r.Domains, ", ")
			d.flat = append(d.flat, flatRecord{r.Name, v, dom})
			d.recs.addRow(r.Name, v, "noch nicht geprüft")
		}
	}
	if len(d.flat) > 0 {
		d.recs.selectRow(0)
	}
	d.recInfo.setText("Tipp: Bei manchen DNS-Anbietern genügt als Name nur der vordere Teil (z. B. „_acme-challenge“), die Domain hängt der Anbieter selbst an.")
}

func (d *wildDlg) copyCell(col int) {
	r := d.recs.selectedRow()
	if r < 0 || r >= len(d.flat) {
		return
	}
	v := d.flat[r].name
	if col == 1 {
		v = d.flat[r].value
	}
	if setClipboardText(d.w.hwnd, v) {
		d.recInfo.setText("In die Zwischenablage kopiert: " + v)
	}
}

func (d *wildDlg) copyAll() {
	var sb strings.Builder
	for _, f := range d.flat {
		fmt.Fprintf(&sb, "TXT\t%s\t%s\r\n", f.name, f.value)
	}
	if setClipboardText(d.w.hwnd, sb.String()) {
		d.recInfo.setText("Alle Einträge stehen in der Zwischenablage (Typ, Name, Wert).")
	}
}

func (d *wildDlg) checkDNS() {
	if d.sess == nil {
		return
	}
	d.bCheck.enable(false)
	d.recInfo.setText("Prüfe …")
	sess := d.sess
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		res := sess.CheckDNS(ctx)
		uiPost(func() {
			d.bCheck.enable(true)
			if d.sess != sess {
				return
			}
			d.applyCheck(res)
		})
	}()
}

func (d *wildDlg) applyCheck(res []DNSCheck) {
	row := 0
	all := true
	unknown := false
	for _, c := range res {
		for _, v := range c.Record.Values {
			var state string
			switch {
			case c.Err != nil:
				state = "nicht prüfbar"
				unknown, all = true, false
			case containsKind(c.Found, v):
				state = "sichtbar"
			default:
				state = "fehlt"
				all = false
			}
			d.recs.setCell(row, 2, state)
			row++
		}
	}
	d.checked, d.allVisible = true, all
	switch {
	case all:
		d.recInfo.setText("Alle Einträge sind von außen sichtbar. Sie können die Bestätigung jetzt starten.")
	case unknown:
		d.recInfo.setText("Die DNS-Abfrage ist von diesem Rechner aus nicht möglich (Proxy oder Firewall?). Sie können die Bestätigung trotzdem starten, wenn die Einträge angelegt sind.")
	default:
		d.recInfo.setText("Mindestens ein Eintrag ist noch nicht sichtbar. Bitte kurz warten und erneut prüfen.")
	}
}

func (d *wildDlg) verify() {
	if d.sess == nil {
		return
	}
	if !d.allVisible {
		q := "Die Einträge wurden noch nicht als sichtbar bestätigt.\n\nWenn die Bestätigung jetzt scheitert, ist diese Bestellung verbraucht und Sie müssen mit neuen Werten von vorn beginnen.\n\nTrotzdem starten?"
		if !d.checked {
			q = "Sie haben die Einträge noch nicht geprüft.\n\nWenn die Bestätigung scheitert, ist diese Bestellung verbraucht und Sie müssen mit neuen Werten von vorn beginnen.\n\nTrotzdem starten?"
		}
		if !askBox(d.w, q) {
			return
		}
	}
	sess := d.sess
	sv := d.out.value()
	save := WildSave{TargetDir: sv.Dir, FileName: sv.Name, Outputs: sv.Kinds, CertFormat: sv.CertFormat, Password: sv.Password, PfxFormat: sv.PfxFormat}
	d.running, d.failed = true, false
	d.show(wdRun)
	d.back.show(false)
	d.abort.enable(false)
	job := newJob("wild")
	job.Declare("pruefung", "Domains bestätigen")
	job.Declare("zertifikat", "Zertifikat abholen")
	job.Declare("speichern", "Dateien speichern")
	go func() {
		ctx := context.Background()
		if err := sess.Verify(ctx, job); err != nil {
			job.finish(err, nil)
			return
		}
		chain, key, csr, err := sess.Finish(ctx, job)
		if err != nil {
			job.finish(err, nil)
			return
		}
		iss := &wildIssued{chain, key, csr}
		uiPost(func() { d.issued = iss })
		r, err := saveStep(job, sess, iss, save)
		job.finish(err, r)
	}()
	d.watchRun(job, sess)
}

// save speichert ein bereits ausgestelltes Zertifikat noch einmal (z. B. in einen anderen Ordner).
func (d *wildDlg) save() {
	sv := d.out.value()
	save := WildSave{TargetDir: sv.Dir, FileName: sv.Name, Outputs: sv.Kinds, CertFormat: sv.CertFormat, Password: sv.Password, PfxFormat: sv.PfxFormat}
	sess, iss := d.sess, d.issued
	d.running, d.failed = true, false
	d.show(wdRun)
	d.back.show(false)
	d.abort.enable(false)
	job := newJob("wild")
	job.Declare("speichern", "Dateien speichern")
	go func() {
		r, err := saveStep(job, sess, iss, save)
		job.finish(err, r)
	}()
	d.watchRun(job, sess)
}

func saveStep(job *Job, sess *WildSession, iss *wildIssued, save WildSave) (any, error) {
	job.Step("speichern", "Dateien speichern")
	files, err := saveWildResult(sess.Domains, iss.chain, iss.key, iss.csr, save)
	if err != nil {
		job.Fail("speichern", err.Error())
		return nil, uerr("Das Zertifikat wurde ausgestellt, aber die Dateien konnten nicht gespeichert werden: "+err.Error()+"\n\nMit „Zurück“ lässt sich ein anderer Ordner wählen. Der Schlüssel bleibt bis dahin in diesem Fenster erhalten.", "")
	}
	job.Ok("speichern", fmt.Sprintf("%s gespeichert", filesText(len(files))))
	certs, _ := parseCertsPEM(iss.chain)
	return &wildDone{files: files, leaf: certs[0], staging: sess.ServerKind == "staging"}, nil
}

func (d *wildDlg) watchRun(job *Job, sess *WildSession) {
	d.run.start(job, formatWildDone, func(v jobView) {
		d.running = false
		d.abort.enable(true)
		if v.State == "ok" {
			d.issued = nil
			d.title.setText("Fertig")
			d.sub.setText("Das Zertifikat ist ausgestellt und gespeichert")
			d.abort.setText("Fertig")
			d.w.defID = d.abort.id
			d.abort.focus()
			return
		}
		d.failed = true
		d.title.setText("Das hat nicht geklappt")
		d.sub.setText("")
		d.back.show(true)
		if d.issued != nil {
			d.back.setText("< Zurück")
		} else {
			d.back.setText("Von vorn")
		}
		d.abort.setText("Schließen")
	})
}

func formatWildDone(res any) string {
	r, ok := res.(*wildDone)
	if !ok {
		return "Fertig."
	}
	var sb strings.Builder
	sb.WriteString("Das Zertifikat wurde ausgestellt und gespeichert.\n")
	fmt.Fprintf(&sb, "\nNamen: %s", strings.Join(r.leaf.DNSNames, ", "))
	fmt.Fprintf(&sb, "\nGültig bis: %s", r.leaf.NotAfter.Local().Format("02.01.2006"))
	sb.WriteString("\n\nDateien:")
	for _, f := range r.files {
		sb.WriteString("\n  " + f)
	}
	sb.WriteString("\n\nEine automatische Erneuerung gibt es hierfür nicht. Bitte den Vorgang rechtzeitig wiederholen (spätestens in etwa 60 Tagen). Die TXT-Einträge dürfen jetzt gelöscht werden.")
	if r.staging {
		sb.WriteString("\n\nAchtung: Das ist ein Testzertifikat. Browser und Server vertrauen ihm nicht.")
	}
	return sb.String()
}
