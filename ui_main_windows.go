//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"unsafe"
)

const (
	miNew      = 9001
	miWild     = 9002
	miPfx      = 9003
	miRefresh  = 9004
	miQuit     = 9005
	miAbout    = 9006
	miLog      = 9007
	miData     = 9008
	miWeb      = 9009
	projectURL = "https://github.com/ddzhan19/certbumblebee"
)

type mainWin struct {
	w       *wnd
	list    *ctl
	det     *ctl
	status  *ctl
	bRenew  *ctl
	bForce  *ctl
	bTask   *ctl
	bLog    *ctl
	bFolder *ctl
	bDelete *ctl
	ps      []ProfileView
	loading bool
	pending string // Kennung, die nach dem Laden ausgewählt werden soll
}

// runNativeUI öffnet das Hauptfenster und kehrt zurück, wenn es geschlossen wurde.
func runNativeUI() int {
	uiInit()
	m := newMainWin()
	if m == nil {
		showError(appName, "Das Programmfenster konnte nicht geöffnet werden.")
		return 1
	}
	appLogGlobal("Programmfenster geöffnet (Windows-Oberfläche)")
	m.w.center()
	_, _, _ = pShowWindow.Call(uintptr(m.w.hwnd), swShow)
	_, _, _ = pSetForegroundWindow.Call(uintptr(m.w.hwnd))
	m.refresh("")
	runLoop(func() bool { return false })
	return 0
}

func newMainWin() *mainWin {
	w := newWindow(nil, appName, 920, 570, true)
	if w == nil {
		return nil
	}
	w.resizable = true
	w.minW, w.minH = 800, 500
	m := &mainWin{w: w}
	m.buildMenu()

	w.button(12, 12, 150, 30, "Neues Zertifikat …", func() { m.newCert() })
	w.button(170, 12, 150, 30, "Wildcard / DNS …", func() { m.wild() })
	w.button(328, 12, 150, 30, "PFX umwandeln …", func() { m.pfx() })
	rb := w.button(920-12-120, 12, 120, 30, "Aktualisieren", func() { m.refresh("") })
	rb.anchor = anchorR

	m.list = w.list(12, 54, 896, 226, true,
		[]string{"Namen", "Art", "Gültig bis", "Noch", "Erneuerung", "Zustand"},
		[]int{250, 150, 90, 70, 150, 160})
	m.list.anchor = anchorL | anchorT | anchorR | anchorB
	m.list.onSelect(m.onSelect)
	m.list.onActivate(m.openFolder)

	m.det = w.list(12, 290, 896, 178, false, []string{"Eigenschaft", "Wert"}, []int{190, 680})
	m.det.anchor = anchorL | anchorR | anchorB

	by := 478
	m.bRenew = w.button(12, by, 130, 28, "Jetzt erneuern", func() { m.renew(false) })
	m.bForce = w.button(150, by, 150, 28, "Erneuern erzwingen", func() { m.renew(true) })
	m.bTask = w.button(308, by, 130, 28, "Aufgabe testen", m.testTask)
	m.bLog = w.button(446, by, 100, 28, "Protokoll …", m.showLog)
	m.bFolder = w.button(554, by, 120, 28, "Ordner öffnen", m.openFolder)
	m.bDelete = w.button(920-12-110, by, 110, 28, "Entfernen …", m.remove)
	for _, b := range []*ctl{m.bRenew, m.bForce, m.bTask, m.bLog, m.bFolder, m.bDelete} {
		b.anchor = anchorL | anchorB
	}
	m.bDelete.anchor = anchorR | anchorB

	m.status = w.statusBar()
	w.cmd[idCancel] = func(int) {}
	w.onKey = func(vk int) bool {
		switch {
		case vk == vkF5:
			m.refresh("")
			return true
		case vk == 'N' && keyDown(vkControl):
			m.newCert()
			return true
		case vk == vkDelete && m.cur() != nil && focusIs(m.list):
			m.remove()
			return true
		}
		return false
	}
	m.updateButtons()
	return m
}

func focusIs(c *ctl) bool {
	f, _, _ := pGetFocus.Call()
	return f == uintptr(c.hwnd)
}

func (m *mainWin) buildMenu() {
	add := func(menu uintptr, id int, text string) {
		_, _, _ = pAppendMenu.Call(menu, mfString, uintptr(id), uintptr(unsafe.Pointer(u16(text))))
	}
	sep := func(menu uintptr) { _, _, _ = pAppendMenu.Call(menu, mfSeparator, 0, 0) }
	bar, _, _ := pCreateMenu.Call()
	file, _, _ := pCreatePopupMenu.Call()
	add(file, miNew, "&Neues Zertifikat …\tStrg+N")
	add(file, miWild, "&Wildcard / DNS …")
	add(file, miPfx, "&PFX umwandeln …")
	sep(file)
	add(file, miRefresh, "&Aktualisieren\tF5")
	sep(file)
	add(file, miQuit, "&Beenden")
	help, _, _ := pCreatePopupMenu.Call()
	add(help, miLog, "&Protokoll anzeigen …")
	add(help, miData, "&Datenordner öffnen")
	add(help, miWeb, "Projektseite im &Browser")
	sep(help)
	add(help, miAbout, "&Über Certbumblebee …")
	_, _, _ = pAppendMenu.Call(bar, mfPopup, file, uintptr(unsafe.Pointer(u16("&Datei"))))
	_, _, _ = pAppendMenu.Call(bar, mfPopup, help, uintptr(unsafe.Pointer(u16("&Hilfe"))))
	_, _, _ = pSetMenu.Call(uintptr(m.w.hwnd), bar)
	m.w.hasMenu = true
	rc := rect{0, 0, int32(m.w.px(m.w.cw)), int32(m.w.px(m.w.ch))}
	m.w.adjust(&rc)
	_, _, _ = pSetWindowPos.Call(uintptr(m.w.hwnd), 0, 0, 0, uintptr(rc.Right-rc.Left), uintptr(rc.Bottom-rc.Top), swpNoMove|swpNoZOrder|swpNoActivate)

	m.w.cmd[miNew] = func(int) { m.newCert() }
	m.w.cmd[miWild] = func(int) { m.wild() }
	m.w.cmd[miPfx] = func(int) { m.pfx() }
	m.w.cmd[miRefresh] = func(int) { m.refresh("") }
	m.w.cmd[miQuit] = func(int) { m.w.requestClose() }
	m.w.cmd[miLog] = func(int) { showLogDialog(m.w, "Protokoll", "") }
	m.w.cmd[miData] = func(int) { shellOpen(dataDir()) }
	m.w.cmd[miWeb] = func(int) { shellOpen(projectURL) }
	m.w.cmd[miAbout] = func(int) {
		infoBox(m.w, fmt.Sprintf("%s %s\n\nProgrammiert von %s\n\nZertifikate holen, erstellen und automatisch erneuern.\n%s", appName, appVersion, appAuthor, projectURL))
	}
}

// ---------- Liste ----------

// refresh lädt die Übersicht im Hintergrund (die Abfrage der Aufgabenplanung kann etwas dauern).
func (m *mainWin) refresh(selectID string) {
	if selectID != "" {
		m.pending = selectID
	} else if p := m.cur(); p != nil && m.pending == "" {
		m.pending = p.ID
	}
	if m.loading {
		return
	}
	m.loading = true
	m.status.setStatus("Lade Übersicht …")
	go func() {
		ps := listProfiles()
		uiPost(func() {
			m.loading = false
			m.setProfiles(ps)
		})
	}()
}

func (m *mainWin) cur() *ProfileView {
	r := m.list.selectedRow()
	if r < 0 || r >= len(m.ps) {
		return nil
	}
	return &m.ps[r]
}

func methodText(p *ProfileView) string {
	switch p.Method {
	case "selfsigned":
		return "Selbstsigniert"
	case "webroot":
		return "Let’s Encrypt (Webordner)"
	}
	if p.ServerKind == "staging" {
		return "Let’s Encrypt Test"
	}
	if p.ServerKind == "custom" {
		return "Eigener ACME-Server"
	}
	return "Let’s Encrypt"
}

func stateText(p *ProfileView) string {
	switch {
	case p.Cert == nil && p.LastResult == "fehler":
		return "Fehler beim Ausstellen"
	case p.Cert == nil:
		return "Kein Zertifikat"
	case p.DaysLeft < 0:
		return "Abgelaufen"
	case p.LastResult == "fehler":
		return "Letzte Erneuerung fehlgeschlagen"
	case p.Task.Enabled && !p.Task.Exists:
		return "Aufgabe fehlt"
	case !p.TargetFound:
		return "Datei im Zielordner fehlt"
	case p.DaysLeft <= 14:
		return "Läuft bald ab"
	}
	return "In Ordnung"
}

func daysText(n int) string {
	switch {
	case n < 0:
		return "abgelaufen"
	case n == 1:
		return "1 Tag"
	}
	return fmt.Sprintf("%d Tage", n)
}

func (m *mainWin) setProfiles(ps []ProfileView) {
	m.ps = ps
	m.list.clearRows()
	want := m.pending
	m.pending = ""
	sel := -1
	for i := range ps {
		p := &ps[i]
		until, left := "–", "–"
		if p.Cert != nil {
			until = p.Cert.NotAfter.Local().Format("02.01.2006")
			left = daysText(p.DaysLeft)
		}
		renew := "von Hand"
		if p.Task.Enabled {
			renew = "täglich " + p.Task.Time
		}
		names := strings.Join(p.Domains, ", ")
		if names == "" {
			names = p.ID
		}
		m.list.addRow(names, methodText(p), until, left, renew, stateText(p))
		if p.ID == want {
			sel = i
		}
	}
	if len(ps) == 0 {
		m.list.addRow("(noch nichts eingerichtet)")
	} else if sel < 0 {
		sel = 0
	}
	if sel >= 0 {
		m.list.selectRow(sel)
	}
	m.onSelect()
	switch n := len(ps); n {
	case 0:
		m.status.setStatus("Keine Einrichtungen · " + adminText())
	case 1:
		m.status.setStatus("1 Einrichtung · " + adminText())
	default:
		m.status.setStatus(fmt.Sprintf("%d Einrichtungen · %s", n, adminText()))
	}
}

func adminText() string {
	if plat.IsElevated() {
		return "Läuft mit Administratorrechten"
	}
	return "Ohne Administratorrechte (Aufgaben lassen sich nicht anlegen)"
}

func (m *mainWin) updateButtons() {
	p := m.cur()
	has := p != nil
	m.bRenew.enable(has)
	m.bForce.enable(has)
	m.bTask.enable(has && p.Task.Enabled)
	m.bLog.enable(has)
	m.bFolder.enable(has)
	m.bDelete.enable(has)
}

func (m *mainWin) onSelect() {
	m.updateButtons()
	m.det.clearRows()
	p := m.cur()
	if p == nil {
		if len(m.ps) == 0 {
			m.det.addRow("So fängt es an", "„Neues Zertifikat …“ holt ein Zertifikat von Let’s Encrypt oder erstellt ein selbstsigniertes.")
			m.det.addRow("Wildcard und DNS", "„Wildcard / DNS …“ ist für *.beispiel.de und für Domains ohne erreichbaren Port 80.")
			m.det.addRow("Vorhandene Dateien", "„PFX umwandeln …“ macht aus PEM-Dateien eine PFX-Datei und umgekehrt.")
		}
		return
	}
	add := func(k, v string) {
		if v != "" {
			m.det.addRow(k, v)
		}
	}
	add("Namen", strings.Join(p.Domains, ", "))
	add("Art", methodText(p))
	if p.Method == "webroot" {
		add("Webordner", strings.Join(p.Webroot, "; "))
	}
	if c := p.Cert; c != nil {
		add("Gültig", fmt.Sprintf("%s bis %s (%s)", c.NotBefore.Local().Format("02.01.2006"), c.NotAfter.Local().Format("02.01.2006"), daysText(p.DaysLeft)))
		add("Ausgestellt von", c.Issuer)
		if c.KeyBits > 0 {
			add("Schlüssel", fmt.Sprintf("RSA %d", c.KeyBits))
		}
		add("Fingerabdruck (SHA-256)", c.Fingerprint)
	}
	for _, f := range p.Files {
		t := f.Path
		if !f.Found {
			t += "   (fehlt!)"
		}
		add(f.Label, t)
	}
	if p.Task.Enabled {
		t := fmt.Sprintf("täglich um %s Uhr, Konto %s – Aufgabe „%s“", p.Task.Time, p.Task.RunAs, p.Task.Name)
		if !p.Task.Exists {
			t += "   (in der Aufgabenplanung nicht gefunden!)"
		}
		add("Automatische Erneuerung", t)
	} else {
		add("Automatische Erneuerung", "aus (von Hand mit „Jetzt erneuern“)")
	}
	if p.LastRun != nil {
		add("Letzter Lauf", relTime(*p.LastRun)+" – "+lastResultText(p.LastResult))
	}
	add("Meldung", p.LastMessage)
}

func lastResultText(r string) string {
	switch r {
	case "nicht-faellig":
		return "noch nicht fällig"
	case "fehler":
		return "Fehler"
	}
	return r
}

// ---------- Aktionen ----------

func (m *mainWin) newCert() {
	if id := showWizard(m.w); id != "" {
		m.refresh(id)
	}
}

func (m *mainWin) wild() { showWildDialog(m.w) }

func (m *mainWin) pfx() { showPfxDialog(m.w) }

func (m *mainWin) renew(force bool) {
	p := m.cur()
	if p == nil {
		return
	}
	if force && !askBox(m.w, "Das Zertifikat wird jetzt neu bestellt, auch wenn es noch lange gültig ist.\n\nLet’s Encrypt begrenzt die Zahl der Bestellungen (zum Ausprobieren eignet sich „Let’s Encrypt Test“). Trotzdem neu bestellen?") {
		return
	}
	id := p.ID
	job := newJob(id)
	go func() {
		res, err := renewProfile(context.Background(), id, force, job)
		job.finish(err, res)
	}()
	title := "Zertifikat erneuern"
	if force {
		title = "Zertifikat neu bestellen"
	}
	showJobDialog(m.w, title, "„"+strings.Join(p.Domains, ", ")+"“", job, formatRunResult)
	m.refresh(id)
}

func (m *mainWin) testTask() {
	p := m.cur()
	if p == nil || !p.Task.Enabled {
		return
	}
	id := p.ID
	job := newJob(id)
	go func() {
		res, err := testTask(id, job)
		job.finish(err, res)
	}()
	showJobDialog(m.w, "Aufgabe testen", "Die Aufgabe „"+p.Task.Name+"“ wird gestartet. So zeigt sich, ob das Konto der Aufgabe den Zielordner erreicht.", job, formatRunResult)
	m.refresh(id)
}

func (m *mainWin) showLog() {
	if p := m.cur(); p != nil {
		showLogDialog(m.w, "Protokoll – "+strings.Join(p.Domains, ", "), p.ID)
	}
}

func (m *mainWin) openFolder() {
	p := m.cur()
	if p == nil {
		return
	}
	if _, err := os.Stat(p.TargetDir); err != nil {
		warnBox(m.w, "Der Zielordner „"+p.TargetDir+"“ ist nicht erreichbar.")
		return
	}
	shellOpen(p.TargetDir)
}

func (m *mainWin) remove() {
	p := m.cur()
	if p == nil {
		return
	}
	if !askBox(m.w, "Die Einrichtung für\n\n"+strings.Join(p.Domains, "\n")+"\n\nwird entfernt, samt Aufgabe in der Aufgabenplanung und Firewall-Regel.\nDie Dateien im Zielordner bleiben erhalten.\n\nWirklich entfernen?") {
		return
	}
	id := p.ID
	job := newJob(id)
	job.Declare("entfernen", "Aufgabe, Regeln und Einrichtung entfernen")
	go func() {
		job.Step("entfernen", "Aufgabe, Regeln und Einrichtung entfernen")
		err := deleteProfile(id, job)
		if err != nil {
			job.Fail("entfernen", err.Error())
		} else {
			job.Ok("entfernen", "entfernt")
		}
		job.finish(err, nil)
	}()
	showJobDialog(m.w, "Einrichtung entfernen", "„"+strings.Join(p.Domains, ", ")+"“", job, func(any) string {
		return "Die Einrichtung wurde entfernt. Die Dateien im Zielordner sind erhalten geblieben."
	})
	m.pending = ""
	m.refresh("")
}

// showLogDialog zeigt die letzten Zeilen des Protokolls (id leer = alles).
func showLogDialog(owner *wnd, title, id string) {
	d := newWindow(owner, title, 780, 500, false)
	memo := d.memo(12, 12, 756, 436, true)
	load := func() {
		lines := tailLog(id, 300)
		if len(lines) == 0 {
			memo.setText("Noch keine Einträge.")
			return
		}
		memo.setText(strings.Join(lines, "\n"))
		// ans Ende scrollen
		sendMsg(memo.hwnd, emSetSel, ^uintptr(0), ^uintptr(0))
		sendMsg(memo.hwnd, emScrollCaret, 0, 0)
	}
	d.button(560, 460, 100, 30, "Neu laden", load)
	closeBtn := d.button(668, 460, 100, 30, "Schließen", func() { d.close() })
	d.defID = closeBtn.id
	d.cmd[idCancel] = func(int) { d.close() }
	load()
	d.showModal()
}
