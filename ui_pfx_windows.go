//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Dialog „PFX umwandeln“: aus PEM-Dateien eine PFX-Datei bauen und umgekehrt.

const (
	pxToPFX = iota + 1
	pxToPEM
)

type pfxDlg struct {
	w *wnd

	// PEM -> PFX
	certs, key   *ctl
	keyPw, pfxPw *ctl
	showPw       *ctl
	algo         *ctl
	result1      *ctl

	// PFX -> PEM
	file, openPw               *ctl
	info                       *ctl
	dir, name                  *ctl
	kCert, kChain, kFull, kKey *ctl
	format                     *ctl
	bSave                      *ctl
	result2                    *ctl
	opened                     *PfxContents
}

func showPfxDialog(owner *wnd) {
	d := &pfxDlg{}
	w := newWindow(owner, "PFX umwandeln", 700, 556, false)
	d.w = w

	w.at = 0
	r1 := w.radio(20, 14, 320, 22, "Zertifikat und Schlüssel  →  PFX-Datei", true, func() { w.setPage(pxToPFX) })
	w.radio(360, 14, 320, 22, "PFX-Datei  →  Zertifikat, Kette und Schlüssel", false, func() { w.setPage(pxToPEM) })
	r1.setChecked(true)
	w.line(0, 46, 700)

	d.buildToPFX()
	d.buildToPEM()

	w.at = 0
	w.line(0, 506, 700)
	closeBtn := w.button(592, 516, 96, 28, "Schließen", func() { w.close() })
	w.defID = closeBtn.id
	w.cmd[idCancel] = func(int) { w.close() }
	w.setPage(pxToPFX)
	w.showModal()
}

// ---------- PEM -> PFX ----------

func (d *pfxDlg) buildToPFX() {
	w := d.w
	w.at = pxToPFX
	w.label(20, 56, 560, 18, "Zertifikat (mit Zwischenzertifikaten, PEM-Text):")
	d.certs = w.memo(20, 76, 560, 96, false)
	w.button(588, 76, 92, 26, "Datei laden …", func() {
		d.loadInto(d.certs, "Zertifikat wählen", true, "Zertifikate (*.crt, *.cer, *.pem)", "*.crt;*.cer;*.pem", "Alle Dateien", "*.*")
	})
	w.label(20, 180, 560, 18, "Privater Schlüssel (PEM-Text):")
	d.key = w.memo(20, 200, 560, 96, false)
	w.button(588, 200, 92, 26, "Datei laden …", func() {
		d.loadInto(d.key, "Schlüssel wählen", false, "Schlüssel (*.key, *.pem)", "*.key;*.pem", "Alle Dateien", "*.*")
	})
	w.label(20, 308, 270, 18, "Passwort des Schlüssels (falls verschlüsselt):")
	d.keyPw = w.password(300, 304, 200, 24)
	w.label(20, 344, 270, 18, "Passwort für die PFX-Datei:")
	d.pfxPw = w.password(300, 340, 200, 24)
	w.button(508, 339, 80, 26, "Zufällig", func() {
		d.pfxPw.setText(generatePassword(16))
		d.showPw.setChecked(true)
		d.pfxPw.showPassword(true)
	})
	d.showPw = w.check(596, 340, 90, 24, "Anzeigen", func() { d.pfxPw.showPassword(d.showPw.checked()) })
	w.label(20, 380, 270, 18, "Verschlüsselung der PFX:")
	d.algo = w.combo(300, 376, 380, []string{"Kompatibel (3DES, für alle Windows-Versionen)", "Modern (AES-256, nur neuere Windows-Versionen)"}, nil)
	d.result1 = w.label(20, 414, 660, 54, "")
	w.button(540, 468, 140, 30, "PFX speichern …", d.savePFX)
}

func (d *pfxDlg) loadInto(target *ctl, title string, multi bool, filter ...string) {
	files := openFiles(d.w, title, multi, filter...)
	if len(files) == 0 {
		return
	}
	var parts []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			warnBox(d.w, "Die Datei „"+f+"“ konnte nicht gelesen werden: "+simplifyOSError(err))
			return
		}
		if len(b) > 1<<20 {
			warnBox(d.w, "Die Datei „"+f+"“ ist zu groß für ein Zertifikat oder einen Schlüssel.")
			return
		}
		parts = append(parts, strings.TrimSpace(string(b)))
	}
	target.setText(strings.Join(parts, "\n"))
}

func (d *pfxDlg) savePFX() {
	format := "compat"
	if d.algo.comboIndex() == 1 {
		format = "aes"
	}
	res, err := pemToPFX([]byte(d.certs.text()), []byte(d.key.text()), d.keyPw.text(), d.pfxPw.text(), format)
	if err != nil {
		d.result1.setColor(0x000000C0)
		d.result1.setText(err.Error())
		return
	}
	def := "zertifikat.pfx"
	if cn := res.Leaf.Subject.CommonName; cn != "" {
		def = strings.NewReplacer("*", "_", ":", "-").Replace(cn) + ".pfx"
	}
	path := saveFile(d.w, "PFX-Datei speichern", def, "pfx", "PFX-Dateien (*.pfx)", "*.pfx", "Alle Dateien", "*.*")
	if path == "" {
		return
	}
	if err := writeUserFile(path, res.PFX); err != nil {
		d.result1.setColor(0x000000C0)
		d.result1.setText(err.Error())
		return
	}
	d.result1.setColor(0x00008000)
	d.result1.setText(fmt.Sprintf("Gespeichert: %s\r\n%d Zertifikat(e), gültig bis %s. Das Passwort bitte notieren.", path, res.Count, res.Leaf.NotAfter.Local().Format("02.01.2006")))
}

// ---------- PFX -> PEM ----------

func (d *pfxDlg) buildToPEM() {
	w := d.w
	w.at = pxToPEM
	w.label(20, 56, 400, 18, "PFX-Datei (.pfx oder .p12):")
	d.file = w.edit(20, 76, 460, 24, "")
	w.button(488, 75, 96, 26, "Durchsuchen …", func() {
		if f := openFiles(d.w, "PFX-Datei wählen", false, "PFX-Dateien (*.pfx, *.p12)", "*.pfx;*.p12", "Alle Dateien", "*.*"); len(f) > 0 {
			d.file.setText(f[0])
			if d.name.trimmed() == "" {
				d.name.setText(strings.TrimSuffix(filepath.Base(f[0]), filepath.Ext(f[0])))
			}
		}
	})
	w.label(20, 112, 75, 18, "Passwort:")
	d.openPw = w.password(100, 108, 200, 24)
	w.button(308, 107, 96, 26, "Öffnen", d.openPFX)
	d.info = w.memo(20, 142, 660, 120, true)

	w.label(20, 276, 660, 18, "Zielordner für die Dateien:")
	d.dir = w.edit(20, 296, 560, 24, "")
	d.dir.cue("z. B. D:\\Zertifikate")
	w.button(588, 295, 92, 26, "Durchsuchen …", func() {
		if f := pickFolder(d.w, "Zielordner wählen", d.dir.trimmed()); f != "" {
			d.dir.setText(f)
		}
	})
	w.label(20, 332, 170, 18, "Dateiname ohne Endung:")
	d.name = w.edit(200, 328, 240, 24, "")
	d.kCert = w.check(20, 364, 320, 22, "Zertifikat", nil)
	d.kChain = w.check(20, 388, 320, 22, "Zwischenzertifikate (Kette)", nil)
	d.kFull = w.check(350, 364, 330, 22, "Zertifikat mit Kette (fullchain)", nil)
	d.kKey = w.check(350, 388, 330, 22, "Privater Schlüssel (.key), unverschlüsselt", nil)
	d.kCert.setChecked(true)
	d.kFull.setChecked(true)
	d.kKey.setChecked(true)
	w.label(20, 424, 170, 18, "Format des Zertifikats:")
	d.format = w.combo(200, 420, 240, []string{".crt (Text)", ".cer (Text)", ".pem (Text)", ".cer (binär, DER)"}, nil)
	d.result2 = w.label(20, 456, 510, 44, "")
	d.bSave = w.button(540, 468, 140, 30, "Speichern", d.savePEM)
	d.bSave.enable(false)
}

func (d *pfxDlg) openPFX() {
	d.opened = nil
	d.bSave.enable(false)
	path := d.file.trimmed()
	if path == "" {
		d.info.setText("Bitte zuerst eine PFX-Datei wählen.")
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		d.info.setText("Die Datei konnte nicht gelesen werden: " + simplifyOSError(err))
		return
	}
	c, err := openPFX(data, d.openPw.text())
	if err != nil {
		d.info.setText(err.Error())
		return
	}
	d.opened = c
	d.bSave.enable(true)
	d.kChain.enable(len(c.Certs) > 1)
	d.kKey.enable(c.Key != nil)
	var sb strings.Builder
	leaf := certInfoFrom(c.Certs[0])
	fmt.Fprintf(&sb, "Zertifikat für: %s\n", strings.Join(leaf.DNSNames, ", "))
	if len(leaf.DNSNames) == 0 {
		fmt.Fprintf(&sb, "Zertifikat für: %s\n", leaf.Subject)
	}
	fmt.Fprintf(&sb, "Ausgestellt von: %s\n", leaf.Issuer)
	fmt.Fprintf(&sb, "Gültig vom %s bis %s\n", leaf.NotBefore.Local().Format("02.01.2006"), leaf.NotAfter.Local().Format("02.01.2006"))
	fmt.Fprintf(&sb, "Fingerabdruck (SHA-256): %s\n", leaf.Fingerprint)
	fmt.Fprintf(&sb, "Zwischen- und Stammzertifikate: %d\n", len(c.Certs)-1)
	if c.Key != nil {
		sb.WriteString("Privater Schlüssel: enthalten")
	} else {
		sb.WriteString("Privater Schlüssel: nicht enthalten")
	}
	d.info.setText(sb.String())
}

func (d *pfxDlg) savePEM() {
	c := d.opened
	if c == nil {
		return
	}
	var kinds []string
	for _, k := range []struct {
		c    *ctl
		kind string
	}{{d.kCert, "cert"}, {d.kChain, "chain"}, {d.kFull, "fullchain"}, {d.kKey, "key"}} {
		if k.c.checked() {
			kinds = append(kinds, k.kind)
		}
	}
	base := d.name.trimmed()
	if base == "" {
		base = strings.TrimSuffix(filepath.Base(d.file.trimmed()), filepath.Ext(d.file.trimmed()))
	}
	files, err := saveConverted(c, d.dir.trimmed(), base, kinds, certFormats[maxInt(d.format.comboIndex(), 0)])
	if err != nil {
		d.result2.setColor(0x000000C0)
		d.result2.setText(err.Error())
		return
	}
	d.result2.setColor(0x00008000)
	d.result2.setText(fmt.Sprintf("%s gespeichert in „%s“.", filesText(len(files)), filepath.Dir(files[0])))
}
