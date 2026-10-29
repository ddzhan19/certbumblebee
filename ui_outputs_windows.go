//go:build windows

package main

import "strings"

// outputsPanel fragt ab, wohin die Dateien kommen und welche es sein sollen. Gemeinsam genutzt vom
// Assistenten für neue Zertifikate und vom Wildcard-Dialog.
type outputsPanel struct {
	w                                      *wnd
	dir, name, pw                          *ctl
	kPFX, kCert, kChain, kFull, kKey, kCSR *ctl
	format, pfxFmt                         *ctl
	show                                   *ctl
	gen                                    *ctl
}

type outputsValue struct {
	Dir, Name  string
	Kinds      []string
	CertFormat string
	Password   string
	PfxFormat  string
}

var certFormats = []string{"crt", "cer", "pem", "cer-der"}

// newOutputsPanel legt die Elemente ab Zeile y an (auf der Seite w.at).
func newOutputsPanel(w *wnd, x, y int, hint string) *outputsPanel {
	p := &outputsPanel{w: w}
	w.label(x, y, 660, 18, "Zielordner (lokaler Ordner oder Netzwerkfreigabe, z. B. \\\\server\\freigabe\\zertifikate):")
	p.dir = w.edit(x, y+22, 466, 24, "")
	p.dir.cue("z. B. D:\\Zertifikate")
	w.button(x+474, y+21, 92, 26, "Durchsuchen …", p.browse)
	w.button(x+574, y+21, 86, 26, "Testen", p.test)

	w.label(x, y+60, 660, 18, "Dateiname ohne Endung (leer = automatisch aus der ersten Domain):")
	p.name = w.edit(x, y+82, 300, 24, "")

	w.label(x, y+120, 660, 18, "Welche Dateien sollen angelegt werden?")
	p.kPFX = w.check(x+8, y+142, 320, 22, "PFX-Datei (Zertifikat + Schlüssel)", p.pfxToggle)
	p.kCert = w.check(x+8, y+166, 320, 22, "Zertifikat", nil)
	p.kChain = w.check(x+8, y+190, 320, 22, "Zwischenzertifikate (Kette)", nil)
	p.kFull = w.check(x+340, y+142, 320, 22, "Zertifikat mit Kette (fullchain)", nil)
	p.kKey = w.check(x+340, y+166, 320, 22, "Privater Schlüssel (.key)", nil)
	p.kCSR = w.check(x+340, y+190, 320, 22, "Zertifikatsanforderung (.csr)", nil)
	p.kPFX.setChecked(true)

	w.label(x, y+228, 190, 18, "Format des Zertifikats:")
	p.format = w.combo(x+200, y+224, 260, []string{".crt (Text)", ".cer (Text)", ".pem (Text)", ".cer (binär, DER)"}, nil)

	w.label(x, y+264, 190, 18, "Passwort der PFX-Datei:")
	p.pw = w.password(x+200, y+260, 200, 24)
	p.gen = w.button(x+408, y+259, 90, 26, "Zufällig", func() {
		p.pw.setText(generatePassword(16))
		p.show.setChecked(true)
		p.pw.showPassword(true)
	})
	p.show = w.check(x+506, y+260, 150, 24, "Anzeigen", func() { p.pw.showPassword(p.show.checked()) })

	w.label(x, y+300, 190, 18, "Verschlüsselung der PFX:")
	p.pfxFmt = w.combo(x+200, y+296, 460, []string{"Kompatibel (3DES, für alle Windows-Versionen)", "Modern (AES-256, nur neuere Windows-Versionen)"}, nil)
	w.label(x, y+332, 660, 36, hint)
	return p
}

func (p *outputsPanel) pfxToggle() {
	on := p.kPFX.checked()
	p.pw.enable(on)
	p.gen.enable(on)
	p.show.enable(on)
	p.pfxFmt.enable(on)
}

// setChainAllowed blendet „Zwischenzertifikate“ aus (selbstsignierte Zertifikate haben keine).
func (p *outputsPanel) setChainAllowed(v bool) {
	if !v {
		p.kChain.setChecked(false)
	}
	p.kChain.enable(v)
}

func (p *outputsPanel) browse() {
	if d := pickFolder(p.w, "Zielordner für die Zertifikatsdateien wählen", p.dir.trimmed()); d != "" {
		p.dir.setText(d)
	}
}

func (p *outputsPanel) test() {
	msg, err := testWrite(p.dir.trimmed())
	if err != nil {
		warnBox(p.w, err.Error())
		return
	}
	infoBox(p.w, msg)
}

func (p *outputsPanel) value() outputsValue {
	v := outputsValue{Dir: p.dir.trimmed(), Name: p.name.trimmed(), Password: p.pw.text(), CertFormat: certFormats[maxInt(p.format.comboIndex(), 0)]}
	if p.pfxFmt.comboIndex() == 1 {
		v.PfxFormat = "aes"
	} else {
		v.PfxFormat = "compat"
	}
	for _, k := range []struct {
		c    *ctl
		kind string
	}{{p.kPFX, "pfx"}, {p.kCert, "cert"}, {p.kChain, "chain"}, {p.kFull, "fullchain"}, {p.kKey, "key"}, {p.kCSR, "csr"}} {
		if k.c.checked() {
			v.Kinds = append(v.Kinds, k.kind)
		}
	}
	return v
}

// check prüft die Eingaben und liefert eine Meldung für den Anwender, falls etwas fehlt.
func (p *outputsPanel) check() string {
	v := p.value()
	switch {
	case v.Dir == "":
		return "Bitte einen Zielordner angeben."
	case len(v.Kinds) == 0:
		return "Bitte mindestens eine Datei auswählen."
	case containsKind(v.Kinds, "pfx") && v.Password == "":
		return "Bitte ein Passwort für die PFX-Datei vergeben (oder „Zufällig“ wählen)."
	}
	return ""
}

func containsKind(ks []string, k string) bool {
	for _, x := range ks {
		if x == k {
			return true
		}
	}
	return false
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(strings.ReplaceAll(s, "\r", ""), "\n") {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, t)
		}
	}
	return out
}
