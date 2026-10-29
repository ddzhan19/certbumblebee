//go:build windows

package main

import (
	"fmt"
	"strings"
	"time"
)

var panelTimerSeq uintptr = 7000

// jobPanel zeigt den Fortschritt eines Hintergrundvorgangs: Schritte mit Stand, Laufbalken und eine Meldung.
type jobPanel struct {
	w       *wnd
	steps   *ctl
	bar     *ctl
	msg     *ctl
	job     *Job
	sig     string
	logN    int
	running bool
	timerID uintptr
	format  func(res any) string
	onDone  func(v jobView)
}

// newJobPanel legt die Bedienelemente an (auf der Seite, die gerade in w.at steht).
func newJobPanel(w *wnd, x, y, cx, cy, stepsH int) *jobPanel {
	panelTimerSeq++
	p := &jobPanel{w: w, timerID: panelTimerSeq}
	p.steps = w.list(x, y, cx, stepsH, true, []string{"Schritt", "Stand"}, []int{cx * 42 / 100, cx * 52 / 100})
	p.bar = w.progressBar(x, y+stepsH+8, cx, 10)
	p.msg = w.memo(x, y+stepsH+26, cx, cy-stepsH-26, true)
	p.bar.show(false)
	return p
}

func stepText(s *jobStep) string {
	switch s.State {
	case "run":
		if s.Note != "" {
			return "läuft … " + s.Note
		}
		return "läuft …"
	case "ok":
		if s.Note != "" {
			return s.Note
		}
		return "fertig"
	case "fail":
		return "Fehler – " + s.Note
	}
	return ""
}

// start beginnt, den Vorgang anzuzeigen. format macht aus dem Ergebnis den Text der Meldung.
func (p *jobPanel) start(job *Job, format func(res any) string, onDone func(v jobView)) {
	p.job, p.format, p.onDone = job, format, onDone
	p.running = true
	p.sig, p.logN = "", -1
	p.steps.clearRows()
	p.msg.setText("")
	p.bar.show(true)
	p.bar.marquee(true)
	prev := p.w.onTimer
	p.w.onTimer = func(id uintptr) {
		if id == p.timerID {
			p.poll()
			return
		}
		if prev != nil {
			prev(id)
		}
	}
	p.w.timer(p.timerID, 250)
	p.poll()
}

func (p *jobPanel) poll() {
	if p.job == nil {
		return
	}
	v := p.job.view()
	var sb strings.Builder
	for _, s := range v.Steps {
		fmt.Fprintf(&sb, "%s|%s|%s\n", s.Label, s.State, s.Note)
	}
	if sig := sb.String(); sig != p.sig {
		p.sig = sig
		p.steps.clearRows()
		for _, s := range v.Steps {
			p.steps.addRow(s.Label, stepText(s))
		}
	}
	if v.State == "run" {
		if len(v.Log) != p.logN {
			p.logN = len(v.Log)
			p.msg.setText(strings.Join(v.Log, "\n"))
		}
		return
	}
	p.w.killTimer(p.timerID)
	p.running = false
	p.bar.marquee(false)
	p.bar.show(false)
	if v.State == "error" {
		t := v.Message
		if v.Detail != "" {
			t += "\n\nTechnische Einzelheiten:\n" + v.Detail
		}
		p.msg.setText(t)
	} else if p.format != nil {
		p.msg.setText(p.format(v.Result))
	}
	if p.onDone != nil {
		p.onDone(v)
	}
}

// formatRunResult beschreibt das Ergebnis einer Ausstellung oder Erneuerung.
func formatRunResult(res any) string {
	switch r := res.(type) {
	case *RunResult:
		var sb strings.Builder
		sb.WriteString(r.Message)
		if r.Cert != nil {
			fmt.Fprintf(&sb, "\n\nGültig vom %s bis %s", r.Cert.NotBefore.Local().Format("02.01.2006"), r.Cert.NotAfter.Local().Format("02.01.2006"))
			if len(r.Cert.DNSNames) > 0 {
				fmt.Fprintf(&sb, "\nNamen: %s", strings.Join(r.Cert.DNSNames, ", "))
			}
		}
		if len(r.Files) > 0 {
			fmt.Fprintf(&sb, "\n\nDateien in „%s“:", r.Target)
			for _, f := range r.Files {
				fmt.Fprintf(&sb, "\n  %s", f)
			}
		}
		return sb.String()
	case map[string]any:
		if m, ok := r["message"].(string); ok {
			return "Die geplante Aufgabe lief erfolgreich.\n\n" + m
		}
	}
	return "Fertig."
}

// showJobDialog zeigt einen Vorgang in einem eigenen Fenster und kehrt zurück, wenn es geschlossen wurde.
func showJobDialog(owner *wnd, title, intro string, job *Job, format func(res any) string) jobView {
	d := newWindow(owner, title, 640, 440, false)
	d.label(16, 14, 608, 36, intro)
	p := newJobPanel(d, 16, 54, 608, 320, 140)
	close := d.button(528, 392, 96, 30, "Schließen", func() { d.close() })
	close.enable(false)
	d.defID = close.id
	d.cmd[idCancel] = func(int) {
		if !p.running {
			d.close()
		}
	}
	d.onClose = func() bool { return !p.running }
	var final jobView
	p.start(job, format, func(v jobView) {
		final = v
		close.enable(true)
		close.focus()
	})
	d.showModal()
	return final
}

// relTime beschreibt einen Zeitpunkt für Menschen.
func relTime(t time.Time) string {
	if t.IsZero() {
		return "nie"
	}
	return t.Local().Format("02.01.2006 15:04")
}
