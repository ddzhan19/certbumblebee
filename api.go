package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type collectReporter struct {
	id    string
	lines []string
}

func (c *collectReporter) Declare(key, label string) {}
func (c *collectReporter) Step(key, label string)    {}
func (c *collectReporter) Note(key, note string)     {}
func (c *collectReporter) Ok(key, note string)       {}
func (c *collectReporter) Fail(key, msg string)      {}
func (c *collectReporter) Logf(format string, a ...any) {
	line := fmt.Sprintf(format, a...)
	c.lines = append(c.lines, line)
	appLog(c.id, "INFO", line)
}

func errBody(err error) map[string]any {
	m := map[string]any{"error": err.Error()}
	if ue, ok := err.(*userError); ok && ue.Tech != "" {
		m["detail"] = ue.Tech
	}
	return m
}

func (s *server) registerAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/info", s.guard(true, func(w http.ResponseWriter, r *http.Request) {
		exe, _ := os.Executable()
		host, _ := os.Hostname()
		respond(w, 200, map[string]any{
			"name": appName, "author": appAuthor, "version": appVersion,
			"windows": plat.IsWindows(), "elevated": plat.IsElevated(), "dataDir": dataDir(), "exe": exe,
			"httpPort": httpPort(), "computerAccount": plat.ComputerAccount(), "hostname": host,
			"server": s.serverMode(), "container": os.Getenv("ZA_CONTAINER") != "", "timezone": time.Local.String(),
			"scheduler": schedulerKind(s),
		})
	}))

	mux.HandleFunc("GET /api/fs", s.guard(true, func(w http.ResponseWriter, r *http.Request) {
		l, err := listDir(r.URL.Query().Get("path"))
		if err != nil {
			respond(w, 400, errBody(err))
			return
		}
		respond(w, 200, l)
	}))

	mux.HandleFunc("POST /api/fs/test", s.guard(true, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Path string `json:"path"`
		}
		if err := readJSON(r, &req); err != nil {
			respond(w, 400, errBody(err))
			return
		}
		msg, err := testWrite(req.Path)
		if err != nil {
			respond(w, 200, map[string]any{"ok": false, "message": err.Error()})
			return
		}
		respond(w, 200, map[string]any{"ok": true, "message": msg})
	}))

	mux.HandleFunc("POST /api/port80", s.guard(true, func(w http.ResponseWriter, r *http.Request) {
		ok, msg := checkPort80()
		respond(w, 200, map[string]any{"ok": ok, "message": msg})
	}))

	mux.HandleFunc("GET /api/profiles", s.guard(true, func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{"profiles": listProfiles()})
	}))

	mux.HandleFunc("POST /api/profiles", s.guard(true, func(w http.ResponseWriter, r *http.Request) {
		var req CreateRequest
		if err := readJSON(r, &req); err != nil {
			respond(w, 400, errBody(err))
			return
		}
		p, err := buildProfile(req)
		if err != nil {
			respond(w, 400, errBody(err))
			return
		}
		if _, e := os.Stat(profileDir(p.ID) + string(os.PathSeparator) + "profile.json"); e == nil && !req.Replace {
			respond(w, 409, map[string]any{"error": errExists.Error(), "exists": true, "id": p.ID})
			return
		}
		if p.Task.Enabled && !plat.IsElevated() {
			respond(w, 400, map[string]any{"error": "Für die automatische Erneuerung braucht das Programm Administratorrechte. Bitte neu starten und die Abfrage bestätigen."})
			return
		}
		job := newJob(p.ID)
		go func() {
			res, err := createProfile(context.Background(), p, req, job)
			job.finish(err, res)
		}()
		respond(w, 202, map[string]any{"jobId": job.ID, "id": p.ID})
	}))

	mux.HandleFunc("POST /api/profiles/{id}/renew", s.guard(true, func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !validID(id) {
			respond(w, 400, map[string]any{"error": "Ungültige Kennung."})
			return
		}
		var req struct {
			Force bool `json:"force"`
		}
		_ = readJSON(r, &req)
		if _, err := loadProfile(id); err != nil {
			respond(w, 404, errBody(err))
			return
		}
		job := newJob(id)
		go func() {
			res, err := renewProfile(context.Background(), id, req.Force, job)
			job.finish(err, res)
		}()
		respond(w, 202, map[string]any{"jobId": job.ID})
	}))

	mux.HandleFunc("POST /api/profiles/{id}/task-test", s.guard(true, func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !validID(id) {
			respond(w, 400, map[string]any{"error": "Ungültige Kennung."})
			return
		}
		if _, err := loadProfile(id); err != nil {
			respond(w, 404, errBody(err))
			return
		}
		job := newJob(id)
		go func() {
			res, err := testTask(id, job)
			job.finish(err, res)
		}()
		respond(w, 202, map[string]any{"jobId": job.ID})
	}))

	mux.HandleFunc("GET /api/profiles/{id}/log", s.guard(true, func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !validID(id) {
			respond(w, 400, map[string]any{"error": "Ungültige Kennung."})
			return
		}
		respond(w, 200, map[string]any{"lines": tailLog(id, 200)})
	}))

	mux.HandleFunc("DELETE /api/profiles/{id}", s.guard(true, func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !validID(id) {
			respond(w, 400, map[string]any{"error": "Ungültige Kennung."})
			return
		}
		rep := &collectReporter{id: id}
		if err := deleteProfile(id, rep); err != nil {
			respond(w, 400, errBody(err))
			return
		}
		respond(w, 200, map[string]any{"ok": true, "notes": rep.lines})
	}))

	mux.HandleFunc("GET /api/jobs/{id}", s.guard(true, func(w http.ResponseWriter, r *http.Request) {
		j := getJob(r.PathValue("id"))
		if j == nil {
			respond(w, 404, map[string]any{"error": "Vorgang nicht gefunden."})
			return
		}
		respond(w, 200, j.view())
	}))

	if !s.serverMode() {
		mux.HandleFunc("POST /api/quit", s.guard(true, func(w http.ResponseWriter, r *http.Request) {
			respond(w, 200, map[string]any{"ok": true})
			go func() { time.Sleep(200 * time.Millisecond); s.shutdown() }()
		}))
	}
	s.registerDNSAPI(mux)
}

// schedulerKind sagt der Oberfläche, wer die Erneuerung auslöst.
func schedulerKind(s *server) string {
	switch {
	case s.sched != nil:
		return "builtin" // Zeitplan im Programm (Dauerbetrieb)
	case plat.IsWindows():
		return "task" // Windows-Aufgabenplanung
	}
	return "none" // Oberfläche allein: Erneuerung per „renew“ (cron/systemd)
}

type dnsAccountView struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Provider string    `json:"provider"`
	Created  time.Time `json:"created"`
	FromEnv  bool      `json:"fromEnv"`
	UsedBy   []string  `json:"usedBy"`
}

func zoneNames(zs []DNSZone) []string {
	out := make([]string, len(zs))
	for i, z := range zs {
		out[i] = z.Name
	}
	return out
}

func (s *server) registerDNSAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/dns/accounts", s.guard(true, func(w http.ResponseWriter, r *http.Request) {
		out := []dnsAccountView{}
		auto := profilesOnAutoDNS()
		for _, a := range listDNSAccounts() {
			used := append(append([]string{}, profilesUsingAccount(a.ID)...), auto...)
			out = append(out, dnsAccountView{ID: a.ID, Name: a.Name, Provider: a.Provider, Created: a.Created, FromEnv: a.FromEnv, UsedBy: used})
		}
		respond(w, 200, map[string]any{"accounts": out})
	}))

	mux.HandleFunc("POST /api/dns/accounts", s.guard(true, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name  string `json:"name"`
			Token string `json:"token"`
		}
		if err := readJSON(r, &req); err != nil {
			respond(w, 400, errBody(err))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		acc, zones, total, err := addDNSAccount(ctx, req.Name, req.Token)
		if err != nil {
			respond(w, 400, errBody(err))
			return
		}
		appLogGlobal(fmt.Sprintf("DNS-Zugang „%s“ hinterlegt (%d Zone(n) sichtbar)", acc.Name, total))
		respond(w, 200, map[string]any{"account": dnsAccountView{ID: acc.ID, Name: acc.Name, Provider: acc.Provider, Created: acc.Created, UsedBy: []string{}}, "zones": zoneNames(zones), "total": total})
	}))

	mux.HandleFunc("POST /api/dns/accounts/{id}/test", s.guard(true, func(w http.ResponseWriter, r *http.Request) {
		acc, ok := getDNSAccount(r.PathValue("id"))
		if !ok {
			respond(w, 404, map[string]any{"error": "Diesen Zugang gibt es nicht."})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		prov, err := providerFor(acc)
		if err == nil {
			var zones []DNSZone
			var total int
			if zones, total, err = prov.Zones(ctx); err == nil {
				respond(w, 200, map[string]any{"ok": true, "zones": zoneNames(zones), "total": total})
				return
			}
		}
		respond(w, 200, map[string]any{"ok": false, "message": err.Error()})
	}))

	mux.HandleFunc("DELETE /api/dns/accounts/{id}", s.guard(true, func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := removeDNSAccount(id); err != nil {
			respond(w, 400, errBody(err))
			return
		}
		appLogGlobal("DNS-Zugang " + id + " gelöscht")
		respond(w, 200, map[string]any{"ok": true})
	}))

	// Vorab prüfen, ob für jede Domain eine Zone gefunden wird.
	mux.HandleFunc("POST /api/dns/check", s.guard(true, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Domains string `json:"domains"`
			Account string `json:"account"`
		}
		if err := readJSON(r, &req); err != nil {
			respond(w, 400, errBody(err))
			return
		}
		domains, err := normalizeWildDomains(req.Domains)
		if err != nil {
			respond(w, 400, errBody(err))
			return
		}
		router, err := newDNSRouter(strings.TrimSpace(req.Account))
		if err != nil {
			respond(w, 400, errBody(err))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		type row struct {
			Domain  string `json:"domain"`
			OK      bool   `json:"ok"`
			Zone    string `json:"zone,omitempty"`
			Account string `json:"account,omitempty"`
			Message string `json:"message,omitempty"`
		}
		rows := []row{}
		for _, d := range domains {
			loc, err := router.locate(ctx, "_acme-challenge."+strings.TrimPrefix(d, "*."))
			if err != nil {
				rows = append(rows, row{Domain: d, Message: err.Error()})
				continue
			}
			rows = append(rows, row{Domain: d, OK: true, Zone: loc.zone.Name, Account: loc.acct.acc.Name})
		}
		respond(w, 200, map[string]any{"rows": rows})
	}))
}

// testTask startet die geplante Aufgabe und wartet auf das Ergebnis. So zeigt sich früh, ob das Konto der Aufgabe
// (z. B. SYSTEM) den Zielordner erreicht.
func testTask(id string, job *Job) (any, error) {
	p, err := loadProfile(id)
	if err != nil {
		return nil, err
	}
	job.Declare("start", "Aufgabe starten")
	job.Declare("lauf", "Auf das Ergebnis warten")
	if !p.Task.Enabled {
		return nil, uerr("Für dieses Zertifikat ist keine automatische Erneuerung eingerichtet.", "")
	}
	job.Step("start", "Aufgabe starten")
	ok, err := plat.TaskExists(p.Task.Name)
	if err != nil {
		job.Fail("start", err.Error())
		return nil, uerr("Die Aufgabenplanung konnte nicht abgefragt werden.", err.Error())
	}
	if !ok {
		e := uerr(fmt.Sprintf("Die Aufgabe „%s“ gibt es in der Aufgabenplanung nicht mehr. Bitte das Zertifikat neu einrichten.", p.Task.Name), "")
		job.Fail("start", e.Error())
		return nil, e
	}
	before := loadState(id).LastRun
	if err := plat.TaskRun(p.Task.Name); err != nil {
		job.Fail("start", err.Error())
		return nil, uerr("Die Aufgabe konnte nicht gestartet werden.", err.Error())
	}
	job.Ok("start", "gestartet")
	job.Step("lauf", "Auf das Ergebnis warten")
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(1 * time.Second)
		st := loadState(id)
		if st.LastRun.After(before) {
			if st.LastResult == "fehler" {
				e := uerr("Die Aufgabe ist fehlgeschlagen: "+st.LastMessage, "")
				job.Fail("lauf", st.LastMessage)
				return nil, e
			}
			job.Ok("lauf", st.LastMessage)
			return map[string]any{"result": st.LastResult, "message": st.LastMessage}, nil
		}
	}
	e := uerr("Die Aufgabe hat nach 3 Minuten noch kein Ergebnis gemeldet. Bitte das Protokoll prüfen.", "")
	job.Fail("lauf", e.Error())
	return nil, e
}
