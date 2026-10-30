package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	smb2 "github.com/hirochachacha/go-smb2"
)

func TestValidateSMB(t *testing.T) {
	good := []struct {
		name string
		in   SMBRequest
		want SMBTarget
	}{
		{"einfach", SMBRequest{Server: "dateiserver", Share: "zertifikate", User: "dienst"},
			SMBTarget{Server: "dateiserver", Share: "zertifikate", User: "dienst"}},
		{"Domäne im Benutzer, Port, Unterordner", SMBRequest{Server: " 10.0.0.5:4445 ", Share: "z", Dir: `iis\barcode//sub/`, User: `FIRMA\dienst`},
			SMBTarget{Server: "10.0.0.5:4445", Share: "z", Dir: "iis/barcode/sub", User: "dienst", Domain: "FIRMA"}},
		{"Domäne extra, UPN bleibt", SMBRequest{Server: "srv.firma.local", Share: "z$", User: "dienst@firma.local", Domain: "FIRMA"},
			SMBTarget{Server: "srv.firma.local", Share: "z$", User: "dienst@firma.local", Domain: "FIRMA"}},
		{"IPv6 mit Port", SMBRequest{Server: "[fe80::1]:445", Share: "z", User: "u"},
			SMBTarget{Server: "[fe80::1]:445", Share: "z", User: "u"}},
		{"IPv6 ohne Port", SMBRequest{Server: "fe80::1", Share: "z", User: "u"},
			SMBTarget{Server: "[fe80::1]", Share: "z", User: "u"}},
	}
	for _, c := range good {
		got, err := validateSMB(&c.in)
		if err != nil || *got != c.want {
			t.Errorf("%s: %+v %v, erwartet %+v", c.name, got, err, c.want)
		}
	}

	bad := []struct {
		name string
		in   SMBRequest
		want string
	}{
		{"kein Server", SMBRequest{Share: "z", User: "u"}, "Server:"},
		{"UNC im Serverfeld", SMBRequest{Server: `\\srv\z`, Share: "z", User: "u"}, "Server:"},
		{"Pfad im Serverfeld", SMBRequest{Server: "srv/z", Share: "z", User: "u"}, "Server:"},
		{"Leerzeichen im Namen", SMBRequest{Server: "ser ver", Share: "z", User: "u"}, "Server:"},
		{"Port zu groß", SMBRequest{Server: "srv:99999", Share: "z", User: "u"}, "Port"},
		{"Port kein Zahl", SMBRequest{Server: "srv:abc", Share: "z", User: "u"}, "Port"},
		{"keine Freigabe", SMBRequest{Server: "srv", User: "u"}, "Freigabe:"},
		{"Freigabe mit Pfad", SMBRequest{Server: "srv", Share: "a/b", User: "u"}, "Freigabe:"},
		{"Freigabe mit Doppelpunkt", SMBRequest{Server: "srv", Share: "a:b", User: "u"}, "Freigabe:"},
		{"Unterordner nach oben", SMBRequest{Server: "srv", Share: "z", Dir: "a/../b", User: "u"}, "Unterordner:"},
		{"Unterordner mit Stern", SMBRequest{Server: "srv", Share: "z", Dir: "a*b", User: "u"}, "Unterordner:"},
		{"kein Benutzer", SMBRequest{Server: "srv", Share: "z"}, "Benutzer:"},
		{"Domäne doppelt angegeben", SMBRequest{Server: "srv", Share: "z", User: `A\b`, Domain: "X"}, "Benutzer:"},
		{"Benutzer ohne Name", SMBRequest{Server: "srv", Share: "z", User: `A\`}, "Benutzer:"},
		{"Steuerzeichen", SMBRequest{Server: "srv", Share: "z", User: "u\x01"}, "nicht erlaubtes Zeichen"},
	}
	for _, c := range bad {
		if _, err := validateSMB(&c.in); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, erwartet Meldung mit %q", c.name, err, c.want)
		}
	}

	if validateSMBPassword("") == nil || validateSMBPassword("a\nb") == nil || validateSMBPassword(strings.Repeat("x", 257)) == nil {
		t.Error("ungültige Passwörter hätten abgelehnt werden müssen")
	}
	if err := validateSMBPassword("Pa$$wort mit Leerzeichen"); err != nil {
		t.Errorf("gültiges Passwort abgelehnt: %v", err)
	}
}

func TestSMBTargetLabelsAndAddr(t *testing.T) {
	st := &SMBTarget{Server: "10.0.0.5:4445", Share: "zert", Dir: "iis/barcode", User: "dienst", Domain: "FIRMA"}
	if got := st.label(); got != `\\10.0.0.5:4445\zert\iis\barcode` {
		t.Errorf("label: %s", got)
	}
	if got := st.account(); got != `FIRMA\dienst` {
		t.Errorf("account: %s", got)
	}
	p := &Profile{SMB: st}
	if got := p.targetFile("x.pfx"); got != `\\10.0.0.5:4445\zert\iis\barcode\x.pfx` {
		t.Errorf("targetFile: %s", got)
	}
	lp := &Profile{TargetDir: filepath.Join("a", "b")}
	if lp.targetLabel() != filepath.Join("a", "b") || lp.targetFile("x") != filepath.Join("a", "b", "x") {
		t.Error("lokales Ziel unverändert erwartet")
	}
	for in, want := range map[string]string{
		"srv": "srv:445", "srv:4445": "srv:4445", "10.0.0.5": "10.0.0.5:445", "[fe80::1]": "[fe80::1]:445", "[fe80::1]:99": "[fe80::1]:99",
	} {
		if got := smbAddr(in); got != want {
			t.Errorf("smbAddr(%s) = %s, erwartet %s", in, got, want)
		}
	}
}

func TestExplainSMB(t *testing.T) {
	st := &SMBTarget{Server: "srv", Share: "zert", User: "dienst", Domain: "FIRMA"}
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"falsches Passwort", &smb2.ResponseError{Code: ntLogonFailure}, "Anmeldung wurde abgelehnt"},
		{"Konto gesperrt", &smb2.ResponseError{Code: ntAccountLockedOut}, "gesperrt"},
		{"Passwort abgelaufen", &smb2.ResponseError{Code: ntPasswordExpired}, "abgelaufen"},
		{"Freigabe fehlt", &smb2.ResponseError{Code: ntBadNetworkName}, "„zert“ gibt es auf dem Server nicht"},
		{"Datei in Benutzung", &smb2.ResponseError{Code: ntSharingViolation}, "benutzt"},
		{"Platte voll", &smb2.ResponseError{Code: ntDiskFull}, "Speicherplatz"},
		{"kein Zugriff", &os.PathError{Op: "open", Path: "x", Err: os.ErrPermission}, `FIRMA\dienst darf hier nicht schreiben`},
		{"Anmeldung verweigert (Samba)", &smbPhaseError{phase: phaseLogin, err: os.ErrPermission}, "Anmeldung wurde abgelehnt"},
		{"Freigabe verweigert", &smbPhaseError{phase: phaseShare, err: os.ErrPermission}, `FIRMA\dienst darf auf die Freigabe „zert“ nicht zugreifen`},
		{"Pfad fehlt", &os.PathError{Op: "open", Path: "x", Err: os.ErrNotExist}, "Ordner im Pfad fehlt"},
		{"Zeitüberschreitung", fmt.Errorf("x: %w", context.DeadlineExceeded), "nicht rechtzeitig"},
		{"Name unbekannt", &net.DNSError{Err: "no such host", Name: "srv", IsNotFound: true}, "„srv“ ist nicht bekannt"},
		{"Port zu", refused, "keine SMB-Verbindung"},
		{"Verbindung weg", &smb2.TransportError{Err: fmt.Errorf("EOF")}, "unterbrochen"},
		{"Unbekanntes", fmt.Errorf("etwas ganz anderes"), "Unerwarteter Fehler: etwas ganz anderes"},
	}
	for _, c := range cases {
		if got := explainSMB(c.err, st); !strings.Contains(got, c.want) {
			t.Errorf("%s: %q enthält nicht %q", c.name, got, c.want)
		}
	}
}

// memTarget ist ein Ziel im Speicher für die gemeinsame Schreiblogik.
type memTarget struct {
	files                          map[string][]byte
	failMkdir, failWrite, failMove error
}

func newMemTarget() *memTarget { return &memTarget{files: map[string][]byte{}} }

func (m *memTarget) MkdirAll() error { return m.failMkdir }
func (m *memTarget) ReadFile(n string) ([]byte, error) {
	b, ok := m.files[n]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}
func (m *memTarget) WriteFile(n string, d []byte) error {
	if m.failWrite != nil {
		return m.failWrite
	}
	m.files[n] = append([]byte(nil), d...)
	return nil
}
func (m *memTarget) Replace(tmp, n string) error {
	if m.failMove != nil {
		return m.failMove
	}
	m.files[n] = m.files[tmp]
	delete(m.files, tmp)
	return nil
}
func (m *memTarget) Remove(n string) error { delete(m.files, n); return nil }
func (m *memTarget) Close() error          { return nil }

func smbTestProfile(t *testing.T) (*Profile, outputData) {
	t.Helper()
	leaf := selfSigned(t, "www.beispiel.de")
	p := &Profile{SMB: &SMBTarget{Server: "srv", Share: "z", Dir: "a/b", User: "u"}, Domains: []string{"www.beispiel.de"}}
	outs, _ := planOutputs([]string{"cert", "key"}, "crt", "x")
	p.Outputs = outs
	return p, outputData{Chain: pemOf(leaf), Key: []byte("KEY")}
}

func TestSyncToWithSMBProfile(t *testing.T) {
	p, d := smbTestProfile(t)
	m := newMemTarget()
	all, written, err := syncTo(m, p, d)
	if err != nil || len(all) != 2 || len(written) != 2 {
		t.Fatalf("erster Lauf: %v %v %v", err, all, written)
	}
	if all[0] != `\\srv\z\a\b\x.crt` {
		t.Errorf("Anzeigepfad: %s", all[0])
	}
	if len(m.files) != 2 {
		t.Errorf("Ziel enthält %d statt 2 Dateien (Hilfsdateien übrig?): %v", len(m.files), m.files)
	}
	if _, written, _ = syncTo(m, p, d); len(written) != 0 {
		t.Errorf("zweiter Lauf schreibt erneut: %v", written)
	}
	d.Key = []byte("KEY2")
	if _, written, _ = syncTo(m, p, d); len(written) != 1 || written[0] != "x.key" {
		t.Errorf("nur der Schlüssel hätte sich ändern dürfen: %v", written)
	}
	if string(m.files["x.key"]) != "KEY2" {
		t.Error("neuer Schlüssel nicht abgelegt")
	}
}

func TestSyncToErrorsAreExplained(t *testing.T) {
	p, d := smbTestProfile(t)

	m := newMemTarget()
	m.failMkdir = os.ErrPermission
	_, _, err := syncTo(m, p, d)
	if err == nil || !strings.Contains(err.Error(), `\\srv\z\a\b`) || !strings.Contains(err.Error(), "Zugriff verweigert") {
		t.Errorf("Ordner nicht anlegbar: %v", err)
	}

	m = newMemTarget()
	m.failWrite = &smb2.ResponseError{Code: ntDiskFull}
	_, _, err = syncTo(m, p, d)
	if err == nil || !strings.Contains(err.Error(), "x.crt") || !strings.Contains(err.Error(), "Speicherplatz") {
		t.Errorf("Schreiben scheitert: %v", err)
	}

	m = newMemTarget()
	m.failMove = &smb2.ResponseError{Code: ntSharingViolation}
	_, _, err = syncTo(m, p, d)
	if err == nil || !strings.Contains(err.Error(), "konnte nicht ersetzt werden") {
		t.Errorf("Ersetzen scheitert: %v", err)
	}
	for n := range m.files {
		if strings.HasSuffix(n, ".tmp") {
			t.Errorf("Hilfsdatei %s blieb liegen", n)
		}
	}

	// lokales Ziel: Meldungen wie bisher
	lp := &Profile{TargetDir: filepath.Join(t.TempDir(), "x"), Outputs: p.Outputs}
	lm := newMemTarget()
	lm.failMkdir = os.ErrPermission
	if _, _, err = syncTo(lm, lp, d); err == nil || !strings.Contains(err.Error(), "bei Netzwerkfreigaben") {
		t.Errorf("lokale Meldung: %v", err)
	}
}

func TestSMBProfileStoresNoPlainPassword(t *testing.T) {
	t.Setenv("ZA_DATA", t.TempDir())
	const pw = "Geheim-Pa$$wort-12345"
	req := CreateRequest{Domains: "smb.beispiel.test", Method: "selfsigned", ValidDays: 30, Outputs: []string{"cert", "key"}, CertFormat: "crt",
		SMB: &SMBRequest{Server: "srv", Share: "z", Dir: "iis", User: `FIRMA\dienst`, Password: pw}}
	p, err := buildProfile(req)
	if err != nil {
		t.Fatal(err)
	}
	if p.SMB == nil || p.TargetDir != "" || p.SMB.Domain != "FIRMA" || p.SMB.User != "dienst" {
		t.Fatalf("Profil: %+v", p)
	}
	if err := os.MkdirAll(profileDir(p.ID), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := saveProfile(p); err != nil {
		t.Fatal(err)
	}
	if err := saveSMBSecret(p.ID, pw); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"profile.json", "smb.secret"} {
		b, err := os.ReadFile(filepath.Join(profileDir(p.ID), f))
		if err != nil || bytes.Contains(b, []byte(pw)) {
			t.Errorf("%s: Passwort im Klartext oder Datei fehlt (%v)", f, err)
		}
	}
	if got, err := loadSMBSecret(p.ID); err != nil || got != pw {
		t.Errorf("Passwort zurücklesen: %q %v", got, err)
	}
	loaded, err := loadProfile(p.ID)
	if err != nil || loaded.SMB == nil || *loaded.SMB != *p.SMB {
		t.Errorf("Profil zurücklesen: %+v %v", loaded, err)
	}
	// Die Ansicht zeigt das Ziel und kein Passwort.
	views := listProfiles()
	if len(views) != 1 || !views[0].SMB || views[0].TargetDir != `\\srv\z\iis` {
		t.Fatalf("Ansicht: %+v", views)
	}
	if b, _ := json.Marshal(views); bytes.Contains(b, []byte(pw)) {
		t.Error("Passwort in der Ansicht")
	}

	// Eingaben werden geprüft, bevor etwas angelegt wird.
	req.SMB = &SMBRequest{Server: "srv", Share: "z", User: "u"}
	if _, err := buildProfile(req); err == nil || !strings.Contains(err.Error(), "Passwort") {
		t.Errorf("ohne Passwort: %v", err)
	}
	req.SMB = &SMBRequest{Server: `\\srv\z`, Share: "z", User: "u", Password: "x"}
	if _, err := buildProfile(req); err == nil || !strings.Contains(err.Error(), "Server:") {
		t.Errorf("falscher Server: %v", err)
	}
}

func TestFsTestAPIWithSMB(t *testing.T) {
	_, h := newTestServer(t, false)
	host := "zertifikate.firma.example:8080"
	c := cookieOf(call(h, "POST", "/api/login", host, map[string]string{"password": testPW}, nil))
	if c == nil {
		t.Fatal("Anmeldung fehlgeschlagen")
	}
	withCookie := func(r *http.Request) { r.AddCookie(c) }
	post := func(smb map[string]string) (map[string]any, string) {
		rec := call(h, "POST", "/api/fs/test", host, map[string]any{"smb": smb}, withCookie)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out, rec.Body.String()
	}
	const pw = "api-test-passwort-9876"

	if r, _ := post(map[string]string{"share": "z", "user": "u", "password": pw}); r["ok"] != false || !strings.Contains(fmt.Sprint(r["message"]), "Server:") {
		t.Errorf("ohne Server: %v", r)
	}
	if r, _ := post(map[string]string{"server": "srv", "share": "z", "user": "u"}); r["ok"] != false || !strings.Contains(fmt.Sprint(r["message"]), "Passwort") {
		t.Errorf("ohne Passwort: %v", r)
	}
	// Nichts hört auf Port 1: Die Meldung erklärt es, das Passwort taucht nirgends auf.
	r, raw := post(map[string]string{"server": "127.0.0.1:1", "share": "z", "user": "u", "password": pw})
	if r["ok"] != false || !strings.Contains(fmt.Sprint(r["message"]), "keine SMB-Verbindung") {
		t.Errorf("nicht erreichbar: %v", r)
	}
	if strings.Contains(raw, pw) {
		t.Error("das Passwort steht in der Antwort")
	}
	// ohne Anmeldung gibt es keine Prüfung
	if rec := call(h, "POST", "/api/fs/test", host, map[string]any{"smb": map[string]string{"server": "x"}}, nil); rec.Code != 401 {
		t.Errorf("ohne Anmeldung: %d", rec.Code)
	}
}

// ---------- gegen einen echten SMB-Server (z. B. Samba im Docker) ----------

type smbEnvT struct {
	server, share, user, pass string
}

func smbEnv(t *testing.T) smbEnvT {
	t.Helper()
	srv := os.Getenv("ZA_TEST_SMB")
	if srv == "" {
		t.Skip("ZA_TEST_SMB nicht gesetzt (SMB-Testserver nötig, z. B. 127.0.0.1:1445)")
	}
	get := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	return smbEnvT{server: srv, share: get("ZA_TEST_SMB_SHARE", "zert"), user: get("ZA_TEST_SMB_USER", "tester"), pass: get("ZA_TEST_SMB_PASS", "tester-pass-1")}
}

func (e smbEnvT) target(dir string) *SMBTarget {
	return &SMBTarget{Server: e.server, Share: e.share, Dir: dir, User: e.user}
}

func TestSMBServerConnectAndTest(t *testing.T) {
	e := smbEnv(t)
	ctx := context.Background()

	msg, err := testSMB(ctx, e.target(""), e.pass)
	if err != nil || !strings.Contains(msg, "in Ordnung") {
		t.Fatalf("Freigabe prüfen: %q %v", msg, err)
	}

	// Ordner, den es noch nicht gibt: Test legt ihn an und räumt wieder auf.
	dir := "neu-" + randomHex(3) + "/unter/ordner"
	msg, err = testSMB(ctx, e.target(dir), e.pass)
	if err != nil || !strings.Contains(msg, "existiert noch nicht") {
		t.Fatalf("neuer Ordner: %q %v", msg, err)
	}
	s, err := openSMB(ctx, e.target(""), e.pass)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.share.Stat(strings.SplitN(dir, "/", 2)[0]); err == nil {
		t.Error("der Testordner blieb auf der Freigabe liegen")
	}

	// falsche Zugangsdaten und falsche Freigabe werden verständlich gemeldet
	if _, err := testSMB(ctx, e.target(""), "falsches-passwort"); err == nil || !strings.Contains(err.Error(), "Anmeldung wurde abgelehnt") {
		t.Errorf("falsches Passwort: %v", err)
	}
	bad := e.target("")
	bad.Share = "gibt-es-nicht"
	if _, err := testSMB(ctx, bad, e.pass); err == nil || !strings.Contains(err.Error(), "gibt es auf dem Server nicht") {
		t.Errorf("falsche Freigabe: %v", err)
	}
	bad = e.target("")
	bad.User = "unbekannt"
	// Manche Server melden einen unbekannten Benutzer als Gast an und lehnen erst die Freigabe ab.
	if _, err := testSMB(ctx, bad, e.pass); err == nil || !(strings.Contains(err.Error(), "Anmeldung") || strings.Contains(err.Error(), "nicht zugreifen")) {
		t.Errorf("falscher Benutzer: %v", err)
	}
}

func TestSMBServerSyncAndReplace(t *testing.T) {
	e := smbEnv(t)
	ctx := context.Background()
	dir := "sync-" + randomHex(3) + "/ziel"
	p, d := smbTestProfile(t)
	p.SMB = e.target(dir)

	open := func() *smbTarget {
		s, err := openSMB(ctx, p.SMB, e.pass)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := open()
	all, written, err := syncTo(s, p, d)
	if err != nil || len(all) != 2 || len(written) != 2 {
		t.Fatalf("erster Lauf: %v %v %v", err, all, written)
	}
	if _, written, _ = syncTo(s, p, d); len(written) != 0 {
		t.Errorf("zweiter Lauf schreibt erneut: %v", written)
	}
	d.Key = []byte("ANDERER-SCHLUESSEL")
	if _, written, err = syncTo(s, p, d); err != nil || len(written) != 1 {
		t.Fatalf("Ersetzen einer vorhandenen Datei: %v %v", err, written)
	}
	got, err := s.ReadFile("x.key")
	if err != nil || string(got) != "ANDERER-SCHLUESSEL" {
		t.Errorf("Inhalt nach dem Ersetzen: %q %v", got, err)
	}
	infos, err := s.share.ReadDir(dir)
	if err != nil || len(infos) != 2 {
		names := []string{}
		for _, i := range infos {
			names = append(names, i.Name())
		}
		t.Errorf("auf der Freigabe liegen %v (Hilfsdateien übrig?) %v", names, err)
	}
	// Aufräumen: Inhalt und Ordner entfernen
	_ = s.share.RemoveAll(strings.SplitN(dir, "/", 2)[0])
	s.Close()
}

func TestSMBServerProfileEndToEnd(t *testing.T) {
	e := smbEnv(t)
	t.Setenv("ZA_DATA", t.TempDir())
	dir := "e2e-" + randomHex(3)
	req := CreateRequest{Domains: "smb-e2e.beispiel.test", Method: "selfsigned", ValidDays: 30,
		Outputs: []string{"pfx", "cert", "key"}, CertFormat: "crt", Password: "pfx-passwort-1",
		SMB: &SMBRequest{Server: e.server, Share: e.share, Dir: dir, User: e.user, Password: e.pass}}
	p, res, job, err := create(t, req)
	if err != nil {
		t.Fatalf("createProfile: %v", err)
	}
	if res.Result != "ausgestellt" || !res.Written || len(res.Files) != 3 {
		t.Fatalf("Ergebnis: %+v", res)
	}
	if !strings.HasPrefix(res.Files[0], `\\`+e.server+`\`+e.share+`\`+dir+`\`) {
		t.Errorf("Anzeigepfad: %v", res.Files)
	}
	if s := stepState(job, "ziel"); s != "ok" {
		t.Errorf("Schritt ziel: %s", s)
	}

	// Die Dateien liegen wirklich auf der Freigabe.
	s, err := openSMB(context.Background(), p.SMB, e.pass)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer s.share.RemoveAll(dir)
	for _, o := range p.outputs() {
		if b, err := s.ReadFile(o.Name); err != nil || len(b) == 0 {
			t.Errorf("%s fehlt auf der Freigabe: %v", o.Name, err)
		}
	}

	// Erneuerung mit dem gespeicherten Passwort, Dateien werden ersetzt.
	before, _ := s.ReadFile(p.outputs()[1].Name)
	rep := newJob(p.ID)
	r2, err := renewProfile(context.Background(), p.ID, true, rep)
	if err != nil || r2.Result != "erneuert" {
		t.Fatalf("Erneuerung: %+v %v", r2, err)
	}
	after, _ := s.ReadFile(p.outputs()[1].Name)
	if bytes.Equal(before, after) {
		t.Error("das Zertifikat auf der Freigabe wurde bei der Erneuerung nicht ersetzt")
	}

	// Die Übersicht kennt das Ziel; Löschen entfernt auch das gespeicherte Passwort.
	if v := listProfiles(); len(v) != 1 || !v[0].SMB || !v[0].TargetFound {
		t.Errorf("Ansicht: %+v", v)
	}
	if err := deleteProfile(p.ID, &collectReporter{id: p.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(profileDir(p.ID), "smb.secret")); err == nil {
		t.Error("smb.secret blieb nach dem Löschen liegen")
	}

	// Falsche Zugangsdaten scheitern früh und hinterlassen nichts.
	req.SMB.Password = "falsch"
	if _, _, _, err := create(t, req); err == nil || !strings.Contains(err.Error(), "Anmeldung") {
		t.Errorf("falsches Passwort: %v", err)
	}
	if _, err := os.Stat(profileDir(p.ID)); err == nil {
		t.Error("nach dem Fehler blieb ein Profil zurück")
	}
}
