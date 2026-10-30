package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	smb2 "github.com/hirochachacha/go-smb2"
)

// ---------- Ziel der Dateien: lokaler Ordner oder SMB-Freigabe mit eigenen Zugangsdaten ----------

// SMBTarget beschreibt eine Netzwerkfreigabe, in die mit eigenen Zugangsdaten geschrieben wird. Das Passwort steht
// nicht hier, sondern geschützt in smb.secret (siehe store.go).
type SMBTarget struct {
	Server string `json:"server"`           // Name oder IP-Adresse, optional mit :Port
	Share  string `json:"share"`            // Name der Freigabe
	Dir    string `json:"dir,omitempty"`    // Unterordner in der Freigabe, mit / getrennt
	User   string `json:"user"`             // Benutzername
	Domain string `json:"domain,omitempty"` // Domäne oder Rechnername, kann leer sein
}

// SMBRequest sind die Eingaben der Oberfläche für eine SMB-Freigabe.
type SMBRequest struct {
	Server   string `json:"server"`
	Share    string `json:"share"`
	Dir      string `json:"dir"`
	User     string `json:"user"`
	Domain   string `json:"domain"`
	Password string `json:"password"`
}

var (
	smbHostRe  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$`)
	smbBadName = regexp.MustCompile("[\\\\/:*?\"<>|\u0000-\u001f]")
)

func hasControl(s string) bool { return strings.IndexFunc(s, unicode.IsControl) >= 0 }

// splitServer trennt Name und Port: „server“, „server:4445“, „10.0.0.5“, „[fe80::1]:445“.
func splitServer(s string) (host, port string, ok bool) {
	if strings.HasPrefix(s, "[") {
		if h, p, err := net.SplitHostPort(s); err == nil {
			return h, p, true
		}
		if strings.HasSuffix(s, "]") {
			return s[1 : len(s)-1], "", true
		}
		return "", "", false
	}
	if net.ParseIP(s) != nil {
		return s, "", true
	}
	switch strings.Count(s, ":") {
	case 0:
		return s, "", true
	case 1:
		h, p, _ := strings.Cut(s, ":")
		return h, p, true
	}
	return "", "", false
}

// smbAddr liefert Adresse und Port zum Verbinden (Standard 445).
func smbAddr(server string) string {
	host, port, _ := splitServer(server)
	if port == "" {
		port = "445"
	}
	return net.JoinHostPort(host, port)
}

// validateSMB prüft die Eingaben und liefert das Ziel ohne Passwort. Fehler sind für Menschen formuliert.
func validateSMB(in *SMBRequest) (*SMBTarget, error) {
	server := strings.TrimSpace(in.Server)
	if server == "" {
		return nil, fmt.Errorf("Server: Bitte den Namen oder die IP-Adresse des Servers eintragen.")
	}
	if strings.ContainsAny(server, `\/`) {
		return nil, fmt.Errorf("Server: Bitte nur den Namen oder die IP-Adresse eintragen, ohne \\\\ und ohne die Freigabe. Die Freigabe kommt in das nächste Feld.")
	}
	host, port, ok := splitServer(server)
	if !ok || (net.ParseIP(host) == nil && !smbHostRe.MatchString(host)) {
		return nil, fmt.Errorf("Server: „%s“ ist kein gültiger Name und keine gültige IP-Adresse.", server)
	}
	if port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("Server: Der Port „%s“ ist ungültig (erlaubt sind 1 bis 65535).", port)
		}
		server = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		server = "[" + host + "]"
	} else {
		server = host
	}

	share := strings.TrimSpace(in.Share)
	if share == "" {
		return nil, fmt.Errorf("Freigabe: Bitte den Namen der Freigabe eintragen, z. B. zertifikate.")
	}
	if smbBadName.MatchString(share) || len(share) > 80 {
		return nil, fmt.Errorf("Freigabe: Bitte nur den Namen der Freigabe ohne \\ / : * ? \" < > | eintragen.")
	}

	dir, err := cleanSMBDir(in.Dir)
	if err != nil {
		return nil, err
	}

	user, domain := strings.TrimSpace(in.User), strings.TrimSpace(in.Domain)
	if d, u, found := strings.Cut(user, `\`); found {
		if domain != "" || d == "" || u == "" {
			return nil, fmt.Errorf("Benutzer: Bitte Domäne und Benutzername getrennt eintragen oder als DOMÄNE\\Benutzer.")
		}
		domain, user = d, u
	}
	if user == "" {
		return nil, fmt.Errorf("Benutzer: Bitte den Benutzernamen für die Freigabe eintragen.")
	}
	if len(user) > 256 || hasControl(user) || len(domain) > 255 || hasControl(domain) || strings.ContainsAny(domain, `\/`) {
		return nil, fmt.Errorf("Benutzer oder Domäne enthält ein nicht erlaubtes Zeichen.")
	}
	return &SMBTarget{Server: server, Share: share, Dir: dir, User: user, Domain: domain}, nil
}

// cleanSMBDir macht aus der Eingabe einen Pfad innerhalb der Freigabe: Teile mit /, ohne „.“ und ohne „..“.
func cleanSMBDir(in string) (string, error) {
	var parts []string
	for _, seg := range strings.FieldsFunc(in, func(r rune) bool { return r == '/' || r == '\\' }) {
		seg = strings.TrimSpace(seg)
		switch {
		case seg == "" || seg == ".":
			continue
		case seg == "..":
			return "", fmt.Errorf("Unterordner: „..“ ist nicht erlaubt.")
		case strings.ContainsAny(seg, ":*?\"<>|") || hasControl(seg) || len(seg) > 255:
			return "", fmt.Errorf("Unterordner: „%s“ enthält ein nicht erlaubtes Zeichen (: * ? \" < > |).", seg)
		}
		parts = append(parts, seg)
	}
	out := strings.Join(parts, "/")
	if len(out) > 400 {
		return "", fmt.Errorf("Unterordner: Der Pfad ist zu lang.")
	}
	return out, nil
}

// validateSMBPassword prüft das Passwort für die Freigabe.
func validateSMBPassword(pw string) error {
	if pw == "" {
		return fmt.Errorf("Passwort: Bitte das Passwort für die Freigabe eintragen.")
	}
	if len(pw) > 256 || strings.ContainsAny(pw, "\x00\r\n") {
		return fmt.Errorf("Passwort: Das Passwort ist ungültig (höchstens 256 Zeichen, keine Zeilenumbrüche).")
	}
	return nil
}

// label ist der Zielort in der gewohnten Schreibweise: \\server\freigabe\ordner.
func (t *SMBTarget) label() string {
	s := `\\` + t.Server + `\` + t.Share
	if t.Dir != "" {
		s += `\` + strings.ReplaceAll(t.Dir, "/", `\`)
	}
	return s
}

// account ist das Konto in der Schreibweise DOMÄNE\Benutzer.
func (t *SMBTarget) account() string {
	if t.Domain != "" {
		return t.Domain + `\` + t.User
	}
	return t.User
}

// targetLabel nennt den Zielort für Meldungen und Anzeigen.
func (p *Profile) targetLabel() string {
	if p.SMB != nil {
		return p.SMB.label()
	}
	return p.TargetDir
}

// targetFile nennt den Ort einer Datei im Ziel für Anzeigen.
func (p *Profile) targetFile(name string) string {
	if p.SMB != nil {
		return p.SMB.label() + `\` + name
	}
	return filepath.Join(p.TargetDir, name)
}

// targetFS ist der Ort, an den die Dateien geschrieben werden.
type targetFS interface {
	MkdirAll() error                          // legt den Zielordner an
	ReadFile(name string) ([]byte, error)     // liest eine Datei im Ziel
	WriteFile(name string, data []byte) error // schreibt eine Datei unter genau diesem Namen
	Replace(tmpName, name string) error       // benennt tmpName in name um und ersetzt dabei eine vorhandene Datei
	Remove(name string) error                 // löscht eine Datei
	Close() error                             // beendet die Verbindung
}

type localTarget struct{ dir string }

func (l localTarget) MkdirAll() error { return os.MkdirAll(l.dir, 0o755) }
func (l localTarget) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(l.dir, name))
}
func (l localTarget) WriteFile(name string, data []byte) error {
	return os.WriteFile(filepath.Join(l.dir, name), data, 0o600)
}
func (l localTarget) Replace(tmp, name string) error {
	return os.Rename(filepath.Join(l.dir, tmp), filepath.Join(l.dir, name))
}
func (l localTarget) Remove(name string) error { return os.Remove(filepath.Join(l.dir, name)) }
func (l localTarget) Close() error             { return nil }

// smbTimeout begrenzt eine ganze Verbindung (Anmelden, Dateien schreiben, Abmelden).
const smbTimeout = 2 * time.Minute

type smbTarget struct {
	t      *SMBTarget
	conn   net.Conn
	sess   *smb2.Session
	share  *smb2.Share
	cancel context.CancelFunc
}

// openSMB verbindet sich mit dem Server, meldet das Konto an (NTLM) und öffnet die Freigabe.
func openSMB(ctx context.Context, t *SMBTarget, password string) (*smbTarget, error) {
	ctx, cancel := context.WithTimeout(ctx, smbTimeout)
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", smbAddr(t.Server))
	if err != nil {
		cancel()
		return nil, err
	}
	dialer := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: t.User, Password: password, Domain: t.Domain}}
	sess, err := dialer.DialContext(ctx, conn)
	if err != nil {
		_ = conn.Close()
		cancel()
		return nil, &smbPhaseError{phase: phaseLogin, err: err}
	}
	share, err := sess.WithContext(ctx).Mount(t.Share)
	if err != nil {
		bg, stop := context.WithTimeout(context.Background(), 5*time.Second)
		_ = sess.WithContext(bg).Logoff()
		stop()
		_ = conn.Close()
		cancel()
		return nil, &smbPhaseError{phase: phaseShare, err: err}
	}
	return &smbTarget{t: t, conn: conn, sess: sess, share: share.WithContext(ctx), cancel: cancel}, nil
}

func (s *smbTarget) path(name string) string {
	if s.t.Dir == "" {
		return name
	}
	return s.t.Dir + "/" + name // die Bibliothek wandelt / in \ um
}

func (s *smbTarget) MkdirAll() error {
	if s.t.Dir == "" {
		return nil
	}
	return s.share.MkdirAll(s.t.Dir, 0o755)
}
func (s *smbTarget) ReadFile(name string) ([]byte, error) { return s.share.ReadFile(s.path(name)) }
func (s *smbTarget) WriteFile(name string, data []byte) error {
	return s.share.WriteFile(s.path(name), data, 0o600)
}
func (s *smbTarget) Remove(name string) error { return s.share.Remove(s.path(name)) }

// Replace: SMB ersetzt beim Umbenennen keine vorhandene Datei. Die alte Datei wird deshalb kurz beiseitegelegt
// und bei einem Fehler zurückgeholt, damit nie beide Dateien fehlen.
func (s *smbTarget) Replace(tmp, name string) error {
	dest := s.path(name)
	if _, err := s.share.Stat(dest); err != nil { // nichts zu ersetzen
		return s.share.Rename(s.path(tmp), dest)
	}
	old := dest + ".old"
	_ = s.share.Remove(old) // Rest eines früheren Fehlers
	if err := s.share.Rename(dest, old); err != nil {
		return err
	}
	if err := s.share.Rename(s.path(tmp), dest); err != nil {
		_ = s.share.Rename(old, dest)
		return err
	}
	_ = s.share.Remove(old)
	return nil
}

func (s *smbTarget) Close() error {
	bg, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_ = s.share.WithContext(bg).Umount()
	_ = s.sess.WithContext(bg).Logoff()
	err := s.conn.Close()
	s.cancel()
	return err
}

// openTarget öffnet das Ziel des Profils. Bei einer Freigabe wird das gespeicherte Passwort benutzt.
func (p *Profile) openTarget(ctx context.Context) (targetFS, error) {
	if p.SMB == nil {
		return localTarget{dir: p.TargetDir}, nil
	}
	pw, err := loadSMBSecret(p.ID)
	if err != nil {
		return nil, err
	}
	t, err := openSMB(ctx, p.SMB, pw)
	if err != nil {
		return nil, uerr(fmt.Sprintf("Die Freigabe „%s“ ist nicht erreichbar. %s", p.SMB.label(), explainSMB(err, p.SMB)), err.Error())
	}
	return t, nil
}

// writeHint erklärt einen Fehler beim Schreiben ins Ziel.
func (p *Profile) writeHint(err error) string {
	if p.SMB != nil {
		return explainSMB(err, p.SMB)
	}
	return "Bitte Schreibrechte prüfen."
}

// testTarget prüft, ob in das Ziel des Profils geschrieben werden kann (vor der Bestellung beim Anbieter).
func (p *Profile) testTarget(ctx context.Context) (string, error) {
	if p.SMB == nil {
		return testWrite(p.TargetDir)
	}
	pw, err := loadSMBSecret(p.ID)
	if err != nil {
		return "", err
	}
	return testSMB(ctx, p.SMB, pw)
}

// testSMBRequest prüft die Eingaben der Oberfläche und dann die Verbindung.
func testSMBRequest(ctx context.Context, in *SMBRequest) (string, error) {
	t, err := validateSMB(in)
	if err != nil {
		return "", err
	}
	if err := validateSMBPassword(in.Password); err != nil {
		return "", err
	}
	return testSMB(ctx, t, in.Password)
}

// testSMB prüft Erreichbarkeit, Anmeldung und Schreibrecht (legt den Ordner bei Bedarf kurz an).
func testSMB(ctx context.Context, t *SMBTarget, password string) (string, error) {
	s, err := openSMB(ctx, t, password)
	if err != nil {
		return "", errors.New(explainSMB(err, t))
	}
	defer s.Close()

	// Fehlende Ordner der Kette merken, um sie danach wieder zu entfernen (nur diese, von innen nach außen).
	var created []string
	if t.Dir != "" {
		cur := ""
		missing := false
		for _, seg := range strings.Split(t.Dir, "/") {
			if cur != "" {
				cur += "/"
			}
			cur += seg
			if !missing {
				if _, serr := s.share.Stat(cur); serr == nil {
					continue
				} else if !errors.Is(serr, os.ErrNotExist) {
					return "", fmt.Errorf("Der Ordner „%s“ ist nicht lesbar: %s", cur, explainSMB(serr, t))
				}
				missing = true
			}
			if merr := s.share.Mkdir(cur, 0o755); merr != nil {
				s.removeDirs(created)
				return "", fmt.Errorf("Der Ordner existiert nicht und lässt sich nicht anlegen: %s", explainSMB(merr, t))
			}
			created = append(created, cur)
		}
	}
	f := ".certbumblebee-test-" + randomHex(4)
	if werr := s.WriteFile(f, []byte("test")); werr != nil {
		s.removeDirs(created)
		return "", fmt.Errorf("In diesen Ordner kann nicht geschrieben werden: %s", explainSMB(werr, t))
	}
	_ = s.Remove(f)
	s.removeDirs(created)
	if len(created) > 0 {
		return "Der Ordner existiert noch nicht, lässt sich aber anlegen und beschreiben. Das Programm legt ihn beim Ausstellen an.", nil
	}
	return fmt.Sprintf("Anmeldung und Schreibzugriff sind in Ordnung (Konto %s auf %s).", t.account(), t.label()), nil
}

// removeDirs entfernt die angegebenen leeren Ordner von innen nach außen.
func (s *smbTarget) removeDirs(dirs []string) {
	for i := len(dirs) - 1; i >= 0; i-- {
		_ = s.share.Remove(dirs[i])
	}
}

// Statuscodes des Servers (NTSTATUS), soweit sie für Admins eine eigene Erklärung brauchen.
const (
	ntLogonFailure        = 0xC000006D
	ntWrongPassword       = 0xC000006A
	ntAccountRestriction  = 0xC000006E
	ntAccountDisabled     = 0xC0000072
	ntPasswordExpired     = 0xC0000071
	ntPasswordMustChange  = 0xC0000224
	ntAccountLockedOut    = 0xC0000234
	ntAccountExpired      = 0xC0000193
	ntLogonTypeNotGranted = 0xC000015B
	ntBadNetworkName      = 0xC00000CC
	ntSharingViolation    = 0xC0000043
	ntDiskFull            = 0xC000007F
	ntNotSupported        = 0xC00000BB
)

// Phasen beim Öffnen einer Freigabe. Ein „Zugriff verweigert“ bedeutet je nach Phase etwas anderes.
const (
	phaseLogin = "login" // Anmeldung des Kontos
	phaseShare = "share" // Zugriff auf die Freigabe selbst
)

type smbPhaseError struct {
	phase string
	err   error
}

func (e *smbPhaseError) Error() string { return e.err.Error() }
func (e *smbPhaseError) Unwrap() error { return e.err }

// explainSMB macht aus einem Fehler eine Erklärung für Admins (ein oder zwei Sätze).
func explainSMB(err error, t *SMBTarget) string {
	var ph *smbPhaseError
	if errors.As(err, &ph) && errors.Is(ph.err, os.ErrPermission) {
		if ph.phase == phaseLogin {
			return "Die Anmeldung wurde abgelehnt. Bitte Benutzer, Domäne und Passwort prüfen."
		}
		return fmt.Sprintf("Das Konto %s darf auf die Freigabe „%s“ nicht zugreifen. Bitte Benutzername und Passwort sowie die Rechte auf der Freigabe prüfen.", t.account(), t.Share)
	}
	var re *smb2.ResponseError
	if errors.As(err, &re) {
		switch re.Code {
		case ntLogonFailure, ntWrongPassword:
			return "Die Anmeldung wurde abgelehnt. Bitte Benutzer, Domäne und Passwort prüfen."
		case ntAccountDisabled, ntAccountLockedOut, ntAccountExpired, ntAccountRestriction, ntLogonTypeNotGranted:
			return "Das Konto darf sich nicht anmelden (gesperrt, deaktiviert, abgelaufen oder eingeschränkt)."
		case ntPasswordExpired, ntPasswordMustChange:
			return "Das Passwort des Kontos ist abgelaufen und muss zuerst geändert werden."
		case ntBadNetworkName:
			return fmt.Sprintf("Die Freigabe „%s“ gibt es auf dem Server nicht. Bitte den Namen der Freigabe prüfen.", t.Share)
		case ntSharingViolation:
			return "Die Datei wird gerade von einem Programm benutzt."
		case ntDiskFull:
			return "Auf der Freigabe ist kein Speicherplatz mehr frei."
		case ntNotSupported:
			return "Der Server unterstützt diese Anfrage nicht."
		}
	}
	switch {
	case errors.Is(err, os.ErrPermission):
		return fmt.Sprintf("Zugriff verweigert: Das Konto %s darf hier nicht schreiben. Bitte die Rechte auf der Freigabe und im Ordner prüfen.", t.account())
	case errors.Is(err, os.ErrNotExist):
		return "Ein Ordner im Pfad fehlt oder die Datei gibt es nicht."
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Sprintf("Der Server „%s“ hat nicht rechtzeitig geantwortet.", t.Server)
	case errors.Is(err, context.Canceled):
		return "Der Vorgang wurde abgebrochen."
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return fmt.Sprintf("Der Servername „%s“ ist nicht bekannt. Bitte Schreibweise prüfen oder die IP-Adresse verwenden.", t.Server)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return fmt.Sprintf("Der Server „%s“ antwortet nicht. Stimmen Name oder Adresse, und ist Port 445 in der Firewall offen?", t.Server)
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "refused"):
		return fmt.Sprintf("Der Server „%s“ nimmt keine SMB-Verbindung an. Ist SMB eingeschaltet und Port 445 in der Firewall offen?", t.Server)
	case strings.Contains(msg, "no route to host") || strings.Contains(msg, "unreachable"):
		return fmt.Sprintf("Der Server „%s“ ist aus dem Netz nicht erreichbar.", t.Server)
	}
	var te *smb2.TransportError
	if errors.As(err, &te) || strings.Contains(msg, "EOF") || strings.Contains(msg, "reset") {
		return "Die Verbindung zum Server wurde unterbrochen. Spricht der Server SMB 2 oder 3? SMB 1 wird nicht unterstützt."
	}
	return "Unerwarteter Fehler: " + msg
}
