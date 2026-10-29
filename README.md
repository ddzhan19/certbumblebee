# Certbumblebee

Simplification of Certificates – ein Windows-Programm (eine einzige EXE), das TLS-Zertifikate holt oder erstellt, in einem Zielordner ablegt und automatisch erneuert.

Programmiert von Dzhan Chelebi.

## Was es kann

- **Let's Encrypt, Prüfung über Port 80:** Das Programm öffnet kurz einen eigenen Webserver auf Port 80 und beantwortet die HTTP-01-Prüfung selbst.
- **Let's Encrypt, Prüfung über einen vorhandenen Webserver (IIS, nginx, Apache):** Die Prüfdatei landet im Webroot.
- **Selbstsigniert für interne Server:** Kein Internet, keine öffentliche Domain, kein Port 80. Erlaubt sind Hostnamen (auch ohne Endung), Wildcards und IP-Adressen. Gültigkeit 30 bis 3650 Tage (in der Oberfläche 1 bis 10 Jahre).
- **Wildcard-Zertifikate über DNS-01:** Geführter Ablauf im Programm. Den TXT-Eintrag legt man beim DNS-Anbieter selbst an.
- **Dateien frei wählbar:** PFX, Zertifikat (`.crt`, `.cer`, `.pem`, auch binär/DER), Zwischenzertifikate, Zertifikat mit Kette (fullchain), privater Schlüssel (`.key`) und Zertifikatsanforderung (`.csr`).
- **Zielordner lokal oder als Netzwerkfreigabe** (`\\server\freigabe\ordner`).
- **Automatische Erneuerung** über die Windows-Aufgabenplanung. Die EXE legt die Aufgabe selbst an. Erneuert wird 30 Tage vor Ablauf, bei kurzer Laufzeit nach einem Drittel der Laufzeit.
- **PEM ↔ PFX umwandeln** in der Oberfläche.

Die Oberfläche läuft in einem eigenen Programmfenster (WebView2). Ist WebView2 nicht vorhanden oder gewünscht, öffnet sie sich im Browser (`--browser`).

## Download

Die fertige `certbumblebee.exe` (Windows, 64 Bit) gibt es unter [Releases](../../releases). Zu jeder Datei gehört eine SHA-256-Prüfsumme.

Die EXE ist nicht signiert. Windows SmartScreen zeigt deshalb beim ersten Start eine Warnung. Unter „Weitere Informationen“ lässt sie sich mit „Trotzdem ausführen“ starten, oder man entsperrt die Datei in den Dateieigenschaften.

## Aufruf

```
certbumblebee.exe                          Oberfläche starten (Programmfenster)
certbumblebee.exe ui [--port N] [--browser] [--no-browser]
certbumblebee.exe renew --id KENNUNG [--force]   Zertifikat prüfen und bei Bedarf erneuern
certbumblebee.exe renew --all [--force]          alle eingerichteten Zertifikate
certbumblebee.exe list                           eingerichtete Zertifikate anzeigen
certbumblebee.exe version
```

Die automatische Erneuerung ruft `renew` über die Aufgabenplanung auf. Einrichtungen, Schlüssel und Protokolle liegen im Arbeitsordner (Standard unter `C:\ProgramData\Certbumblebee`, änderbar mit der Umgebungsvariable `ZA_DATA`).

## Hinweise zur Sicherheit

- Die Oberfläche hört nur auf `127.0.0.1`. Der Zugang läuft über einen einmaligen Startlink und ein Cookie; Host, Herkunft und ein eigener Header werden geprüft.
- Das PFX-Passwort wird für die Erneuerung mit der Windows-Datenschutz-API (DPAPI, Computerbereich) geschützt gespeichert.
- Die `.key`-Datei im Zielordner ist unverschlüsselt. Wer den Ordner lesen darf, kann das Zertifikat benutzen. Rechte und Freigabe entsprechend eng setzen.
- Selbstsignierte Zertifikate vertraut kein Client von allein. Die Zertifikatsdatei muss dort unter „Vertrauenswürdige Stammzertifizierungsstellen“ importiert werden, im Firmennetz am besten per Gruppenrichtlinie. Jede Erneuerung erzeugt ein neues Zertifikat mit neuem Schlüssel, dem die Clients erneut vertrauen müssen.

## Selbst bauen

Voraussetzung: Go (Version aus `go.mod`).

```
# Windows-EXE (ohne Konsolenfenster)
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -H windowsgui" -o certbumblebee.exe .

# Linux-Fassung für Tests (Oberfläche im Browser)
go build -o bin/certbumblebee-linux .
```

Das Programmsymbol (`icon/certbumblebee.ico`) und die Versionsangaben der EXE stehen in `resource_windows_amd64.syso`, die der Go-Linker beim Windows-Build automatisch aufnimmt. Nach einer Änderung an `version.go` oder am Symbol neu erzeugen (nur Python-Standardbibliothek):

```
python3 tools/mkresource.py
```

Die Oberfläche ist in die EXE eingebettet. Quelle ist `ui/src.html`; `ui/index.html` wird daraus erzeugt:

```
cd ui && node build.js
```

`ui/index.html` wird mit eingecheckt, damit `go build` ohne Node funktioniert.

## Tests

```
go test ./...
```

Ohne weitere Einrichtung laufen die Tests, die keinen ACME-Server brauchen (Dateiauswahl, selbstsignierte Zertifikate usw.). Für `openssl`-Prüfungen muss OpenSSL installiert sein.

Den kompletten Ablauf gegen einen lokalen ACME-Testserver ([Pebble](https://github.com/letsencrypt/pebble)) prüft:

```
GOBIN=$PWD/bin go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
GOBIN=$PWD/bin go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest
bash pebble/up.sh
SSL_CERT_FILE=$PWD/pebble/pebble.crt ZA_TEST_PEBBLE=1 go test -count=1 ./...
bash pebble/down.sh
```

Die Browser-Tests der Oberfläche (Playwright für Python) liegen in `uitest/`:

```
go build -o bin/certbumblebee-linux .
bash pebble/up.sh
bash uitest/run.sh lauf1
RUN=lauf1 python3 uitest/test_ui.py
kill $(cat uitest/server.pid)
```

`uitest/test_wild.py` prüft den Wildcard-Ablauf und braucht zusätzlich den ACME-Nachbau in `mock-acme/` (`cd mock-acme && npm ci && node run-mock.js`). Jeder Testlauf braucht einen frisch gestarteten Server, weil der Startlink nur einmal gilt.

## Lizenz

MIT, siehe [LICENSE](LICENSE). Das Verzeichnis `third_party/go-webview2` ist eine angepasste Kopie von [jchv/go-webview2](https://github.com/jchv/go-webview2) und behält deren Lizenz.
