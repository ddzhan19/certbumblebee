# Certbumblebee

Simplification of Certificates – ein Programm, das TLS-Zertifikate holt oder erstellt, in einem Zielordner ablegt und automatisch erneuert. Es läuft als einzelne Windows-EXE, als Linux-Programm und als Docker-Container. Bedient wird es immer im Browser.

Programmiert von Dzhan Chelebi.

## Was es kann

- **Let's Encrypt über DNS bei Cloudflare, vollautomatisch:** Mit einem API-Token legt das Programm die TXT-Einträge für die Prüfung selbst an, je Zone, wartet, bis sie ausgeliefert werden, und löscht sie danach wieder. Damit gehen **Wildcards** (`*.beispiel.de`), Domains ohne öffentlichen Webserver und die Erneuerung ohne jede Handarbeit. Mehrere Zonen und mehrere Cloudflare-Konten in einem Zertifikat sind möglich.
- **Let's Encrypt, Prüfung über Port 80:** Das Programm öffnet kurz einen eigenen Webserver auf Port 80 und beantwortet die HTTP-01-Prüfung selbst.
- **Let's Encrypt, Prüfung über einen vorhandenen Webserver (IIS, nginx, Apache):** Die Prüfdatei landet im Webroot.
- **Wildcards mit anderem DNS-Anbieter:** Der Reiter „Wildcard / DNS (manuell)“ zeigt die TXT-Einträge an, die man selbst anlegt, prüft sie vor dem Start und stellt das Zertifikat danach aus.
- **Selbstsigniert für interne Server:** Kein Internet, keine öffentliche Domain, kein Port 80. Erlaubt sind Hostnamen (auch ohne Endung), Wildcards und IP-Adressen. Gültigkeit 30 bis 3650 Tage (in der Oberfläche 1 bis 10 Jahre).
- **Dateien frei wählbar:** PFX, Zertifikat (`.crt`, `.cer`, `.pem`, auch binär/DER), Zwischenzertifikate, Zertifikat mit Kette (fullchain), privater Schlüssel (`.key`) und Zertifikatsanforderung (`.csr`).
- **Zielordner lokal oder als Netzwerkfreigabe** (Windows: `\\server\freigabe\ordner`; Container: ein Volume, z. B. `/certs`).
- **Automatische Erneuerung:** 30 Tage vor Ablauf, bei kurzer Laufzeit nach einem Drittel der Laufzeit. Unter Windows über die Aufgabenplanung (die EXE legt die Aufgabe selbst an), im Dauerbetrieb (`serve`, Container) über einen eigenen täglichen Zeitplan im Programm.
- **PEM ↔ PFX umwandeln** in der Oberfläche, in beide Richtungen. Das läuft vollständig im Browser, Schlüssel und Passwörter verlassen den Rechner nicht.

## Drei Arten, es zu betreiben

| | Windows-EXE | Docker-Container | Linux-Programm |
|---|---|---|---|
| Start | Doppelklick, Browser öffnet sich | `docker compose up -d` | `certbumblebee serve` oder `ui` |
| Oberfläche | nur auf diesem Computer (127.0.0.1), einmaliger Startlink | im Netz erreichbar, **Passwort-Anmeldung** | `ui`: lokal; `serve`: im Netz mit Passwort |
| Erneuerung | Windows-Aufgabenplanung | Zeitplan im Programm, läuft dauerhaft | `serve`: Zeitplan im Programm; sonst `renew --all` per cron/systemd |

Fertige Dateien gibt es unter [Releases](../../releases): `certbumblebee.exe` (Windows, 64 Bit) sowie `certbumblebee-linux-amd64` und `certbumblebee-linux-arm64`, jeweils mit SHA-256-Prüfsumme. Das Container-Image liegt unter `ghcr.io/ddzhan19/certbumblebee` (amd64 und arm64).

Die EXE ist nicht signiert. Windows SmartScreen zeigt deshalb beim ersten Start eine Warnung. Unter „Weitere Informationen“ lässt sie sich mit „Trotzdem ausführen“ starten, oder man entsperrt die Datei in den Dateieigenschaften.

## Cloudflare einrichten

1. Bei Cloudflare unter *Mein Profil → API-Tokens → Token erstellen* einen eigenen Token anlegen (Vorlage „Zone-DNS bearbeiten“ oder von Hand).
2. Berechtigungen: **Zone · Zone · Lesen** und **Zone · DNS · Bearbeiten**. Bei „Zonenressourcen“ nur die Zonen auswählen, für die Zertifikate gebraucht werden.
3. In Certbumblebee im Reiter **DNS-Zugänge** Namen und Token eintragen. Das Programm prüft den Token sofort und zeigt die sichtbaren Zonen. Der Token wird verschlüsselt gespeichert und nie wieder angezeigt.
4. Beim Ausstellen die Methode **„Bestätigung per DNS bei Cloudflare“** wählen. „Zonen prüfen“ zeigt vorab, welche Domain in welcher Zone landet.

So läuft es ab: Für jeden Namen wird `_acme-challenge.<domain>` als TXT-Eintrag (TTL 60 s, Kommentar „Certbumblebee ACME“) in der passenden Zone angelegt. Das Programm fragt die Nameserver der Zone direkt ab und fährt erst fort, wenn die Einträge dort ausgeliefert werden. Nach der Prüfung, auch nach einem Fehler oder Abbruch, werden die Einträge wieder gelöscht. Übrig gebliebene Einträge mit diesem Kommentar aus früheren Läufen räumt das Programm beim nächsten Lauf auf; andere Einträge fasst es nicht an.

Ohne Oberfläche lässt sich ein Zugang auch über die Umgebung vorgeben (`ZA_CLOUDFLARE_TOKEN` oder `ZA_CLOUDFLARE_TOKEN_FILE`, siehe unten). Er erscheint dann als „Aus der Umgebung“ und lässt sich nur dort ändern.

Ein Zugang, den Zertifikate benutzen, lässt sich nicht löschen. Das gilt auch für den letzten Zugang, solange Zertifikate ihre Zone automatisch darin suchen.

## Docker

Schnellstart:

```
docker run -d --name certbumblebee --restart unless-stopped \
  --stop-timeout 30 \
  -p 8080:8080 \
  -e TZ=Europe/Berlin \
  -v certbumblebee-data:/data -v "$PWD/certs:/certs" \
  ghcr.io/ddzhan19/certbumblebee:latest
docker logs certbumblebee        # beim ersten Start steht hier das erzeugte Passwort
```

Dann `http://localhost:8080` öffnen und anmelden. Für den Dauerbetrieb ist die mitgelieferte [`docker-compose.yml`](docker-compose.yml) besser: Sie legt Passwort und Schlüssel als Secrets ab, schaltet das Dateisystem auf „nur lesen“ und entzieht dem Container alle Linux-Rechte. Die Vorbereitung steht in den Kommentaren am Anfang der Datei.

Wichtig dabei:

- **Volumes:** `/data` enthält Einrichtungen, Zugänge und Protokolle und muss erhalten bleiben. `/certs` ist der Ordner, in den die Zertifikatsdateien geschrieben werden (in der Oberfläche als Zielordner `/certs` angeben). Von dort aus lassen sie sich in andere Container einhängen, z. B. nginx mit `-v ./certs:/etc/nginx/certs:ro`.
- **Benutzer:** Der Container läuft nicht als root, sondern als Benutzer `10001`. Gebundene Ordner (`./certs`) müssen ihm gehören oder für ihn beschreibbar sein: `chown 10001:10001 certs`.
- **Zeitzone:** `TZ` bestimmt, wann der tägliche Lauf stattfindet (Standard UTC). Die Zeitzonen sind im Programm enthalten.
- **Port 80:** Nur für die Methode „Dieses Programm beantwortet die Prüfung“ nötig (`-p 80:80`). Mit DNS bei Cloudflare braucht der Container keinen eingehenden Port außer 8080.
- **HTTPS für die Oberfläche:** Die Oberfläche spricht von sich aus HTTP. Das Passwort sollte nicht unverschlüsselt durchs Netz gehen. Entweder einen Reverse-Proxy mit TLS davorsetzen (dann `ZA_TRUST_PROXY=1`, der Proxy muss `X-Forwarded-For`, `-Host` und `-Proto` setzen) oder dem Container ein eigenes Zertifikat geben (`ZA_TLS_CERT`, `ZA_TLS_KEY`). Die Oberfläche warnt, wenn sie über unverschlüsseltes HTTP aus dem Netz aufgerufen wird.
- **Passwort:** Es kommt aus `ZA_PASSWORD_HASH` (bcrypt), `ZA_PASSWORD` oder `ZA_PASSWORD_FILE` (mindestens 10 Zeichen). Ist nichts gesetzt, erzeugt das Programm beim ersten Start eines und zeigt es einmal im Protokoll an. Ändern: `docker exec -it certbumblebee /certbumblebee passwd` (wirkt sofort, alle Sitzungen werden beendet; gilt nicht, wenn das Passwort über die Umgebung vorgegeben ist).
- **Gespeicherte Geheimnisse** (Cloudflare-Tokens, PFX-Passwörter) liegen mit AES-256-GCM verschlüsselt in `/data`. Der Schlüssel dazu kommt aus `ZA_SECRET_KEY` oder `ZA_SECRET_KEY_FILE`. Ohne diese Angabe legt das Programm eine Schlüsseldatei **im selben Ordner** ab; das schützt nur vor zufälligem Mitlesen. Wer das Datenvolume sichert oder weitergibt, sollte den Schlüssel getrennt halten (Docker-Secret oder Variable) und separat aufbewahren: Ohne ihn sind die gespeicherten Tokens und Passwörter nach einer Wiederherstellung unbrauchbar.
- **Zustand:** Der Healthcheck (`certbumblebee healthcheck`, im Image eingebaut) meldet „unhealthy“, wenn die Oberfläche nicht antwortet oder der Zeitplan seit über 45 Minuten nicht mehr gelaufen ist. Der Container beendet sich bei `docker stop` geordnet; laufende Vorgänge werden abgebrochen und angelegte DNS-Einträge aufgeräumt (`stop_grace_period: 30s`). Das Aufräumen kann bis zu 30 Sekunden dauern. Bei `docker run` deshalb `--stop-timeout 30` angeben (oder `docker stop -t 30`); sonst beendet Docker den Container nach 10 Sekunden hart, und Einträge bei Cloudflare bleiben bis zum nächsten Lauf stehen.

Selbst bauen: `docker build -t certbumblebee .` (mehrstufig, das Ergebnis ist ein Image aus Programm und Stammzertifikaten, etwa 10 MB).

## Aufruf

```
certbumblebee                          Oberfläche auf diesem Computer starten (Browser öffnet sich)
certbumblebee ui [--port N] [--no-browser]
certbumblebee serve [--listen :8080] [--no-scheduler]
                                       Dauerbetrieb: Oberfläche mit Passwort, eigener Zeitplan
certbumblebee passwd [--stdin]         Passwort der Oberfläche im Dauerbetrieb setzen
certbumblebee renew --id KENNUNG [--force]   Zertifikat prüfen und bei Bedarf erneuern
certbumblebee renew --all [--force]          alle eingerichteten Zertifikate
certbumblebee list                     eingerichtete Zertifikate anzeigen
certbumblebee healthcheck              prüft, ob der Dauerbetrieb antwortet (für Docker)
certbumblebee version
```

Unter Windows heißt das Programm `certbumblebee.exe`. Es ist ein Konsolenprogramm: Der Link der Oberfläche und Meldungen erscheinen im Konsolenfenster, das Schließen beendet das Programm. Für das Anlegen von Aufgaben und Zugriffsrechten fordert es Administratorrechte an.

Unter Linux ohne `serve` gibt es keine Aufgabenplanung. Die Erneuerung übernimmt dann `renew --all` aus cron oder einem systemd-Timer, z. B. täglich:

```
17 3 * * *  /usr/local/bin/certbumblebee renew --all
```

Einrichtungen, Schlüssel und Protokolle liegen im Arbeitsordner: unter Windows standardmäßig `C:\ProgramData\Certbumblebee`, unter Linux `~/.certbumblebee`, im Container `/data`. Änderbar mit `ZA_DATA`.

## Umgebungsvariablen

| Variable | Wirkung |
|---|---|
| `ZA_DATA` | Arbeitsordner für Einrichtungen, Zugänge, Schlüssel und Protokolle |
| `ZA_LISTEN` | Adresse und Port der Oberfläche im Dauerbetrieb (Standard `:8080`) |
| `ZA_PASSWORD_HASH` | bcrypt-Wert des Passworts (hat Vorrang) |
| `ZA_PASSWORD`, `ZA_PASSWORD_FILE` | Passwort im Klartext oder als Datei (Docker-Secret), mindestens 10 Zeichen |
| `ZA_SECRET_KEY`, `ZA_SECRET_KEY_FILE` | Schlüssel für gespeicherte Tokens und Passwörter (Linux und Container) |
| `ZA_CLOUDFLARE_TOKEN`, `ZA_CLOUDFLARE_TOKEN_FILE` | Cloudflare-Zugang ohne Oberfläche vorgeben |
| `ZA_TRUST_PROXY` | `1`: Hinter einem Reverse-Proxy `X-Forwarded-*` auswerten (Adresse für die Anmeldesperre, https für das Cookie) |
| `ZA_TLS_CERT`, `ZA_TLS_KEY` | Die Oberfläche selbst per HTTPS ausliefern |
| `ZA_NO_SCHEDULER` | `1`: keinen eigenen Zeitplan starten (Erneuerung dann per `renew` von außen) |
| `TZ` | Zeitzone des täglichen Laufs |

## Hinweise zur Sicherheit

- **Lokaler Betrieb** (`ui`, Windows-EXE): Die Oberfläche hört nur auf `127.0.0.1`. Der Zugang läuft über einen einmaligen Startlink und ein Cookie; Host, Herkunft und ein eigener Header werden geprüft.
- **Dauerbetrieb** (`serve`): Anmeldung mit Passwort. Nach fünf falschen Eingaben innerhalb von 15 Minuten wird die Adresse 15 Minuten gesperrt. Sitzungen enden nach 8 Stunden Leerlauf, spätestens nach 24 Stunden. Alle Schreibzugriffe verlangen einen eigenen Header, JSON und eine passende Herkunft. Wer die Oberfläche erreicht, kann Zertifikate ausstellen und Cloudflare-DNS-Einträge setzen: sie gehört nicht ins offene Internet, sondern hinter HTTPS und, wenn möglich, in ein internes Netz.
- Der Cloudflare-Token sollte nur die nötigen Zonen und nur die Rechte „Zone lesen“ und „DNS bearbeiten“ haben. Kann ein Token mehr, ist der Schaden bei einem Datenleck größer.
- Das PFX-Passwort und die Tokens werden für die Erneuerung geschützt gespeichert: unter Windows mit der Windows-Datenschutz-API (DPAPI, Computerbereich), unter Linux und im Container mit AES-256-GCM (siehe Docker).
- Die `.key`-Datei im Zielordner ist unverschlüsselt. Wer den Ordner lesen darf, kann das Zertifikat benutzen. Rechte und Freigabe entsprechend eng setzen.
- Selbstsignierte Zertifikate vertraut kein Client von allein. Die Zertifikatsdatei muss dort unter „Vertrauenswürdige Stammzertifizierungsstellen“ importiert werden, im Firmennetz am besten per Gruppenrichtlinie. Jede Erneuerung erzeugt ein neues Zertifikat mit neuem Schlüssel, dem die Clients erneut vertrauen müssen.

## Selbst bauen

Voraussetzung: Go (Version aus `go.mod`).

```
# Windows-EXE
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o certbumblebee.exe .

# Linux
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o certbumblebee .

# Container
docker build -t certbumblebee .
```

Das Programmsymbol (`icon/certbumblebee.ico`) und die Versionsangaben der EXE stehen in `resource_windows_amd64.syso`, die der Go-Linker beim Windows-Build automatisch aufnimmt. Nach einer Änderung an `version.go` oder am Symbol neu erzeugen (nur Python-Standardbibliothek):

```
python3 tools/mkresource.py
```

Die Oberfläche ist in das Programm eingebettet. Quelle ist `ui/src.html`; `ui/index.html` wird daraus erzeugt:

```
cd ui && node build.js
```

`ui/index.html` wird mit eingecheckt, damit `go build` ohne Node funktioniert.

## Tests

```
go test ./...
```

Ohne weitere Einrichtung laufen die Tests, die keinen ACME-Server brauchen (Dateiauswahl, selbstsignierte Zertifikate, Cloudflare gegen einen Nachbau der API, Anmeldung usw.). Für `openssl`-Prüfungen muss OpenSSL installiert sein.

Den kompletten Ablauf gegen einen lokalen ACME-Testserver ([Pebble](https://github.com/letsencrypt/pebble)) prüft, einschließlich Wildcard über den Cloudflare-Nachbau:

```
GOBIN=$PWD/bin go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
GOBIN=$PWD/bin go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest
bash pebble/up.sh
SSL_CERT_FILE=$PWD/pebble/pebble.crt ZA_TEST_PEBBLE=1 go test -count=1 ./...
bash pebble/down.sh
```

Die Browser-Tests der Oberfläche (Playwright für Python) liegen in `uitest/`. Jeder Testlauf braucht einen frisch gestarteten Server, weil der Startlink nur einmal gilt:

```
go build -o bin/certbumblebee-linux .
bash pebble/up.sh

# lokaler Betrieb
bash uitest/run.sh lauf1
RUN=lauf1 python3 uitest/test_ui.py
kill $(cat uitest/server.pid)

# Dauerbetrieb mit Anmeldung und Cloudflare (Nachbau der API in uitest/fakecf.py)
python3 uitest/fakecf.py &
bash uitest/run-serve.sh lauf2
RUN=lauf2 python3 uitest/test_serve.py
kill $(cat uitest/serve.pid)
```

`uitest/test_wild.py` prüft den manuellen Wildcard-Ablauf und braucht zusätzlich den ACME-Nachbau in `mock-acme/` (`cd mock-acme && npm ci && node run-mock.js`).

## Lizenz

MIT, siehe [LICENSE](LICENSE).
