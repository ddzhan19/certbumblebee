import json, os, re, subprocess, sys, urllib.request
from playwright.sync_api import sync_playwright, expect

S = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('SHOTS', S + '/uitest/shots'); os.makedirs(SHOTS, exist_ok=True)
R = S + '/uitest/' + os.environ['RUN']
BASE = 'http://127.0.0.1:8766'
PW = 'Test-Passwort-12345'
CF = 'http://127.0.0.1:18787'
TOKEN = 'cf-test-token-0123456789'
TARGET = R + '/target'
ok = 0
failed = False
def check(name, cond, extra=''):
    global ok, failed
    print(('PASS ' if cond else 'FAIL ') + name + (' – ' + str(extra) if extra and not cond else ''))
    if cond: ok += 1
    else: failed = True
def cf(path): return json.loads(urllib.request.urlopen(CF + path).read())['result']

with sync_playwright() as pw:
    b = pw.chromium.launch(args=['--no-proxy-server'])
    ctx = b.new_context(viewport={'width': 1180, 'height': 900}, accept_downloads=True, locale='de-DE')
    page = ctx.new_page()
    errors = []
    page.on('pageerror', lambda e: errors.append('pageerror: %s' % e))
    page.on('console', lambda m: errors.append(m.text) if m.type == 'error' and 'Failed to load resource' not in m.text else None)

    # ---- Anmeldung ----
    page.goto(BASE)
    page.wait_for_selector('#login-screen:not([hidden])')
    check('Anmeldefenster erscheint ohne Sitzung', page.is_visible('#login-pw'))
    page.screenshot(path=SHOTS + '/s1-anmeldung.png')
    page.click('#login-go')
    check('Leeres Passwort: Hinweis', 'Passwort' in page.inner_text('#login-err'), page.inner_text('#login-err'))
    page.fill('#login-pw', 'falsches-passwort-123')
    page.click('#login-go')
    expect(page.locator('#login-err')).to_contain_text('stimmt nicht')
    expect(page.locator('#login-go')).to_be_enabled()
    check('Falsches Passwort wird abgelehnt', 'stimmt nicht' in page.inner_text('#login-err'), page.inner_text('#login-err'))
    check('Anmeldefenster bleibt stehen', page.is_visible('#login-screen'))
    page.fill('#login-pw', PW)
    page.click('#login-go')
    page.wait_for_selector('#login-screen', state='hidden')
    page.wait_for_selector('#foot-version:not(:empty)')
    check('Nach der Anmeldung: Oberfläche da', page.is_visible('#tab-issue'))
    check('Abmelden sichtbar, Beenden versteckt', page.is_visible('#logout') and not page.is_visible('#quit'))
    check('Anmeldefeld ist leer', page.input_value('#login-pw') == '')

    # ---- Anzeige im Dauerbetrieb ----
    check('Zeitplan: Programm prüft täglich', 'Programm prüft täglich' in page.inner_text('#auto-small') and 'Europe/Berlin' in page.inner_text('#auto-small'), page.inner_text('#auto-small'))
    check('Zeitplan: Auto-Option aktiv', page.is_enabled('#auto') and page.is_checked('#auto'))
    check('Zeitplan: kein Konto der Aufgabe', not page.is_visible('#runas'))
    check('Zielordner-Platzhalter /certs', page.get_attribute('#target', 'placeholder') == '/certs')
    check('Datenschutz-Text für Server', 'Server' in page.inner_text('#privacy-text'), page.inner_text('#privacy-text'))
    check('Kein Warnbanner bei localhost', not page.is_visible('#banner'))

    # ---- DNS-Zugänge ----
    page.click('#tab-dns')
    page.wait_for_selector('#view-dns:not([hidden])')
    check('Leerer Zustand', 'Noch kein Zugang' in page.inner_text('#dns-list'))
    page.fill('#dns-name', ''); page.fill('#dns-token', '')
    page.click('#dns-save')
    check('Ohne Namen: Hinweis', 'Namen' in page.inner_text('#dns-err'), page.inner_text('#dns-err'))
    page.fill('#dns-name', 'Test-Cloudflare')
    page.click('#dns-save')
    check('Ohne Token: Hinweis', 'Token' in page.inner_text('#dns-err'), page.inner_text('#dns-err'))
    page.fill('#dns-token', 'falscher-token-123456')
    page.click('#dns-save')
    expect(page.locator('#dns-err')).to_contain_text('Token')
    check('Falscher Token wird verständlich abgelehnt', 'Token' in page.inner_text('#dns-err'), page.inner_text('#dns-err'))
    check('Falscher Token wird nicht gespeichert', page.locator('#dns-list .card').count() == 0)
    page.fill('#dns-token', TOKEN)
    page.click('#dns-save')
    page.wait_for_selector('#dns-list .card')
    check('Gültiger Token: Zugang in der Liste', 'Test-Cloudflare' in page.inner_text('#dns-list'))
    check('Gültiger Token: Zonen genannt', 'pebble-cf.example' in page.inner_text('#dns-ok') and 'zweite-zone.example' in page.inner_text('#dns-ok'), page.inner_text('#dns-ok'))
    check('Token-Feld wurde geleert', page.input_value('#dns-token') == '')
    page.screenshot(path=SHOTS + '/s2-dns.png', full_page=True)
    page.click('#dns-list [data-dact="test"]')
    expect(page.locator('#dns-list .dres')).to_contain_text('in Ordnung')
    check('Verbindung testen', 'pebble-cf.example' in page.inner_text('#dns-list .dres'), page.inner_text('#dns-list .dres'))
    stored = open(R + '/data/dns-accounts.json', encoding='utf-8').read()
    check('Token liegt nicht im Klartext auf der Platte', TOKEN not in stored)

    # ---- Wildcard über Cloudflare ----
    page.click('#tab-issue')
    page.check('input[name="method"][value="dns"]')
    check('Methode DNS: Zugang-Auswahl da', page.is_visible('#m-dns') and page.is_visible('#dnsaccount'))
    check('Methode DNS: Port-80-Test weg', not page.is_visible('#m-standalone'))
    check('Methode DNS: Zugang in Auswahl', 'Test-Cloudflare' in page.inner_text('#dnsaccount'), page.inner_text('#dnsaccount'))
    check('Methode DNS: Nutzungsbedingungen gefragt', page.is_visible('#tos-wrap'))
    page.fill('#domains', '*.pebble-cf.example\npebble-cf.example\nwww.unbekannt.example')
    page.click('#dns-check')
    page.wait_for_selector('#dns-check-result li')
    res = page.inner_text('#dns-check-result')
    check('Zonenprüfung: Treffer', '*.pebble-cf.example' in res and 'Zone pebble-cf.example' in res, res)
    check('Zonenprüfung: Domain ohne Zone verständlich', 'unbekannt.example' in res and res.count('✗') == 1, res)
    page.screenshot(path=SHOTS + '/s3-dns-methode.png', full_page=True)
    page.fill('#domains', '*.pebble-cf.example\npebble-cf.example')
    page.fill('#target', TARGET)
    page.uncheck('input[name="out"][value="pfx"]')
    page.check('input[name="out"][value="cert"]'); page.check('input[name="out"][value="fullchain"]'); page.check('input[name="out"][value="key"]')
    page.click('#view-issue details.more summary')
    page.select_option('#server', 'custom'); page.fill('#customurl', 'https://localhost:14000/dir')
    page.click('#go-issue')
    check('Ohne Haken bei den Bedingungen: Hinweis', 'Nutzungsbedingungen' in page.inner_text('#err-issue'), page.inner_text('#err-issue'))
    page.check('#tos')
    n_posts = len([x for x in cf('/__reqs') if x.startswith('POST /zones/zone0001/dns_records')])
    page.click('#go-issue')
    page.wait_for_selector('#prog-issue .task')
    page.wait_for_selector('#issue-done:not([hidden])', timeout=120000)
    page.wait_for_timeout(500)
    page.screenshot(path=SHOTS + '/s4-fertig.png', full_page=True)
    done = page.inner_text('#done-info')
    check('Fertig-Seite nennt Cloudflare', 'Cloudflare' in page.inner_text('#issue-done'), page.inner_text('#issue-done')[:400])
    base = TARGET + '/pebble-cf.example'
    # Wildcard-Name wird zu „wildcard_…“ oder dem ersten Namen; wir suchen die Dateien
    crts = [f for f in os.listdir(TARGET) if f.endswith('.cer') or f.endswith('.crt')]
    check('Zertifikatsdatei im Zielordner', len(crts) >= 1, os.listdir(TARGET))
    keys = [f for f in os.listdir(TARGET) if f.endswith('.key')]
    check('Schlüsseldatei im Zielordner', len(keys) == 1, os.listdir(TARGET))
    if crts:
        path = TARGET + '/' + crts[0]
        der = open(path, 'rb').read()
        args = ['openssl', 'x509', '-noout', '-ext', 'subjectAltName', '-in', path] + ([] if der.startswith(b'-----BEGIN') else ['-inform', 'der'])
        r = subprocess.run(args, capture_output=True, text=True)
        check('Zertifikat enthält Wildcard und Hauptdomain', 'DNS:*.pebble-cf.example' in r.stdout and 'DNS:pebble-cf.example' in r.stdout, r.stdout + r.stderr[-200:])
    left = cf('/__recs')
    check('Cloudflare: alle Challenge-Einträge wieder gelöscht', left == [], left)
    posts = [x for x in cf('/__reqs') if x.startswith('POST /zones/zone0001/dns_records')]
    check('Cloudflare: zwei TXT-Einträge angelegt', len(posts) - n_posts == 2, posts)

    # ---- Übersicht ----
    page.click('#to-overview')
    page.wait_for_selector('.card .facts')
    card = page.inner_text('.card')
    check('Karte: Bestätigung über Cloudflare', 'DNS-Eintrag über Cloudflare' in card and 'alle Zugänge' in card, card)
    check('Karte: Zeitplan des Programms', 'durch das Programm' in card and 'Zeitplan aktiv' in card, card)
    check('Karte: kein „Aufgabe testen“', page.locator('.card [data-act="tasktest"]').count() == 0)
    page.screenshot(path=SHOTS + '/s5-uebersicht.png', full_page=True)
    page.click('.card [data-act="renew"]')
    page.wait_for_selector('.card .jobmsg .notice', timeout=60000)
    check('Erneuern: noch nicht fällig', 'nicht fällig' in page.inner_text('.card .jobmsg').lower() or 'noch' in page.inner_text('.card .jobmsg').lower(), page.inner_text('.card .jobmsg'))

    # ---- Zugang in Benutzung lässt sich nicht löschen ----
    page.click('#tab-dns')
    page.wait_for_selector('#dns-list .card')
    check('Zugang zeigt, wer ihn nutzt', 'pebble-cf.example' in page.inner_text('#dns-list') or 'wildcard' in page.inner_text('#dns-list').lower(), page.inner_text('#dns-list'))
    page.click('#dns-list [data-dact="delete"]')
    page.wait_for_selector('#confirm[open]')
    page.click('#cf-yes')
    expect(page.locator('#dns-msg')).to_contain_text('letzte Zugang')
    check('Löschen eines benutzten Zugangs wird verweigert', page.locator('#dns-list .card').count() == 1 and 'letzte Zugang' in page.inner_text('#dns-msg'), page.inner_text('#dns-msg'))

    # ---- Abmelden ----
    page.click('#logout')
    page.wait_for_selector('#login-screen:not([hidden])')
    check('Nach dem Abmelden wieder das Anmeldefenster', page.is_visible('#login-pw'))
    r = ctx.request.get(BASE + '/api/profiles')
    check('Ohne Sitzung liefert die API 401', r.status == 401, r.status)
    r = ctx.request.get(BASE + '/healthz')
    check('/healthz ohne Anmeldung erreichbar', r.status == 200, r.status)
    b.close()

print('Konsolenfehler:', errors if errors else 'keine')
check('Keine Konsolenfehler', not errors, errors)
print('Bestanden: %d – Fehler: %s' % (ok, 'JA' if failed else 'nein'))
sys.exit(1 if failed else 0)
