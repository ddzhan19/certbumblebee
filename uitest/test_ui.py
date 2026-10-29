import re, sys, os, json, glob, subprocess, time
from playwright.sync_api import sync_playwright, expect

S = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('SHOTS', S + '/uitest/shots'); os.makedirs(SHOTS, exist_ok=True)
RUN = os.environ['RUN']; R = S + '/uitest/' + RUN
link = re.search(r'Link: (\S+)', open(R + '/server.log', encoding='utf-8').read()).group(1)
TARGET = R + '/target'
ok = 0
def check(name, cond, extra=''):
    global ok
    print(('PASS ' if cond else 'FAIL ') + name + (' – ' + str(extra) if extra and not cond else ''))
    if not cond: check.failed = True
    else: ok += 1
check.failed = False

with sync_playwright() as pw:
    b = pw.chromium.launch()
    ctx = b.new_context(viewport={'width': 1180, 'height': 900}, accept_downloads=True, bypass_csp=True)
    page = ctx.new_page()
    errors = []
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.on('console', lambda m: errors.append(m.text) if m.type == 'error' else None)
    page.goto(link)
    page.wait_for_selector('#foot-version:not(:empty)')
    check('Titel', page.title() == 'Certbumblebee')
    check('Kopf mit Name', page.inner_text('h1') == 'Certbumblebee')
    check('Fuß: Programmiert von', 'Programmiert von Dzhan Chelebi' in page.inner_text('.foot-app'))
    check('Version im Fuß', '1.2.0' in page.inner_text('#foot-version'))
    page.screenshot(path=SHOTS + '/e1-ausstellen.png', full_page=True)

    # Ordnerauswahl
    page.click('#target-browse')
    page.wait_for_selector('#picker[open] .pk-list li')
    page.fill('#pk-path', TARGET)
    page.click('#pk-open')
    page.wait_for_function("document.querySelector('#pk-path').value === %s" % json.dumps(TARGET))
    page.screenshot(path=SHOTS + '/e2-picker.png')
    page.click('#pk-choose')
    page.wait_for_timeout(300)
    check('Ordnerauswahl übernimmt Pfad', page.input_value('#target') == TARGET, page.input_value('#target'))
    page.click('#target-test')
    page.wait_for_selector('#target-result:not([hidden])')
    check('Zugriff testen ok', 'ok' in page.get_attribute('#target-result', 'class') and 'Schreibzugriff' in page.inner_text('#target-result'), page.inner_text('#target-result'))
    page.fill('#target', '/proc/nein/dort')
    page.click('#target-test')
    page.wait_for_function("document.querySelector('#target-result').className.includes('no')")
    check('Zugriff testen: Fehler verständlich', len(page.inner_text('#target-result')) > 10, page.inner_text('#target-result'))
    page.fill('#target', TARGET)

    # Port-Test (5002 frei)
    page.click('#port-test'); page.wait_for_selector('#port-result:not([hidden])')
    check('Port-Test meldet frei', 'frei' in page.inner_text('#port-result'), page.inner_text('#port-result'))

    # Fehlermeldungen
    page.click('#go-issue')
    check('Pflichtfeld Domain', 'Domain' in page.inner_text('#err-issue'), page.inner_text('#err-issue'))
    page.fill('#domains', '*.pebble-test.example')
    page.click('#go-issue')
    check('Wildcard verweist auf Tab', 'Wildcard / DNS (manuell)' in page.inner_text('#err-issue'))

    # Dateiauswahl: Grundzustand, Vorschau, Passwort nur bei PFX, mindestens eine Datei
    check('Dateiauswahl: nur PFX vorgewählt', page.evaluate("() => [...document.querySelectorAll('input[name=out]:checked')].map(e => e.value).join()") == 'pfx')
    check('Dateiauswahl: Passwortfeld sichtbar', page.is_visible('#pfx-opts'))
    check('Dateiauswahl: Formatwahl noch versteckt', not page.is_visible('#certfmt-wrap'))
    page.fill('#domains', 'ui.pebble-test.example')
    check('Vorschau mit Domain-Name', 'ui.pebble-test.example.pfx' in page.inner_text('#out-preview'), page.inner_text('#out-preview'))
    page.uncheck('input[name="out"][value="pfx"]')
    check('Ohne PFX: Passwortfeld weg', not page.is_visible('#pfx-opts'))
    check('Vorschau ohne Auswahl', 'Keine Datei' in page.inner_text('#out-preview'))
    page.check('#tos')
    page.click('#go-issue')
    check('Ohne Datei: verständlicher Fehler', 'mindestens eine Datei' in page.inner_text('#err-issue'), page.inner_text('#err-issue'))
    page.uncheck('#tos')
    page.check('input[name="out"][value="cert"]')
    check('Formatwahl erscheint bei Zertifikat', page.is_visible('#certfmt-wrap'))
    page.select_option('#certfmt', 'cer-der')
    page.check('input[name="out"][value="key"]')
    check('Warnung beim privaten Schlüssel', page.is_visible('#key-warn'))
    page.fill('#filename', 'Mein Server.PFX')
    check('Vorschau entfernt Endung und passt Format an', 'Mein Server.cer' in page.inner_text('#out-preview') and 'Mein Server.key' in page.inner_text('#out-preview') and '.pfx' not in page.inner_text('#out-preview').replace('Mein Server.PFX', ''), page.inner_text('#out-preview'))
    page.fill('#filename', '')
    for k in ('pfx', 'chain', 'fullchain', 'csr'):
        page.check('input[name="out"][value="%s"]' % k)
    page.screenshot(path=SHOTS + '/e2b-dateiauswahl.png', full_page=True)

    # Ausstellen (echt gegen Pebble)
    page.fill('#domains', 'ui.pebble-test.example')
    page.click('#pw-gen')
    pw_text = page.input_value('#pfxpw')
    check('Passwort erzeugt', len(pw_text) == 20)
    page.click('#view-issue details.more summary')
    page.select_option('#server', 'custom')
    page.fill('#customurl', 'https://localhost:14000/dir')
    page.check('#tos')
    page.click('#go-issue')
    page.wait_for_selector('#prog-issue .task')
    page.screenshot(path=SHOTS + '/e3-lauf.png')
    page.wait_for_selector('#issue-done:not([hidden])', timeout=60000)
    page.wait_for_timeout(700)
    page.screenshot(path=SHOTS + '/e4-fertig.png', full_page=True)
    check('Urkunde zeigt Domain', 'ui.pebble-test.example' in page.inner_text('#done-urkunde'))
    pfx = TARGET + '/ui.pebble-test.example.pfx'
    check('PFX im Zielordner', os.path.exists(pfx))
    r = subprocess.run(['openssl', 'pkcs12', '-in', pfx, '-passin', 'pass:' + pw_text, '-legacy', '-nokeys', '-clcerts'], capture_output=True, text=True)
    check('PFX mit Passwort lesbar (OpenSSL)', 'BEGIN CERTIFICATE' in r.stdout, r.stderr[-200:])
    B = TARGET + '/ui.pebble-test.example'
    check('Fertig-Seite listet 6 Dateien', page.locator('#done-info ul.files li').count() == 6, page.inner_text('#done-info'))
    check('Fertig-Seite nennt Dateiart', 'Zertifikatsanforderung' in page.inner_text('#done-info') and 'Privater Schlüssel' in page.inner_text('#done-info'))
    for ext in ('.pfx', '.cer', '-chain.pem', '-fullchain.pem', '.key', '.csr'):
        check('Datei vorhanden: ' + ext, os.path.exists(B + ext))
    r = subprocess.run(['openssl', 'x509', '-inform', 'der', '-in', B + '.cer', '-noout', '-ext', 'subjectAltName'], capture_output=True, text=True)
    check('.cer ist binär (DER) und lesbar', 'DNS:ui.pebble-test.example' in r.stdout, r.stdout + r.stderr[-200:])
    check('.cer ist wirklich binär', not open(B + '.cer', 'rb').read().startswith(b'-----BEGIN'))
    r = subprocess.run(['openssl', 'req', '-in', B + '.csr', '-noout', '-verify', '-subject'], capture_output=True, text=True)
    check('.csr gültig', 'verify OK' in (r.stdout + r.stderr) and 'ui.pebble-test.example' in r.stdout, r.stdout + r.stderr)
    full_txt = open(B + '-fullchain.pem').read(); chain_txt = open(B + '-chain.pem').read()
    check('fullchain = Zertifikat + Kette', full_txt.count('BEGIN CERTIFICATE') == chain_txt.count('BEGIN CERTIFICATE') + 1 and full_txt.endswith(chain_txt))
    k1 = subprocess.run(['openssl', 'rsa', '-in', B + '.key', '-noout', '-modulus'], capture_output=True, text=True).stdout
    k2 = subprocess.run(['openssl', 'x509', '-inform', 'der', '-in', B + '.cer', '-noout', '-modulus'], capture_output=True, text=True).stdout
    check('Schlüssel passt zum Zertifikat', k1 and k1 == k2)

    # Übersicht
    page.click('#to-overview')
    page.wait_for_selector('.card')
    check('Karte in der Übersicht', 'ui.pebble-test.example' in page.inner_text('.card h3'))
    check('Karte: Aufgabe vorhanden', 'Aufgabe vorhanden' in page.inner_text('.card'), page.inner_text('.card'))
    check('Karte: 6 Dateien, alle vorhanden', page.locator('.card .facts ul.files li').count() == 6 and page.locator('.card .facts ul.files li .st.ok').count() == 6, page.inner_text('.card .facts'))
    check('Karte: Zielordner genannt', TARGET in page.inner_text('.card .facts'))
    page.screenshot(path=SHOTS + '/e5-uebersicht.png', full_page=True)

    page.click('.card [data-act="renew"]')
    page.wait_for_selector('.card .jobmsg .notice')
    check('Erneuern: noch nicht fällig', 'nicht fällig' in page.inner_text('.card .jobmsg').lower() or 'noch' in page.inner_text('.card .jobmsg').lower(), page.inner_text('.card .jobmsg'))
    page.screenshot(path=SHOTS + '/e6-erneuern.png', full_page=True)

    page.click('.card [data-act="tasktest"]')
    page.wait_for_function("document.querySelector('.card .jobmsg .notice')", timeout=15000)
    page.wait_for_timeout(4500)
    check('Aufgabe testen liefert Ergebnis', len(page.inner_text('.card .jobmsg')) > 5, page.inner_text('.card .jobmsg'))
    page.click('.card [data-act="log"]')
    page.wait_for_selector('.card .logbox:not([hidden])')
    check('Protokoll zeigt Einträge', len(page.inner_text('.card .logbox')) > 20)

    # Erzwingen mit Rückfrage
    page.click('.card details.menu summary')
    page.click('.card [data-act="force"]')
    page.wait_for_selector('#confirm[open]')
    page.screenshot(path=SHOTS + '/e7-rueckfrage.png')
    page.click('#cf-yes')
    page.wait_for_selector('.card[data-busy="1"]')
    page.wait_for_selector('.card:not([data-busy])', timeout=60000)
    check('Erzwingen: neues Zertifikat', 'rneuert' in page.inner_text('.card .jobmsg') or 'ausgestellt' in page.inner_text('.card .jobmsg').lower(), page.inner_text('.card .jobmsg'))

    # Doppelt anlegen -> Ersetzen-Hinweis
    page.click('#tab-issue')
    page.click('#issue-again')
    page.fill('#domains', 'ui.pebble-test.example')
    page.fill('#target', TARGET); page.fill('#pfxpw', 'Zweites-Passwort-1')
    page.evaluate("() => { document.querySelector('#view-issue details.more').open = true; }")
    page.select_option('#server', 'custom'); page.fill('#customurl', 'https://localhost:14000/dir'); page.check('#tos')
    page.click('#go-issue')
    page.wait_for_selector('#exists-issue:not([hidden])', timeout=20000)
    check('Doppelt: Ersetzen-Hinweis', 'schon eine Einrichtung' in page.inner_text('#exists-issue'))
    page.screenshot(path=SHOTS + '/e8-ersetzen.png', full_page=True)
    page.click('#no-replace')

    # Webroot-Modus
    page.fill('#domains', 'web.pebble-test.example')
    page.check('input[name="method"][value="webroot"]')
    page.fill('#webroot', R + '/web')
    page.uncheck('input[name="out"][value="pfx"]')
    page.check('input[name="out"][value="cert"]'); page.check('input[name="out"][value="key"]')
    check('Zurückgesetzt: Formatwahl sichtbar bei Zertifikat', page.is_visible('#certfmt-wrap'))
    page.uncheck('#auto')
    # „Vorhandener Webserver“: ein einfacher Dateiserver auf dem Prüfport liefert den Webordner aus
    web = subprocess.Popen(['python3', '-m', 'http.server', '5002', '--bind', '0.0.0.0', '--directory', R + '/web'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.8)
    page.click('#go-issue')
    try:
        page.wait_for_selector('#issue-done:not([hidden])', timeout=60000)
    except Exception:
        print('Fehlertext:', page.inner_text('#err-issue'), '|', page.inner_text('#prog-issue'))
        raise
    finally:
        web.terminate()
    check('Webroot: ohne Aufgabe fertig', 'Keine automatische Erneuerung' in page.inner_text('#done-info'))
    page.click('#to-overview')
    page.wait_for_selector('.card:nth-child(2)')
    check('Zwei Karten', page.locator('.card').count() == 2)

    # Löschen
    card = page.locator('.card', has_text='web.pebble-test.example')
    card.locator('details.menu summary').click()
    card.locator('[data-act="delete"]').click()
    page.wait_for_selector('#confirm[open]')
    page.click('#cf-yes')
    page.wait_for_function("document.querySelectorAll('.card').length === 1")
    check('Löschen entfernt Karte', page.locator('.card').count() == 1)
    check('Webroot ohne PFX: .crt und .key da, keine PFX', os.path.exists(TARGET + '/web.pebble-test.example.crt') and os.path.exists(TARGET + '/web.pebble-test.example.key') and not os.path.exists(TARGET + '/web.pebble-test.example.pfx'))
    check('Dateien bleiben nach Löschen', os.path.exists(TARGET + '/web.pebble-test.example.crt'))
    check('Kein Passwort gespeichert (ohne PFX)', not os.path.exists(R + '/data/profiles/web.pebble-test.example/pfx.secret') )

    # Konverter mit echten PEM-Dateien aus dem Profil
    d = R + '/data/profiles/ui.pebble-test.example'
    page.click('#tab-convert')
    full = open(d + '/fullchain.pem').read(); key = open(d + '/privkey.pem').read()
    page.fill('#pem-certs', full); page.fill('#pem-key', key); page.fill('#pem-pfxpw', 'Konv-Passwort-1')
    check('Konverter erkennt Zertifikat und Schlüssel', 'Zertifikat erkannt' in page.inner_text('#found') and 'Schlüssel erkannt' in page.inner_text('#found'))
    with page.expect_download() as dl:
        page.click('#make-pfx')
    path = R + '/konv.pfx'; dl.value.save_as(path)
    r = subprocess.run(['openssl', 'pkcs12', '-in', path, '-passin', 'pass:Konv-Passwort-1', '-legacy', '-nokeys', '-clcerts'], capture_output=True, text=True)
    check('Konverter-PFX gültig', 'BEGIN CERTIFICATE' in r.stdout, r.stderr[-200:])
    page.screenshot(path=SHOTS + '/e9-konverter.png', full_page=True)

    # Wildcard-Tab
    page.click('#tab-wild')
    check('Wildcard-Tab zeigt Schritt 1', page.is_visible('#wform'))
    page.screenshot(path=SHOTS + '/e10-wildcard.png', full_page=True)

    # Selbstsigniert
    page.click('#tab-issue'); page.click('#issue-again')
    page.check('input[name="method"][value="selfsigned"]')
    check('Selbstsigniert: Port-80-Teil und Anbieter ausgeblendet', not page.is_visible('#m-standalone') and not page.is_visible('#m-webroot') and page.is_visible('#m-selfsigned') and not page.is_visible('#fw-wrap'))
    check('Selbstsigniert: Nutzungsbedingungen entfallen', not page.is_visible('#tos-wrap'))
    check('Selbstsigniert: Zwischenzertifikate nicht wählbar', not page.is_visible('#lbl-chain'))
    check('Selbstsigniert: Beschriftung angepasst', 'Namen' in page.inner_text('#domains-lbl') and 'IP-Adressen' in page.inner_text('#domains-hint'))
    page.fill('#domains', 'server.example.com\nintranet\n10.20.30.40\n*.firma.local')
    check('Vorschau mit Namen ohne Endung', 'server.example.com.pfx' in page.inner_text('#out-preview'), page.inner_text('#out-preview'))
    page.select_option('#validdays', '1825')
    page.fill('#target', TARGET)
    for k in ('cert', 'key', 'csr', 'fullchain'):
        page.check('input[name="out"][value="%s"]' % k)
    page.select_option('#certfmt', 'cer')
    page.fill('#pfxpw', 'Selbst-Passwort-1')
    page.screenshot(path=SHOTS + '/e11-selbstsigniert-form.png', full_page=True)
    page.click('#go-issue')
    page.wait_for_selector('#issue-done:not([hidden])', timeout=60000)
    page.wait_for_timeout(500)
    page.screenshot(path=SHOTS + '/e12-selbstsigniert-fertig.png', full_page=True)
    check('Selbstsigniert: Hinweis zum Vertrauen', page.is_visible('#done-self') and not page.is_visible('#done-staging'))
    check('Selbstsigniert: keine Bestätigung genannt', 'Selbstsigniertes Zertifikat' in page.inner_text('#done-info') and 'Port 80' not in page.inner_text('#done-info'), page.inner_text('#done-info'))
    check('Selbstsigniert: 5 Dateien', page.locator('#done-info ul.files li').count() == 5, page.inner_text('#done-info'))
    SB = TARGET + '/server.example.com'
    for ext in ('.pfx', '.cer', '-fullchain.cer', '.key', '.csr'):
        check('Selbstsigniert: Datei ' + ext, os.path.exists(SB + ext))
    check('Selbstsigniert: keine Kette', not os.path.exists(SB + '-chain.cer'))
    def osl(*a): 
        r = subprocess.run(['openssl'] + list(a), capture_output=True, text=True); return r.returncode, r.stdout + r.stderr
    rc, out = osl('x509', '-in', SB + '.cer', '-noout', '-ext', 'subjectAltName')
    check('Selbstsigniert: Namen im Zertifikat', 'DNS:server.example.com' in out and 'DNS:intranet' in out and 'IP Address:10.20.30.40' in out and 'DNS:*.firma.local' in out, out)
    rc1, _ = osl('x509', '-in', SB + '.cer', '-noout', '-checkend', str(1820 * 86400)); rc2, _ = osl('x509', '-in', SB + '.cer', '-noout', '-checkend', str(1830 * 86400))
    check('Selbstsigniert: 5 Jahre gültig', rc1 == 0 and rc2 == 1, (rc1, rc2))
    rc, out = osl('verify', '-CAfile', SB + '.cer', SB + '.cer')
    check('Selbstsigniert: prüft sich selbst (OpenSSL)', rc == 0 and 'OK' in out, out)
    rc, out = osl('verify', '-CAfile', SB + '.cer', '-verify_hostname', 'intranet', '-purpose', 'sslserver', SB + '.cer')
    check('Selbstsigniert: gültig für Servernamen', rc == 0, out)
    rc, out = osl('pkcs12', '-in', SB + '.pfx', '-passin', 'pass:Selbst-Passwort-1', '-legacy', '-nokeys')
    check('Selbstsigniert: PFX lesbar', 'BEGIN CERTIFICATE' in out, out[-200:])
    page.click('#to-overview')
    page.wait_for_selector('.card:has-text("server.example.com")')
    sc = page.locator('.card', has_text='server.example.com')
    check('Karte: Selbstsigniert gekennzeichnet', 'Selbstsigniert' in sc.inner_text() and 'Port 80' not in sc.inner_text(), sc.inner_text())
    check('Karte: 5 Dateien vorhanden', sc.locator('ul.files li .st.ok').count() == 5)
    ser1 = osl('x509', '-in', SB + '.cer', '-noout', '-serial')[1]
    sc.locator('details.menu summary').click(); sc.locator('[data-act="force"]').click()
    page.wait_for_selector('#confirm[open]'); page.click('#cf-yes')
    page.wait_for_selector('.card:has-text("server.example.com") .jobmsg .notice', timeout=60000)
    page.wait_for_timeout(500)
    ser2 = osl('x509', '-in', SB + '.cer', '-noout', '-serial')[1]
    check('Selbstsigniert: Erzwingen tauscht das Zertifikat', ser1 != ser2 and 'erneuert' in page.locator('.card', has_text='server.example.com').locator('.jobmsg').inner_text().lower(), (ser1, ser2))
    # Fehlerfälle
    page.click('#tab-issue'); page.click('#issue-again')
    page.check('input[name="method"][value="selfsigned"]')
    page.fill('#domains', 'ex@mple/x'); page.fill('#target', TARGET); page.fill('#pfxpw', 'x')
    page.click('#go-issue')
    page.wait_for_selector('#err-issue:not([hidden])')
    check('Selbstsigniert: ungültiger Name wird erklärt', 'kein' in page.inner_text('#err-issue'), page.inner_text('#err-issue'))
    page.fill('#domains', '10.0.0.5')
    page.check('input[name="method"][value="standalone"]')
    page.check('#tos'); page.click('#go-issue')
    page.wait_for_function("document.querySelector('#err-issue').innerText.includes('IP-Adresse')", timeout=20000)
    check('Let’s Encrypt: IP-Adresse wird erklärt (Hinweis auf Selbstsigniert)', 'Selbstsigniert' in page.inner_text('#err-issue'), page.inner_text('#err-issue'))

    check('Meldungen ohne Skriptfehler', not [e for e in errors if 'favicon' not in e and '409' not in e and '400 (Bad Request)' not in e], errors)
    b.close()

print('Bestanden:', ok, '– Fehler:' , 'JA' if check.failed else 'nein')
sys.exit(1 if check.failed else 0)
