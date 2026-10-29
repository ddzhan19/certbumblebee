import json, os, re, subprocess, sys, urllib.request
from playwright.sync_api import sync_playwright, expect

S = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('SHOTS', S + '/uitest/shots'); os.makedirs(SHOTS, exist_ok=True)
R = S + '/uitest/' + os.environ['RUN']
link = re.search(r'Link: (\S+)', open(R + '/server.log', encoding='utf-8').read()).group(1)
MOCK = 'http://127.0.0.1:18443'
def sh(args, inp=None): return subprocess.run(args, input=inp, capture_output=True, text=True, check=True).stdout
def set_txt(name, values):
    urllib.request.urlopen(urllib.request.Request(MOCK + '/__txt', data=json.dumps({'name': name, 'values': values}).encode(), method='POST')).read()
errors = []
def ok(m): print('  PASS', m)

with sync_playwright() as pw:
    b = pw.chromium.launch(args=['--no-proxy-server'])
    ctx = b.new_context(viewport={'width': 1180, 'height': 900}, accept_downloads=True, locale='de-DE')   # CSP bleibt aktiv
    page = ctx.new_page()
    page.on('pageerror', lambda e: errors.append('pageerror: %s' % e))
    page.on('console', lambda m: errors.append('console: ' + m.text) if m.type == 'error' else None)
    page.goto(link)
    expect(page.locator('#foot-version')).to_contain_text(re.search(r'appVersion\s*=\s*"([^"]+)"', open(S + '/version.go', encoding='utf-8').read()).group(1))
    page.click('#tab-wild')
    page.click('#wgo1')
    expect(page.locator('#werr1')).to_contain_text('mindestens eine Domain')
    page.fill('#wdomains', 'beispiel.de\n*.beispiel.de')
    page.click('#wgo1')
    expect(page.locator('#werr1')).to_contain_text('Passwort')
    page.click('#wpw-gen'); pw_value = page.input_value('#wpfxpw'); assert len(pw_value) == 20
    page.click('#view-wild details.more summary')
    page.select_option('#wserver', 'custom'); page.fill('#wcustomurl', MOCK + '/directory')
    page.click('#wgo1')
    expect(page.locator('#werr1')).to_contain_text('Nutzungsbedingungen')
    page.check('#wtos'); page.click('#wgo1')
    expect(page.locator('#view-wild .panel[data-step="2"]')).to_be_visible(timeout=30000)
    ok('Schritt 2 erreicht (CSP aktiv, ACME-Mock über 127.0.0.1)')
    names = page.locator('#wrecords .record .row:nth-child(2) .v').all_inner_texts()
    values = page.locator('#wrecords .stl').evaluate_all('els => els.map(e => e.dataset.val)')
    assert names == ['_acme-challenge.beispiel.de'], names
    assert len(values) == 2 and values[0] != values[1], values
    ok('Ein Eintrag mit Name und zwei verschiedenen TXT-Werten')
    page.screenshot(path=SHOTS + '/w2-dns.png', full_page=True)

    state = {'vals': []}
    def doh(route):
        route.fulfill(status=200, content_type='application/dns-json', headers={'access-control-allow-origin': '*'},
                      body=json.dumps({'Answer': [{'name': 'x', 'type': 16, 'TTL': 60, 'data': '"%s"' % v} for v in state['vals']]}))
    page.route('https://cloudflare-dns.com/**', doh)
    page.click('.check-dns')
    expect(page.locator('#wrecords .stl.no').first).to_contain_text('Noch nicht sichtbar')
    state['vals'] = values; set_txt('_acme-challenge.beispiel.de', values)
    page.click('.check-dns')
    expect(page.locator('#wrecords .stl.ok')).to_have_count(2)
    ok('DNS-Prüfung: erst nicht sichtbar, dann beide sichtbar')

    page.click('#wgo2')
    expect(page.locator('#view-wild .panel[data-step="4"]')).to_be_visible(timeout=60000)
    expect(page.locator('#wurkunde')).to_contain_text('*.beispiel.de')
    page.wait_for_timeout(700)
    page.screenshot(path=SHOTS + '/w4-fertig.png', full_page=True)
    ok('Ausstellung bis Schritt 4')
    page.click('#wpw4-show'); assert page.inner_text('#wpwshow') == pw_value
    with page.expect_download() as d:
        page.click('#wdl-pfx')
    path = R + '/wild.pfx'; d.value.save_as(path)
    assert d.value.suggested_filename == 'beispiel.de.pfx', d.value.suggested_filename
    assert sh(['openssl', 'pkcs12', '-in', path, '-passin', 'pass:' + pw_value, '-nokeys']).count('BEGIN CERTIFICATE') == 2
    leaf = sh(['openssl', 'pkcs12', '-in', path, '-passin', 'pass:' + pw_value, '-nokeys', '-clcerts'])
    san = sh(['openssl', 'x509', '-noout', '-ext', 'subjectAltName'], leaf)
    assert '*.beispiel.de' in san and 'beispiel.de' in san
    ok('PFX-Download: Passwort, Kette und SANs stimmen (OpenSSL)')
    # Weitere Dateien: .crt, .cer (binär), Kette, fullchain, .key, .csr
    page.click('#wmore summary')
    def dl(btn):
        with page.expect_download() as dd:
            page.click(btn)
        pth = R + '/wild_' + dd.value.suggested_filename
        dd.value.save_as(pth)
        return dd.value.suggested_filename, pth
    def run(args):
        r = subprocess.run(args, capture_output=True, text=True); return r.stdout + r.stderr
    n, f = dl('#wdl-crt'); assert n == 'beispiel.de.crt', n
    txt = open(f).read(); assert txt.count('BEGIN CERTIFICATE') == 1 and '\r' not in txt
    assert '*.beispiel.de' in run(['openssl', 'x509', '-in', f, '-noout', '-ext', 'subjectAltName'])
    n, f = dl('#wdl-cer'); assert n == 'beispiel.de.cer' and open(f).read().startswith('-----BEGIN CERTIFICATE'), n
    n, f = dl('#wdl-cerder'); assert n == 'beispiel.de.cer', n
    assert not open(f, 'rb').read().startswith(b'-----BEGIN')
    assert '*.beispiel.de' in run(['openssl', 'x509', '-inform', 'der', '-in', f, '-noout', '-ext', 'subjectAltName'])
    n, f = dl('#wdl-chain'); assert n == 'beispiel.de-chain.pem', n; chain_n = open(f).read().count('BEGIN CERTIFICATE'); assert chain_n == 1, chain_n
    n, f = dl('#wdl-full'); assert n == 'beispiel.de-fullchain.pem', n; assert open(f).read().count('BEGIN CERTIFICATE') == chain_n + 1
    n, f = dl('#wdl-key'); assert n == 'beispiel.de.key', n
    assert 'RSA key ok' in run(['openssl', 'rsa', '-in', f, '-noout', '-check'])
    key_mod = run(['openssl', 'rsa', '-in', f, '-noout', '-modulus'])
    n, f = dl('#wdl-csr'); assert n == 'beispiel.de.csr', n
    o = run(['openssl', 'req', '-in', f, '-noout', '-verify', '-text'])
    assert 'verify OK' in o and 'DNS:beispiel.de' in o and '*.beispiel.de' in o, o[-300:]
    assert run(['openssl', 'req', '-in', f, '-noout', '-modulus']) == key_mod
    ok('Weitere Dateien: .crt, .cer (PEM und binär), Kette, fullchain, .key, .csr gültig; Schlüssel passt zur Anforderung')
    page.click('#wagain')
    expect(page.locator('#view-wild .panel[data-step="1"]')).to_be_visible()
    ok('Zurücksetzen')

    # Sicherheitsregeln der Schnittstelle
    ctx2 = b.new_context()
    api = ctx2.request
    r = api.get('http://127.0.0.1:8765/api/info'); assert r.status == 401, r.status
    ok('Ohne Sitzung: API liefert 401')
    r = ctx.request.post('http://127.0.0.1:8765/api/quit', data='{}', headers={'Content-Type': 'text/plain'}); assert r.status == 403, r.status
    ok('POST ohne JSON-Kopf wird abgelehnt (403)')
    r = ctx.request.post('http://127.0.0.1:8765/api/profiles', data='{}', headers={'Content-Type': 'application/json', 'X-ZA': '1', 'Origin': 'http://evil.example'}); assert r.status == 403, r.status
    ok('Fremde Herkunft (Origin) wird abgelehnt (403)')
    r = ctx.request.get('http://127.0.0.1:8765/api/info', headers={'Host': 'evil.example'}); 
    print('  Host-Test Status:', r.status)
    H = {'Content-Type': 'application/json', 'X-ZA': '1'}
    h = ctx.request.get('http://127.0.0.1:8765/api/info').headers
    assert 'default-src' in h.get('content-security-policy', '') and h.get('x-frame-options') == 'DENY'
    ok('Sicherheits-Header gesetzt')
    r = ctx.request.get('http://127.0.0.1:8765/api/fs?path=' + '%2e%2e%2f%2e%2e'); print('  fs ..:', r.status)
    b.close()

errs = [e for e in errors if '409' not in e]
print('Konsolenfehler:', errs if errs else 'keine')
sys.exit(1 if errs else 0)
