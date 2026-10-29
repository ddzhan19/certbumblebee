#!/usr/bin/env python3
"""Nachbau der Cloudflare-API für Browser-Tests. TXT-Einträge werden an pebble-challtestsrv weitergereicht,
damit der ACME-Testserver (Pebble) sie über DNS sieht. Aufruf: fakecf.py [Port]  (Standard 18787)."""
import json, sys, threading, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = 'cf-test-token-0123456789'
CHALL = 'http://127.0.0.1:8055'
ZONES = [{'id': 'zone0001', 'name': 'pebble-cf.example'}, {'id': 'zone0002', 'name': 'zweite-zone.example'}]
lock = threading.Lock()
recs = {z['id']: [] for z in ZONES}
reqs = []
nxt = [0]


def chall(path, body):
    r = urllib.request.Request(CHALL + path, data=json.dumps(body).encode(), method='POST', headers={'Content-Type': 'application/json'})
    urllib.request.urlopen(r, timeout=5).read()


def sync_host(name):
    """Alle TXT-Werte dieses Namens im Test-DNS neu setzen."""
    chall('/clear-txt', {'host': name + '.'})
    for zr in recs.values():
        for r in zr:
            if r['type'] == 'TXT' and r['name'] == name:
                chall('/set-txt', {'host': name + '.', 'value': r['content']})


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def reply(self, code, ok, result=None, errs=None):
        res = result if result is not None else []
        body = json.dumps({'success': ok, 'errors': errs or [], 'messages': [], 'result': res,
                           'result_info': {'page': 1, 'per_page': 50, 'count': len(res) if isinstance(res, list) else 0,
                                           'total_count': len(res) if isinstance(res, list) else 0, 'total_pages': 1}}).encode()
        self.send_response(code); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)

    def handle_any(self, method):
        from urllib.parse import urlparse, parse_qs
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query).items()}
        parts = [p for p in u.path.split('/') if p]
        n = int(self.headers.get('Content-Length') or 0)
        data = json.loads(self.rfile.read(n) or b'{}') if n else {}
        if parts and parts[0] == '__recs':
            self.reply(200, True, [dict(r, zone=z) for z, rs in recs.items() for r in rs]); return
        if parts and parts[0] == '__reqs':
            self.reply(200, True, reqs); return
        with lock:
            reqs.append(method + ' ' + self.path)
            if self.headers.get('Authorization') != 'Bearer ' + TOKEN:
                self.reply(401, False, None, [{'code': 9109, 'message': 'Invalid access token'}]); return
            if method == 'GET' and parts == ['zones']:
                res = [{'id': z['id'], 'name': z['name'], 'status': 'active', 'name_servers': ['127.0.0.1']} for z in ZONES if not q.get('name') or q['name'] == z['name']]
                self.reply(200, True, res); return
            if len(parts) >= 3 and parts[0] == 'zones' and parts[2] == 'dns_records':
                zid = parts[1]
                zone = next((z for z in ZONES if z['id'] == zid), None)
                if not zone:
                    self.reply(404, False, None, [{'code': 7003, 'message': 'invalid zone'}]); return
                zr = recs[zid]
                if method == 'GET' and len(parts) == 3:
                    res = [r for r in zr if all(not q.get(k) or q[k] == r[k] for k in ('type', 'name', 'content'))]
                    self.reply(200, True, res); return
                if method == 'POST' and len(parts) == 3:
                    if not data.get('name', '').endswith(zone['name']):
                        self.reply(400, False, None, [{'code': 9005, 'message': 'name outside zone'}]); return
                    if any(r['type'] == data['type'] and r['name'] == data['name'] and r['content'] == data['content'] for r in zr):
                        self.reply(400, False, None, [{'code': 81058, 'message': 'A record with those settings already exists.'}]); return
                    nxt[0] += 1
                    r = {'id': 'rec%05d' % nxt[0], 'type': data['type'], 'name': data['name'], 'content': data['content'], 'comment': data.get('comment', '')}
                    zr.append(r)
                    if r['type'] == 'TXT': sync_host(r['name'])
                    self.reply(200, True, r); return
                if method == 'DELETE' and len(parts) == 4:
                    for i, r in enumerate(zr):
                        if r['id'] == parts[3]:
                            zr.pop(i)
                            if r['type'] == 'TXT': sync_host(r['name'])
                            self.reply(200, True, {'id': r['id']}); return
                    self.reply(404, False, None, [{'code': 81044, 'message': 'Record does not exist.'}]); return
            self.reply(404, False, None, [{'code': 7000, 'message': 'No route'}])

    def do_GET(self): self.handle_any('GET')
    def do_POST(self): self.handle_any('POST')
    def do_DELETE(self): self.handle_any('DELETE')


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18787
    ThreadingHTTPServer(('127.0.0.1', port), H).serve_forever()
