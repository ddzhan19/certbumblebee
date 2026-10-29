/* Minimaler, aber strenger ACME-Mock-Server für Tests:
 * prüft JWS-Signatur (ES256), Nonce (einmalig), url-Header, kid/jwk,
 * validiert dns-01 gegen eine vom Test gesetzte TXT-Tabelle,
 * prüft CSR (Signatur + SANs) und stellt mit einer Test-CA ein Zertifikat aus. */
const http = require('node:http');
const crypto = require('node:crypto');
const forge = require('node-forge');

const b64uDec = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
const b64u = (b) => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function makeCa() {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date(Date.now() - 86400000);
  cert.validity.notAfter = new Date(Date.now() + 10 * 365 * 86400000);
  const attrs = [{ name: 'commonName', value: 'Mock Test CA' }, { name: 'organizationName', value: 'Mock Org' }];
  cert.setSubject(attrs); cert.setIssuer(attrs);
  cert.setExtensions([{ name: 'basicConstraints', cA: true }, { name: 'keyUsage', keyCertSign: true, cRLSign: true }]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return { keys, cert };
}

function start(port) {
  const ca = makeCa();
  const base = () => `http://127.0.0.1:${port}`;
  const state = { nonces: new Set(), accounts: new Map(), orders: new Map(), authzs: new Map(), challenges: new Map(), txt: new Map(), http: new Map(), log: [], forceBadNonceOnce: false, seq: 0 };
  const id = () => (++state.seq).toString(36) + crypto.randomBytes(4).toString('hex');
  const newNonce = () => { const n = b64u(crypto.randomBytes(16)); state.nonces.add(n); return n; };

  function send(res, code, obj, extra = {}) {
    const body = typeof obj === 'string' ? obj : JSON.stringify(obj);
    res.writeHead(code, Object.assign({
      'Content-Type': typeof obj === 'string' ? 'application/pem-certificate-chain' : 'application/json',
      'Replay-Nonce': newNonce(),
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Expose-Headers': 'Link, Replay-Nonce, Location'
    }, extra));
    res.end(body);
  }
  function problem(res, code, type, detail) {
    send(res, code, { type: 'urn:ietf:params:acme:error:' + type, detail, status: code }, { 'Content-Type': 'application/problem+json' });
  }

  function thumbprintOf(jwk) {
    return b64u(crypto.createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest());
  }
  function authzObj(a) {
    return {
      status: a.status, expires: new Date(Date.now() + 86400000).toISOString(),
      identifier: { type: 'dns', value: a.domain }, wildcard: a.wildcard || undefined,
      challenges: a.chIds.map((cid) => { const c = state.challenges.get(cid); return Object.assign({ type: c.type, url: `${base()}/chall/${cid}`, token: c.token, status: c.status }, c.error ? { error: c.error } : {}); })
    };
  }
  function orderObj(o) {
    const out = { status: o.status, expires: new Date(Date.now() + 86400000).toISOString(), identifiers: o.identifiers, authorizations: o.authzIds.map((a) => `${base()}/authz/${a}`), finalize: `${base()}/finalize/${o.id}` };
    if (o.certId) out.certificate = `${base()}/cert/${o.certId}`;
    return out;
  }
  function refreshOrder(o) {
    const as = o.authzIds.map((a) => state.authzs.get(a));
    if (as.some((a) => a.status === 'invalid')) o.status = 'invalid';
    else if (o.status === 'pending' && as.every((a) => a.status === 'valid')) o.status = 'ready';
  }

  function validateChallenge(c, authz, thumb) {
    setTimeout(() => {
      const keyAuth = c.token + '.' + thumb;
      let ok = false;
      if (c.type === 'dns-01') {
        const expected = b64u(crypto.createHash('sha256').update(keyAuth).digest());
        const vals = state.txt.get('_acme-challenge.' + authz.domain) || [];
        ok = vals.includes(expected);
      } else {
        ok = state.http.get(`${authz.domain}/${c.token}`) === keyAuth;
      }
      c.status = ok ? 'valid' : 'invalid';
      if (!ok) c.error = { type: 'urn:ietf:params:acme:error:unauthorized', detail: 'Incorrect TXT record / file for ' + authz.domain, status: 403 };
      authz.status = ok ? 'valid' : 'invalid';
      const o = [...state.orders.values()].find((x) => x.authzIds.includes(authz.id)); if (o) refreshOrder(o);
    }, 150);
  }

  const server = http.createServer((req, res) => {
    const url = base() + req.url;
    if (req.method === 'OPTIONS') {
      res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '86400' });
      return res.end();
    }
    if (req.method === 'POST' && req.url === '/__txt') { // Teststeuerung: TXT-Einträge setzen
      let b = ''; req.on('data', (d) => (b += d));
      return req.on('end', () => { const j = JSON.parse(b); state.txt.set(j.name, j.values); res.writeHead(204); res.end(); });
    }
    if (req.url === '/directory') {
      return send(res, 200, { newNonce: `${base()}/new-nonce`, newAccount: `${base()}/new-acct`, newOrder: `${base()}/new-order`, meta: { termsOfService: base() + '/tos' } });
    }
    if (req.url === '/new-nonce') return send(res, req.method === 'HEAD' ? 200 : 204, '');
    if (req.method !== 'POST') return send(res, 404, { detail: 'nicht gefunden' });

    let raw = '';
    req.on('data', (d) => (raw += d));
    req.on('end', () => {
      let jws;
      try { jws = JSON.parse(raw); } catch { return problem(res, 400, 'malformed', 'kein JSON'); }
      let prot;
      try { prot = JSON.parse(b64uDec(jws.protected).toString()); } catch { return problem(res, 400, 'malformed', 'protected kaputt'); }
      if (state.forceBadNonceOnce) { state.forceBadNonceOnce = false; return problem(res, 400, 'badNonce', 'Test: badNonce erzwungen'); }
      if (!state.nonces.delete(prot.nonce)) return problem(res, 400, 'badNonce', 'unbekannter oder bereits benutzter Nonce');
      if (prot.url !== url) return problem(res, 400, 'malformed', `url im JWS (${prot.url}) passt nicht zu ${url}`);
      if (prot.alg !== 'ES256') return problem(res, 400, 'badSignatureAlgorithm', 'nur ES256');
      let jwk, acct = null;
      if (prot.jwk) { jwk = prot.jwk; if (prot.kid) return problem(res, 400, 'malformed', 'jwk und kid'); }
      else if (prot.kid) { acct = state.accounts.get(prot.kid); if (!acct) return problem(res, 400, 'accountDoesNotExist', 'Konto unbekannt'); jwk = acct.jwk; }
      else return problem(res, 400, 'malformed', 'weder jwk noch kid');
      const pub = crypto.createPublicKey({ key: jwk, format: 'jwk' });
      const okSig = crypto.verify('sha256', Buffer.from(jws.protected + '.' + jws.payload), { key: pub, dsaEncoding: 'ieee-p1363' }, b64uDec(jws.signature));
      if (!okSig) return problem(res, 400, 'malformed', 'JWS-Signatur ungültig');
      const payload = jws.payload === '' ? null : JSON.parse(b64uDec(jws.payload).toString());
      state.log.push(req.url);

      if (req.url === '/new-acct') {
        if (!payload.termsOfServiceAgreed) return problem(res, 403, 'malformed', 'AGB nicht akzeptiert');
        const kid = `${base()}/acct/${id()}`;
        state.accounts.set(kid, { jwk, contact: payload.contact });
        return send(res, 201, { status: 'valid', contact: payload.contact }, { Location: kid });
      }
      if (!acct) return problem(res, 400, 'malformed', 'kid erforderlich');

      if (req.url === '/new-order') {
        const o = { id: id(), status: 'pending', identifiers: payload.identifiers, authzIds: [], kid: prot.kid };
        for (const ident of payload.identifiers) {
          const wildcard = ident.value.startsWith('*.');
          const domain = wildcard ? ident.value.slice(2) : ident.value;
          const aid = id();
          const types = wildcard ? ['dns-01'] : ['http-01', 'dns-01'];
          const chIds = types.map((t) => { const cid = id(); state.challenges.set(cid, { type: t, token: b64u(crypto.randomBytes(24)), status: 'pending', authzId: aid }); return cid; });
          state.authzs.set(aid, { id: aid, domain, wildcard, status: 'pending', chIds });
          o.authzIds.push(aid);
        }
        state.orders.set(o.id, o);
        return send(res, 201, orderObj(o), { Location: `${base()}/order/${o.id}` });
      }
      let m;
      if ((m = req.url.match(/^\/authz\/(.+)$/))) { const a = state.authzs.get(m[1]); return a ? send(res, 200, authzObj(a)) : problem(res, 404, 'malformed', 'authz?'); }
      if ((m = req.url.match(/^\/chall\/(.+)$/))) {
        const c = state.challenges.get(m[1]); if (!c) return problem(res, 404, 'malformed', 'chall?');
        const a = state.authzs.get(c.authzId);
        if (c.status === 'pending') { c.status = 'processing'; validateChallenge(c, a, thumbprintOf(jwk)); }
        return send(res, 200, { type: c.type, url: url, token: c.token, status: c.status });
      }
      if ((m = req.url.match(/^\/order\/(.+)$/))) { const o = state.orders.get(m[1]); refreshOrder(o); return send(res, 200, orderObj(o)); }
      if ((m = req.url.match(/^\/finalize\/(.+)$/))) {
        const o = state.orders.get(m[1]); refreshOrder(o);
        if (o.status !== 'ready') return problem(res, 403, 'orderNotReady', 'Order nicht bereit: ' + o.status);
        let csr;
        try { csr = forge.pki.certificationRequestFromAsn1(forge.asn1.fromDer(forge.util.createBuffer(b64uDec(payload.csr).toString('binary')))); } catch (e) { return problem(res, 400, 'badCSR', 'CSR nicht lesbar: ' + e.message); }
        if (!csr.verify()) return problem(res, 400, 'badCSR', 'CSR-Signatur ungültig');
        const ext = (csr.getAttribute({ name: 'extensionRequest' }) || {}).extensions || [];
        const san = ext.find((e) => e.name === 'subjectAltName');
        const want = o.identifiers.map((i) => i.value).sort().join(',');
        const got = ((san && san.altNames) || []).map((a) => a.value).sort().join(',');
        if (want !== got) return problem(res, 400, 'badCSR', `SANs ${got} != ${want}`);
        const cert = forge.pki.createCertificate();
        cert.publicKey = csr.publicKey; cert.serialNumber = crypto.randomBytes(8).toString('hex');
        cert.validity.notBefore = new Date(Date.now() - 60000); cert.validity.notAfter = new Date(Date.now() + 90 * 86400000);
        cert.setSubject(csr.subject.attributes); cert.setIssuer(ca.cert.subject.attributes);
        cert.setExtensions([{ name: 'subjectAltName', altNames: o.identifiers.map((i) => ({ type: 2, value: i.value })) }, { name: 'basicConstraints', cA: false }]);
        cert.sign(ca.keys.privateKey, forge.md.sha256.create());
        o.certId = id(); o.status = 'valid';
        state.certs = state.certs || new Map();
        state.certs.set(o.certId, forge.pki.certificateToPem(cert) + forge.pki.certificateToPem(ca.cert));
        return send(res, 200, orderObj(o), { Location: `${base()}/order/${o.id}` });
      }
      if ((m = req.url.match(/^\/cert\/(.+)$/))) return send(res, 200, state.certs.get(m[1]));
      return problem(res, 404, 'malformed', 'unbekannter Pfad ' + req.url);
    });
  });

  return new Promise((resolve) => server.listen(port, '127.0.0.1', () => resolve({ server, state, url: base() + '/directory', ca, close: () => new Promise((r) => server.close(r)) })));
}

module.exports = { start };
