/* core.js – ACME-Client (RFC 8555) und PFX-Werkzeuge.
 * Läuft unverändert im Browser (global `forge` vorhanden) und in Node (Tests). */
(function (global) {
  'use strict';

  var isNode = typeof require === 'function' && typeof process !== 'undefined' && !!(process.versions && process.versions.node);
  var forge = global.forge || (isNode ? require('node-forge') : null);
  var webcrypto = (global.crypto && global.crypto.subtle) ? global.crypto : (isNode ? require('node:crypto').webcrypto : null);
  if (!forge) throw new Error('forge nicht geladen');
  if (!webcrypto) throw new Error('WebCrypto nicht verfügbar – bitte die Seite über https:// oder von dieser Datei aus öffnen.');
  var subtle = webcrypto.subtle;
  var te = new TextEncoder();

  /* ---------- kleine Helfer ---------- */
  function bytesToBin(u8) {
    var s = '';
    for (var i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    return s;
  }
  function binToBytes(s) {
    var u = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
    return u;
  }
  function b64u(input) {
    var u8 = typeof input === 'string' ? te.encode(input) : (input instanceof Uint8Array ? input : new Uint8Array(input));
    return btoa(bytesToBin(u8)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  async function sha256(data) {
    var u8 = typeof data === 'string' ? te.encode(data) : data;
    return new Uint8Array(await subtle.digest('SHA-256', u8));
  }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  function AcmeError(message, info) {
    var e = new Error(message);
    e.name = 'AcmeError';
    info = info || {};
    e.type = info.type || null;
    e.detail = info.detail || null;
    e.status = info.status || null;
    e.subproblems = info.subproblems || null;
    return e;
  }

  async function readProblem(res) {
    var text = '';
    try { text = await res.text(); } catch (e) { /* ignorieren */ }
    var obj = null;
    try { obj = JSON.parse(text); } catch (e) { /* kein JSON */ }
    return {
      status: res.status,
      type: obj && obj.type,
      detail: (obj && obj.detail) || text || ('HTTP ' + res.status),
      subproblems: obj && obj.subproblems
    };
  }

  /* ---------- Domains ---------- */
  function normalizeDomains(input) {
    var list = (Array.isArray(input) ? input : String(input || '').split(/[\s,;]+/))
      .map(function (s) { return String(s).trim(); }).filter(Boolean);
    var seen = {}, out = [];
    list.forEach(function (raw) {
      var d = raw.toLowerCase().replace(/\.$/, '');
      var wildcard = false;
      if (d.indexOf('*.') === 0) { wildcard = true; d = d.slice(2); }
      d = d.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
      if (!d || /[\s:@*]/.test(d)) throw new Error('„' + raw + '“ ist kein gültiger Domainname.');
      var ascii;
      try { ascii = new URL('http://' + d).hostname; } catch (e) { throw new Error('„' + raw + '“ ist kein gültiger Domainname.'); }
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ascii) || ascii.indexOf(':') >= 0) throw new Error('IP-Adressen werden nicht unterstützt („' + raw + '“). Bitte einen Domainnamen verwenden.');
      if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(ascii)) {
        throw new Error('„' + raw + '“ ist kein gültiger öffentlicher Domainname (Endung fehlt oder ungültige Zeichen).');
      }
      var full = (wildcard ? '*.' : '') + ascii;
      if (!seen[full]) { seen[full] = true; out.push(full); }
    });
    if (!out.length) throw new Error('Bitte mindestens eine Domain angeben.');
    if (out.length > 100) throw new Error('Maximal 100 Domains pro Zertifikat.');
    return out;
  }

  /* ---------- ACME-Client ---------- */
  function AcmeClient(opts) {
    this.directoryUrl = opts.directoryUrl;
    this.fetch = opts.fetch || global.fetch.bind(global);
    this.dir = null;
    this.nonce = null;
    this.kid = null;
    this.jwk = null;
    this.thumbprint = null;
    this.accountKey = null;
  }

  AcmeClient.prototype.init = async function () {
    var res;
    try { res = await this.fetch(this.directoryUrl); }
    catch (e) { throw new AcmeError('Der Zertifikatsserver ist nicht erreichbar (' + this.directoryUrl + '). Internetverbindung und Adresse prüfen.', { detail: String(e && e.message || e) }); }
    if (!res.ok) throw new AcmeError('Der Zertifikatsserver antwortet mit Fehler ' + res.status + '.', await readProblem(res));
    this.dir = await res.json();
    var self = this;
    ['newNonce', 'newAccount', 'newOrder'].forEach(function (k) {
      if (!self.dir[k]) throw new AcmeError('Unter ' + self.directoryUrl + ' liegt kein ACME-Verzeichnis (Eintrag „' + k + '“ fehlt).');
    });
    return this.dir;
  };

  AcmeClient.prototype._freshNonce = async function () {
    var res = await this.fetch(this.dir.newNonce, { method: 'HEAD' });
    var n = res.headers.get('replay-nonce');
    if (!n) throw new AcmeError('Der Server hat keinen Nonce geliefert (CORS: Replay-Nonce nicht freigegeben?).');
    return n;
  };

  AcmeClient.prototype._post = async function (url, payload, opts) {
    opts = opts || {};
    for (var attempt = 0; attempt < 3; attempt++) {
      var nonce = this.nonce || await this._freshNonce();
      this.nonce = null;
      var hdr = { alg: 'ES256', nonce: nonce, url: url };
      if (opts.useJwk) hdr.jwk = this.jwk; else hdr.kid = this.kid;
      var p64 = b64u(JSON.stringify(hdr));
      var pl64 = (payload === '' || payload === undefined) ? '' : b64u(JSON.stringify(payload));
      var sig = new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.accountKey.privateKey, te.encode(p64 + '.' + pl64)));
      var headers = { 'Content-Type': 'application/jose+json' };
      if (opts.accept) headers['Accept'] = opts.accept;
      var res = await this.fetch(url, { method: 'POST', headers: headers, body: JSON.stringify({ protected: p64, payload: pl64, signature: b64u(sig) }) });
      var n = res.headers.get('replay-nonce');
      if (n) this.nonce = n;
      if (res.ok) return res;
      var info = await readProblem(res);
      if (info.type === 'urn:ietf:params:acme:error:badNonce' && attempt < 2) continue;
      throw new AcmeError(friendlyAcmeMessage(info), info);
    }
  };

  function friendlyAcmeMessage(info) {
    var t = (info.type || '').replace('urn:ietf:params:acme:error:', '');
    var map = {
      rateLimited: 'Let’s Encrypt hat die Anfrage wegen zu vieler Versuche vorübergehend abgelehnt.',
      rejectedIdentifier: 'Für diese Domain stellt der Anbieter kein Zertifikat aus.',
      invalidContact: 'Die E-Mail-Adresse wurde vom Anbieter abgelehnt.',
      unsupportedContact: 'Die E-Mail-Adresse wurde vom Anbieter abgelehnt.',
      dns: 'Der Anbieter konnte die Domain nicht auflösen.',
      caa: 'Ein CAA-Eintrag der Domain verbietet diesem Anbieter die Ausstellung.',
      connection: 'Der Anbieter konnte den Server der Domain nicht erreichen.',
      unauthorized: 'Der erwartete Eintrag bzw. die Datei wurde nicht gefunden oder passt nicht.',
      malformed: 'Die Anfrage wurde vom Anbieter als fehlerhaft abgelehnt.',
      badCSR: 'Die Zertifikatsanfrage (CSR) wurde abgelehnt.',
      serverInternal: 'Beim Anbieter ist ein interner Fehler aufgetreten.'
    };
    return (map[t] || 'Der Anbieter hat die Anfrage abgelehnt.') + (info.detail ? ' (' + info.detail + ')' : '');
  }

  AcmeClient.prototype.createAccount = async function (email) {
    this.accountKey = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    var j = await subtle.exportKey('jwk', this.accountKey.publicKey);
    this.jwk = { crv: j.crv, kty: j.kty, x: j.x, y: j.y };
    this.thumbprint = b64u(await sha256(JSON.stringify(this.jwk)));
    var payload = { termsOfServiceAgreed: true };
    if (email) payload.contact = ['mailto:' + email];
    var res = await this._post(this.dir.newAccount, payload, { useJwk: true });
    this.kid = res.headers.get('location');
    if (!this.kid) throw new AcmeError('Der Server hat keine Konto-Adresse geliefert (CORS: Location nicht freigegeben?).');
    return this.kid;
  };

  AcmeClient.prototype.newOrder = async function (domains) {
    var res = await this._post(this.dir.newOrder, { identifiers: domains.map(function (d) { return { type: 'dns', value: d }; }) });
    var order = await res.json();
    order.url = res.headers.get('location');
    return order;
  };

  AcmeClient.prototype.getAuthorization = async function (url) {
    var res = await this._post(url, '');
    var a = await res.json();
    a.url = url;
    return a;
  };

  /* Liefert alles, was der Anwender für die Domain-Bestätigung braucht. */
  AcmeClient.prototype.challengeInfo = async function (authz) {
    var self = this;
    var domain = authz.identifier.value;
    var out = { authzUrl: authz.url, domain: domain, wildcard: !!authz.wildcard, status: authz.status, dns: null, http: null };
    var dnsCh = (authz.challenges || []).filter(function (c) { return c.type === 'dns-01'; })[0];
    var httpCh = (authz.challenges || []).filter(function (c) { return c.type === 'http-01'; })[0];
    if (dnsCh) {
      var keyAuth = dnsCh.token + '.' + self.thumbprint;
      out.dns = { url: dnsCh.url, name: '_acme-challenge.' + domain, value: b64u(await sha256(keyAuth)) };
    }
    if (httpCh) {
      out.http = {
        url: httpCh.url,
        fileUrl: 'http://' + domain + '/.well-known/acme-challenge/' + httpCh.token,
        path: '.well-known/acme-challenge/' + httpCh.token,
        fileName: httpCh.token,
        content: httpCh.token + '.' + self.thumbprint
      };
    }
    return out;
  };

  AcmeClient.prototype.respondToChallenge = function (challengeUrl) {
    return this._post(challengeUrl, {});
  };

  AcmeClient.prototype._poll = async function (url, check, opts) {
    opts = opts || {};
    var timeout = opts.timeoutMs || 180000, interval = opts.intervalMs || 2000;
    var start = Date.now();
    for (;;) {
      if (this.cancelled) throw new AcmeError('Abgebrochen.');
      var res = await this._post(url, '');
      var obj = await res.json();
      var r = check(obj);
      if (r) return obj;
      if (Date.now() - start > timeout) throw new AcmeError('Zeitüberschreitung: Der Anbieter hat nicht rechtzeitig geantwortet.');
      await sleep(interval);
    }
  };

  AcmeClient.prototype.waitForAuthorization = async function (authzUrl, opts) {
    var a = await this._poll(authzUrl, function (o) {
      if (o.status === 'valid') return true;
      if (o.status === 'pending' || o.status === 'processing') return false;
      var bad = (o.challenges || []).filter(function (c) { return c.error; })[0];
      var info = bad ? bad.error : { detail: 'Status: ' + o.status };
      throw new AcmeError('Die Domain „' + (o.identifier && o.identifier.value) + '“ konnte nicht bestätigt werden. ' + friendlyAcmeMessage(info), info);
    }, opts);
    return a;
  };

  AcmeClient.prototype.finalize = async function (order, csrDer, opts) {
    var res = await this._post(order.finalize, { csr: b64u(csrDer) });
    var o = await res.json();
    if (o.status !== 'valid') {
      o = await this._poll(order.url, function (ob) {
        if (ob.status === 'valid') return true;
        if (ob.status === 'invalid') {
          var info = ob.error || { detail: 'Der Auftrag wurde vom Anbieter als ungültig markiert.' };
          throw new AcmeError('Die Ausstellung wurde abgelehnt. ' + friendlyAcmeMessage(info), info);
        }
        return false;
      }, opts);
    }
    var cres = await this._post(o.certificate, '', { accept: 'application/pem-certificate-chain' });
    return await cres.text();
  };

  /* ---------- DNS-Prüfung über DNS-over-HTTPS ---------- */
  async function lookupTxt(name, fetchImpl) {
    var f = fetchImpl || global.fetch.bind(global);
    var urls = [
      'https://cloudflare-dns.com/dns-query?type=TXT&name=' + encodeURIComponent(name),
      'https://dns.google/resolve?type=TXT&name=' + encodeURIComponent(name)
    ];
    var lastErr = null;
    for (var i = 0; i < urls.length; i++) {
      try {
        var res = await f(urls[i], { headers: { Accept: 'application/dns-json' } });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        var j = await res.json();
        return (j.Answer || []).filter(function (a) { return a.type === 16; }).map(function (a) {
          var d = String(a.data);
          var parts = d.match(/"((?:[^"\\]|\\.)*)"/g);
          return parts ? parts.map(function (p) { return p.slice(1, -1); }).join('') : d;
        });
      } catch (e) { lastErr = e; }
    }
    throw lastErr || new Error('DNS-Abfrage nicht möglich');
  }

  /* ---------- Schlüssel, CSR, PEM ---------- */
  async function generateKeyAndCsr(domains, bits) {
    bits = bits || 2048;
    var kp = await subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
    var pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', kp.privateKey));
    var key = forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(forge.util.createBuffer(bytesToBin(pkcs8))));
    var csr = forge.pki.createCertificationRequest();
    csr.publicKey = forge.pki.setRsaPublicKey(key.n, key.e);
    var cn = domains[0];
    csr.setSubject(cn.length <= 64 ? [{ name: 'commonName', value: cn }] : []);
    csr.setAttributes([{ name: 'extensionRequest', extensions: [{ name: 'subjectAltName', altNames: domains.map(function (d) { return { type: 2, value: d }; }) }] }]);
    csr.sign(key, forge.md.sha256.create());
    var der = binToBytes(forge.asn1.toDer(forge.pki.certificationRequestToAsn1(csr)).getBytes());
    return {
      keyPem: forge.pem.encode({ type: 'PRIVATE KEY', body: bytesToBin(pkcs8) }),
      csrDer: der
    };
  }

  function parseCertBundle(text) {
    return (String(text || '').match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || []).map(function (p) {
      return p.replace(/\r/g, '').trim() + '\n';
    });
  }

  function parsePrivateKey(pem, password) {
    pem = String(pem || '').trim();
    if (!pem) throw new Error('Es wurde kein privater Schlüssel angegeben.');
    if (/-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(pem) || /Proc-Type:\s*4,ENCRYPTED/.test(pem)) {
      if (!password) throw new Error('Der private Schlüssel ist verschlüsselt. Bitte sein Passwort angeben.');
      var k;
      try { k = forge.pki.decryptRsaPrivateKey(pem, password); } catch (e) { k = null; }
      if (!k) throw new Error('Das Passwort für den privaten Schlüssel stimmt nicht (oder das Format wird nicht unterstützt).');
      return k;
    }
    if (/-----BEGIN EC PRIVATE KEY-----/.test(pem)) throw new Error('ECDSA-Schlüssel werden nicht unterstützt. Bitte einen RSA-Schlüssel verwenden.');
    if (!/-----BEGIN (RSA )?PRIVATE KEY-----/.test(pem)) throw new Error('Das ist kein privater Schlüssel im PEM-Format (Zeile „-----BEGIN PRIVATE KEY-----“ fehlt).');
    try { return forge.pki.privateKeyFromPem(pem); }
    catch (e) { throw new Error('Der private Schlüssel konnte nicht gelesen werden. Unterstützt werden RSA-Schlüssel (ECDSA nicht).'); }
  }

  function sameKey(cert, key) {
    return cert.publicKey && cert.publicKey.n && cert.publicKey.n.toString(16) === key.n.toString(16) && cert.publicKey.e.toString(16) === key.e.toString(16);
  }

  function orderChain(certs, key) {
    var leafIdx = -1;
    for (var i = 0; i < certs.length; i++) { if (sameKey(certs[i], key)) { leafIdx = i; break; } }
    if (leafIdx < 0) throw new Error('Der private Schlüssel gehört zu keinem der angegebenen Zertifikate.');
    var leaf = certs[leafIdx];
    var pool = certs.filter(function (_, i) { return i !== leafIdx; });
    var ordered = [leaf], cur = leaf;
    while (pool.length) {
      var idx = -1;
      for (var j = 0; j < pool.length; j++) { if (cur.isIssuer(pool[j]) && pool[j] !== cur) { idx = j; break; } }
      if (idx < 0) break;
      cur = pool.splice(idx, 1)[0];
      ordered.push(cur);
    }
    return ordered.concat(pool);
  }

  /* ---------- PFX ---------- */
  function buildPfx(o) {
    if (!o.password) throw new Error('Bitte ein Passwort für die PFX-Datei angeben.');
    if (!/^[\x20-\x7e]+$/.test(o.password)) throw new Error('Das PFX-Passwort darf nur Zeichen ohne Umlaute und Akzente enthalten (Buchstaben, Ziffern, Satz- und Sonderzeichen). Sonst lässt sich die Datei auf anderen Systemen oft nicht importieren.');
    var key = parsePrivateKey(o.keyPem, o.keyPassword);
    var certs = parseCertBundle(o.certsPem).map(function (p) { return forge.pki.certificateFromPem(p); });
    if (!certs.length) throw new Error('Es wurde kein Zertifikat gefunden (Block „-----BEGIN CERTIFICATE-----“ fehlt).');
    var ordered = orderChain(certs, key);
    var leafCn = (ordered[0].subject.getField('CN') || {}).value;
    var p12 = forge.pkcs12.toPkcs12Asn1(key, ordered, o.password, {
      algorithm: o.algorithm === 'aes256' ? 'aes256' : '3des',
      friendlyName: o.friendlyName || leafCn || 'Zertifikat',
      generateLocalKeyId: true,
      count: 2048
    });
    return {
      der: binToBytes(forge.asn1.toDer(p12).getBytes()),
      certCount: ordered.length,
      leafPem: forge.pki.certificateToPem(ordered[0])
    };
  }

  function parsePfx(der, password) {
    var asn1, p12;
    try { asn1 = forge.asn1.fromDer(forge.util.createBuffer(bytesToBin(der))); }
    catch (e) { throw new Error('Das ist keine gültige PFX-/P12-Datei.'); }
    try { p12 = forge.pkcs12.pkcs12FromAsn1(asn1, password || ''); }
    catch (e) {
      var m = String(e && e.message || e);
      if (/MAC|password/i.test(m)) throw new Error('Das Passwort stimmt nicht – oder die Datei ist mit einem Verfahren verschlüsselt, das hier nicht gelesen werden kann.');
      throw new Error('Die PFX-Datei konnte nicht gelesen werden: ' + m);
    }
    var oids = forge.pki.oids;
    var bagsOf = function (t) { return p12.getBags({ bagType: t })[t] || []; };
    var certs = bagsOf(oids.certBag).map(function (b) { return b.cert; }).filter(Boolean);
    var keyBags = bagsOf(oids.pkcs8ShroudedKeyBag).concat(bagsOf(oids.keyBag));
    var key = keyBags.length ? keyBags[0].key : null;
    if (!certs.length && !key) throw new Error('In der PFX-Datei wurden weder Zertifikat noch Schlüssel gefunden.');
    var ordered = certs;
    if (key) { try { ordered = orderChain(certs, key); } catch (e) { ordered = certs; } }
    var pems = ordered.map(function (c) { return forge.pki.certificateToPem(c); });
    var keyPem = key ? forge.pki.privateKeyInfoToPem(forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(key))) : null;
    return { keyPem: keyPem, leafPem: pems[0] || null, chainPems: pems.slice(1), fullchainPem: pems.join('') };
  }

  function describeCert(pem) {
    var c = forge.pki.certificateFromPem(pem);
    var san = c.getExtension('subjectAltName');
    var der = forge.asn1.toDer(forge.pki.certificateToAsn1(c)).getBytes();
    var fp = forge.md.sha256.create().update(der).digest().toHex().toUpperCase().match(/.{2}/g).join(':');
    var f = function (dn, n) { var x = dn.getField(n); return x ? x.value : ''; };
    return {
      commonName: f(c.subject, 'CN'),
      names: san ? san.altNames.map(function (a) { return a.value; }) : [],
      issuer: f(c.issuer, 'CN') + (f(c.issuer, 'O') ? ' (' + f(c.issuer, 'O') + ')' : ''),
      notBefore: c.validity.notBefore,
      notAfter: c.validity.notAfter,
      serial: c.serialNumber,
      fingerprint: fp
    };
  }

  function generatePassword(len) {
    len = len || 20;
    var alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
    var limit = 256 - (256 % alphabet.length), out = '';
    while (out.length < len) {
      var buf = webcrypto.getRandomValues(new Uint8Array(len * 2));
      for (var i = 0; i < buf.length && out.length < len; i++) if (buf[i] < limit) out += alphabet[buf[i] % alphabet.length];
    }
    return out;
  }

  // PEM <-> DER (für .cer in binärer Form und für die Zertifikatsanforderung)
  function pemToDer(pem) {
    var m = forge.pem.decode(String(pem))[0];
    if (!m) throw new Error('Kein PEM-Block gefunden.');
    return binToBytes(m.body);
  }
  function derToPem(der, type) {
    return forge.pem.encode({ type: type, body: bytesToBin(der) }).replace(/\r\n/g, '\n');
  }

  var api = {
    pemToDer: pemToDer, derToPem: derToPem,
    AcmeClient: AcmeClient, AcmeError: AcmeError,
    normalizeDomains: normalizeDomains, lookupTxt: lookupTxt,
    generateKeyAndCsr: generateKeyAndCsr, parseCertBundle: parseCertBundle,
    buildPfx: buildPfx, parsePfx: parsePfx, describeCert: describeCert,
    generatePassword: generatePassword, b64u: b64u, bytesToBin: bytesToBin, binToBytes: binToBytes
  };
  global.LE = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : self);
