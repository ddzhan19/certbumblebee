package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"net"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Werkzeuge zum Umwandeln zwischen PEM-Dateien und PFX.

// ---------- Port-80-Prüfung (Oberfläche und Browser-Version) ----------

// checkPort80 prüft, ob der eingebaute Webserver Port 80 benutzen kann.
func checkPort80() (bool, string) {
	ln, err := net.Listen("tcp", ":"+httpPort())
	if err != nil {
		return false, fmt.Sprintf("Port %s ist belegt oder gesperrt (%v). Läuft hier schon ein Webserver, bitte „Vorhandener Webserver“ wählen.", httpPort(), simplifyOSError(err))
	}
	_ = ln.Close()
	return true, fmt.Sprintf("Port %s ist frei. Ob er auch aus dem Internet erreichbar ist, zeigt erst die Ausstellung (am besten zuerst mit „Let’s Encrypt Test“).", httpPort())
}

// ---------- Zufallspasswort ----------

const pwAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// generatePassword liefert ein Zufallspasswort ohne leicht verwechselbare Zeichen.
func generatePassword(n int) string {
	if n < 8 {
		n = 8
	}
	b := make([]byte, n)
	buf := make([]byte, n)
	for i := 0; i < n; {
		if _, err := rand.Read(buf); err != nil {
			panic(err)
		}
		for _, c := range buf {
			if int(c) >= 256-256%len(pwAlphabet) {
				continue
			}
			b[i] = pwAlphabet[int(c)%len(pwAlphabet)]
			i++
			if i == n {
				break
			}
		}
	}
	return string(b)
}

// ---------- Privater Schlüssel (auch verschlüsselt) ----------

var (
	oidPBES2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHmacSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHmacSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHmacSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHmacSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHmacSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oid3DESCBC    = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

var errKeyPassword = errors.New("Das Passwort für den privaten Schlüssel stimmt nicht.")

type encryptedPKInfo struct {
	Alg  pkix.AlgorithmIdentifier
	Data []byte
}

type pbes2Params struct {
	KDF    pkix.AlgorithmIdentifier
	Scheme pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt   []byte
	Iter   int
	KeyLen int                      `asn1:"optional"`
	PRF    pkix.AlgorithmIdentifier `asn1:"optional"`
}

// decryptPKCS8 entschlüsselt „ENCRYPTED PRIVATE KEY“ (PBES2 mit PBKDF2 und AES oder 3DES, wie OpenSSL es schreibt).
func decryptPKCS8(der []byte, password string) ([]byte, error) {
	var info encryptedPKInfo
	if rest, err := asn1.Unmarshal(der, &info); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("Der verschlüsselte Schlüssel ist beschädigt.")
	}
	if !info.Alg.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("Dieses Verschlüsselungsverfahren des Schlüssels wird nicht unterstützt. Mit „openssl pkcs8 -in alt.key -out neu.key“ lässt er sich ohne Passwort umwandeln.")
	}
	var pp pbes2Params
	if _, err := asn1.Unmarshal(info.Alg.Parameters.FullBytes, &pp); err != nil || !pp.KDF.Algorithm.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("Dieses Verschlüsselungsverfahren des Schlüssels wird nicht unterstützt.")
	}
	var kp pbkdf2Params
	if _, err := asn1.Unmarshal(pp.KDF.Parameters.FullBytes, &kp); err != nil || kp.Iter <= 0 || kp.Iter > 10_000_000 {
		return nil, fmt.Errorf("Der verschlüsselte Schlüssel ist beschädigt.")
	}
	var h func() hash.Hash
	switch {
	case len(kp.PRF.Algorithm) == 0 || kp.PRF.Algorithm.Equal(oidHmacSHA1):
		h = sha1.New
	case kp.PRF.Algorithm.Equal(oidHmacSHA224):
		h = sha256.New224
	case kp.PRF.Algorithm.Equal(oidHmacSHA256):
		h = sha256.New
	case kp.PRF.Algorithm.Equal(oidHmacSHA384):
		h = sha512.New384
	case kp.PRF.Algorithm.Equal(oidHmacSHA512):
		h = sha512.New
	default:
		return nil, fmt.Errorf("Dieses Verschlüsselungsverfahren des Schlüssels wird nicht unterstützt.")
	}
	var keyLen int
	var mk func(key []byte) (cipher.Block, error)
	switch {
	case pp.Scheme.Algorithm.Equal(oidAES128CBC):
		keyLen, mk = 16, aes.NewCipher
	case pp.Scheme.Algorithm.Equal(oidAES192CBC):
		keyLen, mk = 24, aes.NewCipher
	case pp.Scheme.Algorithm.Equal(oidAES256CBC):
		keyLen, mk = 32, aes.NewCipher
	case pp.Scheme.Algorithm.Equal(oid3DESCBC):
		keyLen, mk = 24, des.NewTripleDESCipher
	default:
		return nil, fmt.Errorf("Dieses Verschlüsselungsverfahren des Schlüssels wird nicht unterstützt.")
	}
	var iv []byte
	if _, err := asn1.Unmarshal(pp.Scheme.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("Der verschlüsselte Schlüssel ist beschädigt.")
	}
	dk, err := pbkdf2.Key(h, password, kp.Salt, kp.Iter, keyLen)
	if err != nil {
		return nil, err
	}
	blk, err := mk(dk)
	if err != nil {
		return nil, err
	}
	if len(iv) != blk.BlockSize() || len(info.Data) == 0 || len(info.Data)%blk.BlockSize() != 0 {
		return nil, fmt.Errorf("Der verschlüsselte Schlüssel ist beschädigt.")
	}
	plain := make([]byte, len(info.Data))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(plain, info.Data)
	pad := int(plain[len(plain)-1])
	if pad == 0 || pad > blk.BlockSize() || pad > len(plain) {
		return nil, errKeyPassword
	}
	for _, b := range plain[len(plain)-pad:] {
		if int(b) != pad {
			return nil, errKeyPassword
		}
	}
	return plain[:len(plain)-pad], nil
}

// parsePrivateKeyPEM liest einen privaten Schlüssel (PKCS#8, PKCS#1 oder EC; auch verschlüsselt).
func parsePrivateKeyPEM(b []byte, password string) (crypto.PrivateKey, error) {
	var blk *pem.Block
	for rest := b; ; {
		var p *pem.Block
		p, rest = pem.Decode(rest)
		if p == nil {
			break
		}
		if strings.Contains(p.Type, "PRIVATE KEY") {
			blk = p
			break
		}
	}
	if blk == nil {
		return nil, fmt.Errorf("Das ist kein privater Schlüssel im PEM-Format (die Zeile „-----BEGIN PRIVATE KEY-----“ fehlt).")
	}
	der := blk.Bytes
	switch {
	case blk.Type == "ENCRYPTED PRIVATE KEY":
		if password == "" {
			return nil, fmt.Errorf("Der private Schlüssel ist verschlüsselt. Bitte sein Passwort angeben.")
		}
		var err error
		if der, err = decryptPKCS8(blk.Bytes, password); err != nil {
			return nil, err
		}
	case x509.IsEncryptedPEMBlock(blk): //nolint:staticcheck // altes OpenSSL-Format („Proc-Type: 4,ENCRYPTED“)
		if password == "" {
			return nil, fmt.Errorf("Der private Schlüssel ist verschlüsselt. Bitte sein Passwort angeben.")
		}
		var err error
		if der, err = x509.DecryptPEMBlock(blk, []byte(password)); err != nil { //nolint:staticcheck
			return nil, errKeyPassword
		}
	}
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	if blk.Type == "ENCRYPTED PRIVATE KEY" || strings.Contains(blk.Headers["Proc-Type"], "ENCRYPTED") {
		return nil, errKeyPassword
	}
	return nil, fmt.Errorf("Der private Schlüssel konnte nicht gelesen werden (unterstützt: RSA und ECDSA).")
}

func keyToPKCS8PEM(k crypto.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func publicOf(k crypto.PrivateKey) crypto.PublicKey {
	switch v := k.(type) {
	case *rsa.PrivateKey:
		return &v.PublicKey
	case *ecdsa.PrivateKey:
		return &v.PublicKey
	case ed25519.PrivateKey:
		return v.Public()
	}
	return nil
}

// orderChain stellt Zertifikat und Kette in die richtige Reihenfolge: zuerst das Zertifikat zum Schlüssel,
// dann jeweils der Aussteller.
func orderChain(certs []*x509.Certificate, key crypto.PrivateKey) ([]*x509.Certificate, error) {
	pub, ok := publicOf(key).(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return nil, fmt.Errorf("Der Schlüsseltyp wird nicht unterstützt.")
	}
	leaf := -1
	for i, c := range certs {
		if pub.Equal(c.PublicKey) {
			leaf = i
			break
		}
	}
	if leaf < 0 {
		return nil, fmt.Errorf("Der private Schlüssel gehört zu keinem der angegebenen Zertifikate.")
	}
	out := []*x509.Certificate{certs[leaf]}
	var pool []*x509.Certificate
	for i, c := range certs {
		if i != leaf {
			pool = append(pool, c)
		}
	}
	cur := certs[leaf]
	for len(pool) > 0 {
		idx := -1
		for j, c := range pool {
			if bytes.Equal(cur.RawIssuer, c.RawSubject) && !bytes.Equal(cur.Raw, c.Raw) {
				idx = j
				break
			}
		}
		if idx < 0 {
			break
		}
		cur = pool[idx]
		out = append(out, cur)
		pool = append(pool[:idx], pool[idx+1:]...)
	}
	return append(out, pool...), nil
}

func certsToPEM(certs []*x509.Certificate) []byte {
	var b []byte
	for _, c := range certs {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return b
}

// ---------- PEM → PFX ----------

// PemToPfxResult ist die fertige PFX-Datei mit Angaben zur Anzeige.
type PemToPfxResult struct {
	PFX   []byte
	Leaf  *x509.Certificate
	Count int
}

// pemToPFX baut aus Zertifikat(en) und Schlüssel (PEM-Text) eine PFX-Datei.
func pemToPFX(certsPEM, keyPEM []byte, keyPassword, pfxPassword, format string) (*PemToPfxResult, error) {
	if strings.TrimSpace(string(certsPEM)) == "" {
		return nil, fmt.Errorf("Es wurde kein Zertifikat angegeben.")
	}
	if strings.TrimSpace(string(keyPEM)) == "" {
		return nil, fmt.Errorf("Es wurde kein privater Schlüssel angegeben.")
	}
	if pfxPassword == "" {
		return nil, fmt.Errorf("Bitte ein Passwort für die PFX-Datei angeben.")
	}
	if len(pfxPassword) > 100 || strings.ContainsAny(pfxPassword, "\x00\r\n") {
		return nil, fmt.Errorf("Das PFX-Passwort ist ungültig (höchstens 100 Zeichen, keine Zeilenumbrüche).")
	}
	key, err := parsePrivateKeyPEM(keyPEM, keyPassword)
	if err != nil {
		return nil, err
	}
	certs, err := parseCertsPEM(certsPEM)
	if err != nil {
		return nil, fmt.Errorf("Es wurde kein Zertifikat gefunden (der Block „-----BEGIN CERTIFICATE-----“ fehlt oder ist beschädigt).")
	}
	ordered, err := orderChain(certs, key)
	if err != nil {
		return nil, err
	}
	keyOut, err := keyToPKCS8PEM(key)
	if err != nil {
		return nil, err
	}
	data, err := buildPFX(keyOut, certsToPEM(ordered), pfxPassword, format)
	if err != nil {
		return nil, err
	}
	return &PemToPfxResult{PFX: data, Leaf: ordered[0], Count: len(ordered)}, nil
}

// ---------- PFX → PEM ----------

// PfxContents ist der Inhalt einer geöffneten PFX-Datei.
type PfxContents struct {
	Certs        []*x509.Certificate // Zertifikat zuerst, dann die Kette
	Key          crypto.PrivateKey   // nil, wenn die Datei keinen Schlüssel enthält
	CertPEM      []byte
	ChainPEM     []byte
	FullchainPEM []byte
	KeyPEM       []byte
}

// openPFX liest eine PFX-/P12-Datei.
func openPFX(data []byte, password string) (*PfxContents, error) {
	c := &PfxContents{}
	key, leaf, ca, err := pkcs12.DecodeChain(data, password)
	switch {
	case err == nil:
		c.Key = key
		c.Certs = append([]*x509.Certificate{leaf}, ca...)
	case errors.Is(err, pkcs12.ErrIncorrectPassword):
		return nil, fmt.Errorf("Das Passwort stimmt nicht.")
	default:
		certs, err2 := pkcs12.DecodeTrustStore(data, password)
		if err2 != nil || len(certs) == 0 {
			var ni pkcs12.NotImplementedError
			if errors.As(err, &ni) {
				return nil, fmt.Errorf("Die Datei ist mit einem Verfahren verschlüsselt, das hier nicht gelesen werden kann (%v).", err)
			}
			return nil, fmt.Errorf("Das ist keine lesbare PFX-/P12-Datei oder sie enthält kein einzelnes Zertifikat mit Schlüssel (%v).", err)
		}
		c.Certs = certs
	}
	if c.Key != nil {
		if o, err := orderChain(c.Certs, c.Key); err == nil {
			c.Certs = o
		}
		kp, err := keyToPKCS8PEM(c.Key)
		if err != nil {
			return nil, err
		}
		c.KeyPEM = kp
	}
	c.CertPEM = certsToPEM(c.Certs[:1])
	if len(c.Certs) > 1 {
		c.ChainPEM = certsToPEM(c.Certs[1:])
	}
	c.FullchainPEM = certsToPEM(c.Certs)
	return c, nil
}

// saveConverted schreibt die gewünschten Teile einer geöffneten PFX-Datei als Einzeldateien in einen Ordner.
// kinds: cert, chain, fullchain, key. Rückgabe: die geschriebenen Pfade.
func saveConverted(c *PfxContents, dir, base string, kinds []string, certFormat string) ([]string, error) {
	dir, err := validatePath(dir, osIsWindows(), "Zielordner")
	if err != nil {
		return nil, err
	}
	if base == "" || badNameRe.MatchString(base) || len(base) > 110 {
		return nil, fmt.Errorf("Dateiname: Bitte einen einfachen Namen ohne \\ / : * ? \" < > | verwenden.")
	}
	var want []string
	for _, k := range kinds {
		if k == "key" && c.Key == nil {
			continue
		}
		if k == "chain" && len(c.Certs) < 2 {
			continue
		}
		want = append(want, k)
	}
	if len(want) == 0 {
		return nil, fmt.Errorf("Bitte mindestens eine Datei auswählen.")
	}
	outs, err := planOutputs(want, certFormat, base)
	if err != nil {
		return nil, err
	}
	p := &Profile{TargetDir: dir, Outputs: outs}
	all, _, err := syncOutputs(p, outputData{Chain: c.FullchainPEM, Key: c.KeyPEM})
	return all, err
}

// writeUserFile schreibt eine einzelne Datei (z. B. die fertige PFX) an den gewählten Ort.
func writeUserFile(path string, data []byte) error {
	if err := writeFileAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("Die Datei „%s“ konnte nicht geschrieben werden: %v", path, simplifyOSError(err))
	}
	return nil
}
