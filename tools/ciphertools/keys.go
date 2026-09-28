package ciphertools

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Key kinds.
const (
	KindSecret  = "secret"
	KindRSA     = "rsa"
	KindEC      = "ec"
	KindEd25519 = "ed25519"
)

// Key is one piece of parsed key material: a public key, a private key (which
// always carries its public half), or a shared secret.
type Key struct {
	Kind    string
	Public  crypto.PublicKey // *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey
	Private crypto.Signer    // nil for a public key or a secret
	Secret  []byte
	// Source says what the input was, in the words the visitor would use:
	// "PKCS#8 private key (PEM)", "JWKS entry 2", "X.509 certificate".
	Source string
	// From a JWK only.
	KID, Alg, Use string
	// From an OpenSSH public key line only.
	Comment string
}

// Describe is the one-line summary shown beside a verification result.
func (k Key) Describe() string {
	part := "public key"
	if k.Private != nil {
		part = "private key"
	}
	if k.Kind == KindSecret {
		s := fmt.Sprintf("%d-byte shared secret (%s)", len(k.Secret), k.Source)
		if k.KID != "" {
			s += fmt.Sprintf(", kid %q", k.KID)
		}
		return s
	}
	s := fmt.Sprintf("%s %s, from %s", keyName(k.Public), part, k.Source)
	if k.KID != "" {
		s += fmt.Sprintf(", kid %q", k.KID)
	}
	return s
}

// looksLikeKeyMaterial reports whether s is a PEM block, a JSON key or an
// OpenSSH public key line rather than a shared secret. Decided on shape, before
// any parsing, so a malformed PEM is reported as a malformed PEM instead of
// being quietly used as an HMAC key — which is precisely the algorithm-confusion
// attack (docs/03-correctness-traps.md).
func looksLikeKeyMaterial(s string) bool {
	t := strings.TrimSpace(s)
	return strings.Contains(t, "-----BEGIN") || strings.HasPrefix(t, "{") || looksLikeOpenSSH(t)
}

// maxKeys bounds one ParseKeys call: a JWKS or a PEM bundle, not a keystore.
// Every private key is validated as it is read, so the count is CPU.
const maxKeys = 64

var errTooManyKeys = fmt.Errorf("more than %d keys; paste fewer at once", maxKeys)

// maxRSABits caps every RSA key read from input, at the limit crypto/tls and
// x/crypto/ssh already apply. Go's RSA has none of its own, and verifying
// grows with the square of the modulus, signing with its cube: RSA-32768 takes
// seconds to sign with, and a key filling the request body minutes to verify.
// Such a key needs no real primes (validation multiplies, it doesn't test
// primality), so without this one POST to a non-Heavy op could pin a CPU.
const maxRSABits = 8192

// maxPrivateKeyDER bounds a private key block before it is parsed: Go validates
// an RSA key while parsing it, which is quadratic in its size, so the bit cap
// alone would come too late. RSA-16384 is ~9.3 KB of PKCS#1.
const maxPrivateKeyDER = 16 << 10

func checkRSASize(pub *rsa.PublicKey) error {
	if n := pub.N.BitLen(); n > maxRSABits {
		return fmt.Errorf("RSA %d-bit key: above the limit of %s bits, which is also what TLS and SSH accept", n, thousands(maxRSABits))
	}
	return nil
}

func checkPrivateDER(b *pem.Block) error {
	if strings.Contains(b.Type, "PRIVATE KEY") && len(b.Bytes) > maxPrivateKeyDER {
		return fmt.Errorf("%s of DER is larger than any real private key; this page reads up to %s", bytesText(len(b.Bytes)), bytesText(maxPrivateKeyDER))
	}
	return nil
}

// derError keeps encoding/asn1's parse errors off the page: they print Go
// struct tags ("tags don't match (16 vs {class:0 tag:0 …}) {optional:false …}
// publicKeyInfo @2"). crypto/x509 returns some bare and folds others into its
// own message as text, so the check is on the text.
func derError(err error) error {
	if err != nil && strings.Contains(err.Error(), "asn1: ") {
		return errors.New("the bytes inside don't parse as that type; the paste may be damaged, or the BEGIN line may name the wrong type")
	}
	return err
}

// ParseKeys reads PEM (up to maxKeys blocks), a JWK, a JWKS, or OpenSSH public
// key lines (authorized_keys format, one or more).
func ParseKeys(s string) ([]Key, error) {
	t := strings.TrimSpace(s)
	switch {
	case t == "":
		return nil, errors.New("no key given")
	case strings.HasPrefix(t, "{"):
		return parseJWKInput([]byte(t))
	case strings.Contains(t, "-----BEGIN"):
		return parsePEM([]byte(t))
	case looksLikeOpenSSH(t):
		return parseOpenSSH(t)
	}
	return nil, errors.New("not PEM, a JWK or an OpenSSH public key line")
}

func parsePEM(data []byte) ([]Key, error) {
	var keys []Key
	for n := 1; ; n++ {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if n > maxKeys {
			return nil, errTooManyKeys
		}
		k, err := keyFromPEM(b)
		if err != nil {
			return nil, fmt.Errorf("PEM block %d (%s): %w", n, b.Type, derError(err))
		}
		if k != nil {
			keys = append(keys, *k)
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("no usable PEM block found; check the -----BEGIN/-----END lines survived the paste")
	}
	return keys, nil
}

// keyFromPEM returns nil, nil for blocks that are legitimately not keys
// (openssl ecparam prints EC PARAMETERS ahead of the key).
func keyFromPEM(b *pem.Block) (*Key, error) {
	if strings.Contains(b.Headers["Proc-Type"], "ENCRYPTED") {
		return nil, errors.New("encrypted with a passphrase; decrypt it locally first: openssl pkey -in key.pem -out plain.pem")
	}
	if err := checkPrivateDER(b); err != nil {
		return nil, err
	}
	switch b.Type {
	case "EC PARAMETERS":
		return nil, nil
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(b.Bytes)
		if err != nil {
			return nil, err
		}
		return keyFromPublic(pub, "SPKI public key (PEM)")
	case "RSA PUBLIC KEY":
		pub, err := x509.ParsePKCS1PublicKey(b.Bytes)
		if err != nil {
			return nil, err
		}
		return keyFromPublic(pub, "PKCS#1 public key (PEM)")
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		return keyFromPublic(cert.PublicKey, "X.509 certificate "+certName(cert))
	case "PRIVATE KEY":
		priv, err := x509.ParsePKCS8PrivateKey(b.Bytes)
		if err != nil {
			return nil, err
		}
		return keyFromPrivate(priv, "PKCS#8 private key (PEM)")
	case "RSA PRIVATE KEY":
		priv, err := x509.ParsePKCS1PrivateKey(b.Bytes)
		if err != nil {
			return nil, err
		}
		return keyFromPrivate(priv, "PKCS#1 private key (PEM)")
	case "EC PRIVATE KEY":
		priv, err := x509.ParseECPrivateKey(b.Bytes)
		if err != nil {
			return nil, err
		}
		return keyFromPrivate(priv, "SEC 1 EC private key (PEM)")
	case "ENCRYPTED PRIVATE KEY":
		return nil, errors.New("encrypted with a passphrase; decrypt it locally first: openssl pkey -in key.pem -out plain.pem")
	case "OPENSSH PRIVATE KEY":
		raw, err := ssh.ParseRawPrivateKey(pem.EncodeToMemory(b))
		if err != nil {
			var pm *ssh.PassphraseMissingError
			if errors.As(err, &pm) {
				return nil, errors.New("encrypted with a passphrase; decrypt a copy locally first: ssh-keygen -p -N '' -f copy_of_key")
			}
			return nil, err
		}
		if p, ok := raw.(*ed25519.PrivateKey); ok { // the ssh package returns a pointer
			raw = *p
		}
		return keyFromPrivate(raw, "OpenSSH private key (PEM)")
	}
	return nil, fmt.Errorf("unsupported PEM type %q", b.Type)
}

func certName(c *x509.Certificate) string {
	if len(c.DNSNames) > 0 {
		return "for " + c.DNSNames[0]
	}
	if c.Subject.CommonName != "" {
		return "for " + c.Subject.CommonName
	}
	return "(PEM)"
}

func keyFromPublic(pub any, source string) (*Key, error) {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		if err := checkRSASize(p); err != nil {
			return nil, err
		}
		return &Key{Kind: KindRSA, Public: p, Source: source}, nil
	case *ecdsa.PublicKey:
		return &Key{Kind: KindEC, Public: p, Source: source}, nil
	case ed25519.PublicKey:
		return &Key{Kind: KindEd25519, Public: p, Source: source}, nil
	}
	return nil, fmt.Errorf("unsupported public key type %T (X25519 and DSA keys can't sign)", pub)
}

func keyFromPrivate(priv any, source string) (*Key, error) {
	switch p := priv.(type) {
	case *rsa.PrivateKey:
		if err := checkRSASize(&p.PublicKey); err != nil {
			return nil, err
		}
		return &Key{Kind: KindRSA, Public: &p.PublicKey, Private: p, Source: source}, nil
	case *ecdsa.PrivateKey:
		return &Key{Kind: KindEC, Public: &p.PublicKey, Private: p, Source: source}, nil
	case ed25519.PrivateKey:
		return &Key{Kind: KindEd25519, Public: p.Public(), Private: p, Source: source}, nil
	}
	return nil, fmt.Errorf("unsupported private key type %T (X25519 and DSA keys can't sign)", priv)
}

// JWK is the RFC 7517 wire form, every member optional.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	K   string `json:"k,omitempty"`
	D   string `json:"d,omitempty"`
	P   string `json:"p,omitempty"`
	Q   string `json:"q,omitempty"`
	DP  string `json:"dp,omitempty"`
	DQ  string `json:"dq,omitempty"`
	QI  string `json:"qi,omitempty"`
}

func parseJWKInput(data []byte) ([]Key, error) {
	var probe struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) { // valid JSON, but "keys" isn't an array
			return nil, fmt.Errorf("JWKS: %w", jsonError(err))
		}
		return nil, fmt.Errorf("not valid JSON: %w", jsonError(err))
	}
	if probe.Keys == nil {
		var j JWK
		if err := json.Unmarshal(data, &j); err != nil {
			return nil, fmt.Errorf("JWK: %w", jsonError(err))
		}
		k, err := keyFromJWK(j, "JWK")
		if err != nil {
			return nil, fmt.Errorf("JWK: %w", err)
		}
		return []Key{*k}, nil
	}
	if len(probe.Keys) > maxKeys {
		return nil, errTooManyKeys
	}
	var keys []Key
	for i, raw := range probe.Keys {
		var j JWK
		if err := json.Unmarshal(raw, &j); err != nil {
			return nil, fmt.Errorf("JWKS entry %d: %w", i+1, jsonError(err))
		}
		k, err := keyFromJWK(j, fmt.Sprintf("JWKS entry %d", i+1))
		if err != nil {
			return nil, fmt.Errorf("JWKS entry %d: %w", i+1, err)
		}
		keys = append(keys, *k)
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS has no keys")
	}
	return keys, nil
}

func b64field(name, v string) ([]byte, error) {
	b, err := b64url.DecodeString(strings.TrimRight(v, "="))
	if err != nil {
		return nil, fmt.Errorf("%q is not base64url: %w", name, err)
	}
	return b, nil
}

func bigField(name, v string) (*big.Int, error) {
	b, err := b64field(name, v)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// ecCurves maps JWK crv names to curves, with their coordinate size in bytes.
var ecCurves = map[string]struct {
	curve elliptic.Curve
	size  int
}{
	"P-256": {elliptic.P256(), 32},
	"P-384": {elliptic.P384(), 48},
	"P-521": {elliptic.P521(), 66},
}

func keyFromJWK(j JWK, source string) (*Key, error) {
	var k *Key
	switch j.Kty {
	case "oct":
		secret, err := b64field("k", j.K)
		if err != nil {
			return nil, err
		}
		k = &Key{Kind: KindSecret, Secret: secret}
	case "RSA":
		n, err := bigField("n", j.N)
		if err != nil {
			return nil, err
		}
		e, err := bigField("e", j.E)
		if err != nil {
			return nil, err
		}
		if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
			return nil, errors.New(`"e" is out of range`)
		}
		pub := &rsa.PublicKey{N: n, E: int(e.Int64())}
		if err := checkRSASize(pub); err != nil {
			return nil, err
		}
		k = &Key{Kind: KindRSA, Public: pub}
		if j.D != "" {
			priv, err := rsaPrivateFromJWK(j, pub)
			if err != nil {
				return nil, err
			}
			k.Private = priv
		}
	case "EC":
		c, ok := ecCurves[j.Crv]
		if !ok {
			return nil, fmt.Errorf("unsupported EC curve %q (want P-256, P-384 or P-521)", j.Crv)
		}
		x, err := b64field("x", j.X)
		if err != nil {
			return nil, err
		}
		y, err := b64field("y", j.Y)
		if err != nil {
			return nil, err
		}
		if len(x) > c.size || len(y) > c.size {
			return nil, fmt.Errorf("coordinates are longer than %d bytes, the size of %s", c.size, j.Crv)
		}
		// RFC 7518 §6.2.1.2 says the coordinates are exactly the curve size;
		// some encoders drop leading zeros anyway, so left-pad rather than refuse.
		point := append([]byte{4}, append(leftPad(x, c.size), leftPad(y, c.size)...)...)
		pub, err := ecdsa.ParseUncompressedPublicKey(c.curve, point)
		if err != nil {
			return nil, fmt.Errorf("the point is not on %s: %w", j.Crv, err)
		}
		k = &Key{Kind: KindEC, Public: pub}
		if j.D != "" {
			d, err := b64field("d", j.D)
			if err != nil {
				return nil, err
			}
			priv, err := ecdsa.ParseRawPrivateKey(c.curve, leftPad(d, c.size))
			if err != nil {
				return nil, fmt.Errorf(`"d": %w`, err)
			}
			if !priv.PublicKey.Equal(pub) {
				return nil, errors.New(`"d" does not belong to the public point in "x"/"y"`)
			}
			k.Private = priv
		}
	case "OKP":
		if j.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve %q (only Ed25519 can sign)", j.Crv)
		}
		x, err := b64field("x", j.X)
		if err != nil {
			return nil, err
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf(`"x" is %d bytes; an Ed25519 public key is 32`, len(x))
		}
		pub := ed25519.PublicKey(x)
		k = &Key{Kind: KindEd25519, Public: pub}
		if j.D != "" {
			d, err := b64field("d", j.D)
			if err != nil {
				return nil, err
			}
			if len(d) != ed25519.SeedSize {
				return nil, fmt.Errorf(`"d" is %d bytes; an Ed25519 private key seed is 32`, len(d))
			}
			priv := ed25519.NewKeyFromSeed(d)
			if !pub.Equal(priv.Public()) {
				return nil, errors.New(`"d" does not belong to the public key in "x"`)
			}
			k.Private = priv
		}
	case "":
		return nil, errors.New(`no "kty" member`)
	default:
		return nil, fmt.Errorf("unsupported kty %q", j.Kty)
	}
	k.Source, k.KID, k.Alg, k.Use = source, j.Kid, j.Alg, j.Use
	return k, nil
}

func rsaPrivateFromJWK(j JWK, pub *rsa.PublicKey) (*rsa.PrivateKey, error) {
	if j.P == "" || j.Q == "" {
		return nil, errors.New(`private RSA JWK without "p" and "q" is not supported`)
	}
	d, err := bigField("d", j.D)
	if err != nil {
		return nil, err
	}
	p, err := bigField("p", j.P)
	if err != nil {
		return nil, err
	}
	q, err := bigField("q", j.Q)
	if err != nil {
		return nil, err
	}
	priv := &rsa.PrivateKey{PublicKey: *pub, D: d, Primes: []*big.Int{p, q}}
	if err := priv.Validate(); err != nil {
		return nil, fmt.Errorf("RSA private key is inconsistent: %w", err)
	}
	priv.Precompute()
	return priv, nil
}

func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// keyName is a public key's kind and size in words: "RSA 2048-bit",
// "ECDSA P-256", "Ed25519".
func keyName(pub crypto.PublicKey) string {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d-bit", p.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + p.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	case *ecdh.PublicKey:
		return fmt.Sprint(p.Curve())
	case nil:
		return "unknown key type"
	}
	return fmt.Sprintf("%T", pub)
}

// jwsAlgFor is the alg a JWK of this key would normally carry: RS256 for RSA
// (PS256 is as valid), the ES* whose curve matches, EdDSA for Ed25519.
func jwsAlgFor(pub crypto.PublicKey) string {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		return "RS256"
	case *ecdsa.PublicKey:
		for _, alg := range []string{"ES256", "ES384", "ES512"} {
			if jwsAlgs[alg].curve == p.Curve {
				return alg
			}
		}
	case ed25519.PublicKey:
		return "EdDSA"
	}
	return ""
}

// jwkCurve names an EC curve the way a JWK does, with its coordinate size.
func jwkCurve(c elliptic.Curve) (string, int, error) {
	for name, cc := range ecCurves {
		if cc.curve == c {
			return name, cc.size, nil
		}
	}
	return "", 0, fmt.Errorf("no JWK name for curve %s", c.Params().Name)
}

// PublicJWK is pub as a JWK: kty and the public members only. It never
// carries d, p, q, dp, dq or qi, whatever key it came from
// (docs/03-correctness-traps.md). Integers are big-endian with leading zeros
// stripped; EC coordinates are the exception, always the curve's size
// (RFC 7518 §6.2.1.2).
func PublicJWK(pub crypto.PublicKey) (JWK, error) {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		return JWK{Kty: "RSA", N: b64url.EncodeToString(p.N.Bytes()),
			E: b64url.EncodeToString(big.NewInt(int64(p.E)).Bytes())}, nil
	case *ecdsa.PublicKey:
		crv, size, err := jwkCurve(p.Curve)
		if err != nil {
			return JWK{}, err
		}
		point, err := p.Bytes() // 0x04 ‖ X ‖ Y, each exactly size bytes
		if err != nil {
			return JWK{}, err
		}
		return JWK{Kty: "EC", Crv: crv, X: b64url.EncodeToString(point[1 : 1+size]),
			Y: b64url.EncodeToString(point[1+size:])}, nil
	case ed25519.PublicKey:
		return JWK{Kty: "OKP", Crv: "Ed25519", X: b64url.EncodeToString(p)}, nil
	}
	return JWK{}, fmt.Errorf("no JWK form for %s", keyName(pub))
}

// PrivateJWK is priv as a private JWK: the public members plus d, and for RSA
// the CRT members p, q, dp, dq and qi. EC's d is the curve's size, like x and y.
func PrivateJWK(priv crypto.Signer) (JWK, error) {
	j, err := PublicJWK(priv.Public())
	if err != nil {
		return JWK{}, err
	}
	switch p := priv.(type) {
	case *rsa.PrivateKey:
		if len(p.Primes) != 2 {
			return JWK{}, fmt.Errorf("a %d-prime RSA key has no private JWK form here", len(p.Primes))
		}
		one := big.NewInt(1)
		pp, q := p.Primes[0], p.Primes[1]
		qi := new(big.Int).ModInverse(q, pp)
		if qi == nil {
			return JWK{}, errors.New("RSA key is inconsistent: q has no inverse mod p")
		}
		enc := func(n *big.Int) string { return b64url.EncodeToString(n.Bytes()) }
		j.D, j.P, j.Q = enc(p.D), enc(pp), enc(q)
		j.DP = enc(new(big.Int).Mod(p.D, new(big.Int).Sub(pp, one)))
		j.DQ = enc(new(big.Int).Mod(p.D, new(big.Int).Sub(q, one)))
		j.QI = enc(qi)
	case *ecdsa.PrivateKey:
		d, err := p.Bytes()
		if err != nil {
			return JWK{}, err
		}
		j.D = b64url.EncodeToString(d)
	case ed25519.PrivateKey:
		j.D = b64url.EncodeToString(p.Seed())
	default:
		return JWK{}, fmt.Errorf("no JWK form for %T", priv)
	}
	return j, nil
}

// JWKThumbprint is the RFC 7638 SHA-256 thumbprint: the key's required members
// only, in lexicographic order, no whitespace, hashed, as base64url. Compute it
// from a PublicJWK rather than from pasted text, so a padded or non-minimal
// encoding in the input can't change it.
func JWKThumbprint(j JWK) (string, error) {
	var members [][2]string
	switch j.Kty {
	case "RSA":
		members = [][2]string{{"e", j.E}, {"kty", j.Kty}, {"n", j.N}}
	case "EC":
		members = [][2]string{{"crv", j.Crv}, {"kty", j.Kty}, {"x", j.X}, {"y", j.Y}}
	case "OKP": // RFC 8037 §2
		members = [][2]string{{"crv", j.Crv}, {"kty", j.Kty}, {"x", j.X}}
	case "oct":
		members = [][2]string{{"k", j.K}, {"kty", j.Kty}}
	default:
		return "", fmt.Errorf("no thumbprint for kty %q", j.Kty)
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, m := range members {
		if m[1] == "" {
			return "", fmt.Errorf("no %q member", m[0])
		}
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(m[0])
		v, _ := json.Marshal(m[1])
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	sum := sha256.Sum256([]byte(b.String()))
	return b64url.EncodeToString(sum[:]), nil
}

// spkiSHA256 is the SHA-256 of a public key's SubjectPublicKeyInfo DER: the
// fingerprint certificates, pins and "does this key match" all agree on.
func spkiSHA256(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return sum[:], nil
}

// fingerprintHex writes a digest the way openssl prints fingerprints:
// uppercase hex pairs joined by colons.
func fingerprintHex(b []byte) string { return strings.ToUpper(hexColons(b)) }

// samePublicKey reports whether two public keys are the same key.
func samePublicKey(a, b crypto.PublicKey) bool {
	e, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && b != nil && e.Equal(b)
}

// OpenSSH public keys: one authorized_keys line each, "type base64 comment",
// with optional options in front.

// sshKeyTypes are the key type names an authorized_keys line can carry.
var sshKeyTypes = map[string]bool{
	"ssh-rsa": true, "ssh-dss": true, "ssh-ed25519": true,
	"ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true, "ecdsa-sha2-nistp521": true,
	"sk-ssh-ed25519@openssh.com": true, "sk-ecdsa-sha2-nistp256@openssh.com": true,
}

// isSSHKeyType matches exact names only, so a secret that merely contains
// "ssh-" is still read as a secret.
func isSSHKeyType(f string) bool {
	t := strings.TrimSuffix(f, "-cert-v01@openssh.com")
	if t != f && strings.HasPrefix(t, "sk-") {
		t += "@openssh.com"
	}
	return sshKeyTypes[t]
}

// looksLikeOpenSSH: the first line that isn't blank or a # comment names a
// key type.
func looksLikeOpenSSH(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, f := range strings.Fields(line) {
			if isSSHKeyType(f) {
				return true
			}
		}
		return false
	}
	return false
}

func parseOpenSSH(s string) ([]Key, error) {
	var keys []Key
	for n, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		if t := strings.TrimSpace(line); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if len(keys) == maxKeys {
			return nil, errTooManyKeys
		}
		k, err := keyFromOpenSSH(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n+1, err)
		}
		keys = append(keys, *k)
	}
	if len(keys) == 0 {
		return nil, errors.New("no OpenSSH public key found")
	}
	return keys, nil
}

func keyFromOpenSSH(line string) (*Key, error) {
	pk, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, openSSHLineError(line)
	}
	source := "OpenSSH public key"
	if c, ok := pk.(*ssh.Certificate); ok {
		pk, source = c.Key, "OpenSSH certificate"
	}
	switch t := pk.Type(); {
	case strings.HasPrefix(t, "sk-"):
		return nil, fmt.Errorf("%s is a security-key (FIDO) key: its signatures are in a format only OpenSSH checks, so it has no PEM or JWK form", t)
	case t == "ssh-dss":
		return nil, errors.New("ssh-dss (DSA) keys are not supported; OpenSSH has disabled them by default since version 7.0")
	}
	cp, ok := pk.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported OpenSSH key type %s", pk.Type())
	}
	k, err := keyFromPublic(cp.CryptoPublicKey(), source)
	if err != nil {
		return nil, err
	}
	k.Comment = comment
	if comment != "" {
		k.Source += fmt.Sprintf(" %q", comment)
	}
	return k, nil
}

// openSSHLineError says what is wrong with a line ssh.ParseAuthorizedKey
// refused, whose own error is only "no key found". Offsets count from the
// start of the line.
func openSSHLineError(line string) error {
	fields := strings.Fields(line)
	at := 0
	for i, f := range fields {
		at += strings.Index(line[at:], f)
		if !isSSHKeyType(f) {
			at += len(f)
			continue
		}
		if i+1 >= len(fields) {
			return fmt.Errorf("%s with no key data after it", f)
		}
		data := fields[i+1]
		start := at + len(f) + strings.Index(line[at+len(f):], data)
		b, _, err := decodeBase64Any(strings.Repeat(" ", start) + data)
		if err != nil {
			return fmt.Errorf("the key data after %s: %w", f, err)
		}
		if _, err := ssh.ParsePublicKey(b); err != nil {
			return fmt.Errorf("the %s key data doesn't parse: %v", f, err)
		}
		return fmt.Errorf("the line says %s, and its key data doesn't agree", f)
	}
	return errors.New("not an OpenSSH public key line")
}

// openSSHLine is pub as one authorized_keys line, with comment appended when
// there is one.
func openSSHLine(pk ssh.PublicKey, comment string) string {
	line := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pk)), "\n")
	if comment != "" {
		line += " " + comment
	}
	return line
}
