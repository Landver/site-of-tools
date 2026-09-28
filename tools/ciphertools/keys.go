package ciphertools

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
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
}

// Describe is the one-line summary shown beside a verification result.
func (k Key) Describe() string {
	part := "public key"
	if k.Private != nil {
		part = "private key"
	}
	var what string
	switch k.Kind {
	case KindSecret:
		s := fmt.Sprintf("%d-byte shared secret (%s)", len(k.Secret), k.Source)
		if k.KID != "" {
			s += fmt.Sprintf(", kid %q", k.KID)
		}
		return s
	case KindRSA:
		what = fmt.Sprintf("RSA %d-bit", k.Public.(*rsa.PublicKey).N.BitLen())
	case KindEC:
		what = "ECDSA " + k.Public.(*ecdsa.PublicKey).Curve.Params().Name
	case KindEd25519:
		what = "Ed25519"
	}
	s := fmt.Sprintf("%s %s, from %s", what, part, k.Source)
	if k.KID != "" {
		s += fmt.Sprintf(", kid %q", k.KID)
	}
	return s
}

// looksLikeKeyMaterial reports whether s is a PEM block or a JSON key rather
// than a shared secret. Decided on shape, before any parsing, so a malformed PEM
// is reported as a malformed PEM instead of being quietly used as an HMAC key —
// which is precisely the algorithm-confusion attack (docs/03-correctness-traps.md).
func looksLikeKeyMaterial(s string) bool {
	t := strings.TrimSpace(s)
	return strings.Contains(t, "-----BEGIN") || strings.HasPrefix(t, "{")
}

// ParseKeys reads PEM (any number of blocks), a JWK, or a JWKS.
func ParseKeys(s string) ([]Key, error) {
	t := strings.TrimSpace(s)
	switch {
	case t == "":
		return nil, errors.New("no key given")
	case strings.HasPrefix(t, "{"):
		return parseJWKInput([]byte(t))
	case strings.Contains(t, "-----BEGIN"):
		return parsePEM([]byte(t))
	}
	return nil, errors.New("not a PEM block or a JWK")
}

func parsePEM(data []byte) ([]Key, error) {
	var keys []Key
	for n := 1; ; n++ {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		k, err := keyFromPEM(b)
		if err != nil {
			return nil, fmt.Errorf("PEM block %d (%s): %w", n, b.Type, err)
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
		return nil, errors.New("OpenSSH format; convert a copy to PKCS#8 first: ssh-keygen -p -m PKCS8 -f copy_of_key")
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
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	if probe.Keys == nil {
		var j JWK
		if err := json.Unmarshal(data, &j); err != nil {
			return nil, fmt.Errorf("JWK: %w", err)
		}
		k, err := keyFromJWK(j, "JWK")
		if err != nil {
			return nil, fmt.Errorf("JWK: %w", err)
		}
		return []Key{*k}, nil
	}
	var keys []Key
	for i, raw := range probe.Keys {
		var j JWK
		if err := json.Unmarshal(raw, &j); err != nil {
			return nil, fmt.Errorf("JWKS entry %d: %w", i+1, err)
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
