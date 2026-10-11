package ciphertools

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	KindSecret  = "secret"
	KindRSA     = "rsa"
	KindEC      = "ec"
	KindEd25519 = "ed25519"
)

// Key is a public key, a private key (with its public half), or a shared secret.
type Key struct {
	Kind    string
	Public  crypto.PublicKey // *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey
	Private crypto.Signer
	Secret  []byte
	Source  string // what the input was, in the visitor's words: "JWKS entry 2"
	// KID, Alg and Use come from a JWK, Comment from an OpenSSH line.
	KID, Alg, Use, Comment string
}

// Describe is the one-line summary shown beside a verification result.
func (k Key) Describe() string {
	s := fmt.Sprintf("%d-byte shared secret (%s)", len(k.Secret), k.Source)
	if k.Kind != KindSecret {
		s = fmt.Sprintf("%s %s, from %s", keyName(k.Public), k.half(), k.Source)
	}
	if k.KID != "" {
		s += fmt.Sprintf(", kid %q", k.KID)
	}
	return s
}

func (k Key) half() string {
	return map[bool]string{false: "public key", true: "private key"}[k.Private != nil]
}

// looksLikeKeyMaterial goes by shape, so a broken PEM is never used as an HMAC key (alg confusion).
func looksLikeKeyMaterial(s string) bool {
	t := strings.TrimSpace(s)
	return strings.Contains(t, "-----BEGIN") || strings.HasPrefix(t, "{") || looksLikeOpenSSH(t)
}

// maxKeys bounds one ParseKeys call; every private key is validated as read.
const maxKeys = 64

var errTooManyKeys = fmt.Errorf("more than %d keys; paste fewer at once", maxKeys)

// maxRSABits is crypto/tls's cap: Go's RSA has none, and a huge modulus needs no
// real primes yet costs seconds to sign with and minutes to verify.
const maxRSABits = 8192

// maxPrivateKeyDER is checked before parsing, since Go validates an RSA key
// while parsing it, in quadratic time. RSA-16384 is ~9.3 KB of PKCS#1.
const maxPrivateKeyDER = 16 << 10

func checkRSASize(pub any) error {
	if k, ok := pub.(*rsa.PublicKey); ok && k.N.BitLen() > maxRSABits {
		return fmt.Errorf("RSA %d-bit key: above the limit of %s bits, which is also what TLS and SSH accept", k.N.BitLen(), thousands(maxRSABits))
	}
	return nil
}

func checkPrivateDER(b *pem.Block) error {
	if strings.Contains(b.Type, "PRIVATE KEY") && len(b.Bytes) > maxPrivateKeyDER {
		return fmt.Errorf("%s of DER is larger than any real private key; this page reads up to %s", bytesText(len(b.Bytes)), bytesText(maxPrivateKeyDER))
	}
	return nil
}

// derError hides encoding/asn1 errors (they print Go struct tags); x509 wraps some as text.
func derError(err error) error {
	if err != nil && strings.Contains(err.Error(), "asn1: ") {
		return errors.New("the bytes inside don't parse as that type; the paste may be damaged, or the BEGIN line may name the wrong type")
	}
	return err
}

// ParseKeys reads PEM blocks, a JWK or JWKS, or authorized_keys lines.
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
		if b, data = pem.Decode(data); b == nil {
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

var keysPEMSources = map[string]string{
	"PUBLIC KEY": "SPKI public key", "RSA PUBLIC KEY": "PKCS#1 public key",
	"PRIVATE KEY": "PKCS#8 private key", "RSA PRIVATE KEY": "PKCS#1 private key",
	"EC PRIVATE KEY": "SEC 1 EC private key", "OPENSSH PRIVATE KEY": "OpenSSH private key",
}

// keyFromPEM returns nil, nil for openssl ecparam's EC PARAMETERS block.
func keyFromPEM(b *pem.Block) (*Key, error) {
	const encrypted = "encrypted with a passphrase; decrypt it locally first: openssl pkey -in key.pem -out plain.pem"
	if strings.Contains(b.Headers["Proc-Type"], "ENCRYPTED") {
		return nil, errors.New(encrypted)
	}
	if err := checkPrivateDER(b); err != nil {
		return nil, err
	}
	var key any
	var err error
	source := keysPEMSources[b.Type] + " (PEM)"
	switch b.Type {
	case "EC PARAMETERS":
		return nil, nil
	case "ENCRYPTED PRIVATE KEY":
		return nil, errors.New(encrypted)
	case "PUBLIC KEY", "RSA PUBLIC KEY", "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
		key, err = pemKinds[b.Type].parse(b.Bytes)
	case "CERTIFICATE":
		var c *x509.Certificate
		if c, err = x509.ParseCertificate(b.Bytes); err == nil {
			key, source = c.PublicKey, "X.509 certificate "+certName(c)
		}
	case "OPENSSH PRIVATE KEY":
		key, err = ssh.ParseRawPrivateKey(pem.EncodeToMemory(b))
		if _, ok := errors.AsType[*ssh.PassphraseMissingError](err); ok {
			return nil, errors.New("encrypted with a passphrase; decrypt a copy locally first: ssh-keygen -p -N '' -f copy_of_key")
		}
		if p, ok := key.(*ed25519.PrivateKey); ok { // the ssh package returns a pointer
			key = *p
		}
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", b.Type)
	}
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(b.Type, "PRIVATE KEY") {
		return keyFromPrivate(key, source)
	}
	return keyFromPublic(key, source)
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
	f := keysFactsOf(pub)
	if f.kind == "" {
		return nil, fmt.Errorf("unsupported public key type %T (X25519 and DSA keys can't sign)", pub)
	}
	if err := checkRSASize(pub); err != nil {
		return nil, err
	}
	return &Key{Kind: f.kind, Public: pub, Source: source}, nil
}

func keyFromPrivate(priv any, source string) (*Key, error) {
	s, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type %T (X25519 and DSA keys can't sign)", priv)
	}
	k, err := keyFromPublic(s.Public(), source)
	if err != nil {
		return nil, err
	}
	k.Private = s
	return k, nil
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
		if _, ok := errors.AsType[*json.UnmarshalTypeError](err); ok { // "keys" isn't an array
			return nil, fmt.Errorf("JWKS: %w", jsonError(err))
		}
		return nil, fmt.Errorf("not valid JSON: %w", jsonError(err))
	}
	entries, label := probe.Keys, func(i int) string { return fmt.Sprintf("JWKS entry %d", i+1) }
	switch {
	case entries == nil:
		entries, label = []json.RawMessage{data}, func(int) string { return "JWK" }
	case len(entries) > maxKeys:
		return nil, errTooManyKeys
	case len(entries) == 0:
		return nil, errors.New("JWKS has no keys")
	}
	keys := make([]Key, len(entries))
	for i, raw := range entries {
		var j JWK
		if err := json.Unmarshal(raw, &j); err != nil {
			return nil, fmt.Errorf("%s: %w", label(i), jsonError(err))
		}
		k, err := keyFromJWK(j, label(i))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label(i), err)
		}
		keys[i] = *k
	}
	return keys, nil
}

// ecCurves maps JWK crv names to the ES* alg that signs on each, whose jwsAlgs row holds the curve.
var ecCurves = map[string]string{"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}

func keyFromJWK(j JWK, source string) (*Key, error) {
	var bad error // the first member that isn't base64url
	b64 := func(name, v string) []byte {
		b, err := b64url.DecodeString(strings.TrimRight(v, "="))
		if err != nil && bad == nil {
			bad = fmt.Errorf("%q is not base64url: %w", name, err)
		}
		return b
	}
	num := func(name, v string) *big.Int { return new(big.Int).SetBytes(b64(name, v)) }
	k := &Key{Source: source, KID: j.Kid, Alg: j.Alg, Use: j.Use}
	switch j.Kty {
	case "oct":
		k.Kind, k.Secret = KindSecret, b64("k", j.K)
	case "RSA":
		n, e := num("n", j.N), num("e", j.E)
		switch {
		case bad != nil:
			return nil, bad
		case !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1:
			return nil, errors.New(`"e" is out of range`)
		}
		pub := &rsa.PublicKey{N: n, E: int(e.Int64())}
		if err := checkRSASize(pub); err != nil {
			return nil, err
		}
		k.Kind, k.Public = KindRSA, pub
		if j.D != "" {
			if j.P == "" || j.Q == "" {
				return nil, errors.New(`private RSA JWK without "p" and "q" is not supported`)
			}
			priv := &rsa.PrivateKey{PublicKey: *pub, D: num("d", j.D), Primes: []*big.Int{num("p", j.P), num("q", j.Q)}}
			if bad != nil {
				return nil, bad
			}
			// Validate inverts q mod p before it checks p*q == n, so an oversized prime costs minutes.
			if priv.Primes[0].BitLen() > n.BitLen() || priv.Primes[1].BitLen() > n.BitLen() {
				return nil, errors.New("RSA private key is inconsistent: a prime is longer than the modulus")
			}
			if err := priv.Validate(); err != nil {
				return nil, fmt.Errorf("RSA private key is inconsistent: %w", err)
			}
			priv.Precompute()
			k.Private = priv
		}
	case "EC":
		c, ok := jwsAlgs[ecCurves[j.Crv]]
		if !ok {
			return nil, fmt.Errorf("unsupported EC curve %q (want P-256, P-384 or P-521)", j.Crv)
		}
		size := c.size()
		x, y := b64("x", j.X), b64("y", j.Y)
		switch {
		case bad != nil:
			return nil, bad
		case len(x) > size || len(y) > size:
			return nil, fmt.Errorf("coordinates are longer than %d bytes, the size of %s", size, j.Crv)
		}
		// RFC 7518 §6.2.1.2 fixes their size, but some encoders drop leading zeros.
		pub, err := ecdsa.ParseUncompressedPublicKey(c.curve, append([]byte{4}, append(leftPad(x, size), leftPad(y, size)...)...))
		if err != nil {
			return nil, fmt.Errorf("the point is not on %s: %w", j.Crv, err)
		}
		k.Kind, k.Public = KindEC, pub
		if j.D != "" {
			db := b64("d", j.D)
			d := new(big.Int).SetBytes(db)
			// Checked here, as Go's errors for these talk of public key encodings and moduli.
			switch {
			case bad != nil:
				return nil, bad
			case len(db) > size:
				return nil, fmt.Errorf(`"d" is longer than %d bytes, the size of %s`, size, j.Crv)
			case d.Sign() == 0:
				return nil, errors.New(`"d" is zero, so it isn't a private key`)
			case d.Cmp(c.curve.Params().N) >= 0:
				return nil, fmt.Errorf(`"d" is not below the order of %s, so it isn't a private key`, j.Crv)
			}
			priv, err := ecdsa.ParseRawPrivateKey(c.curve, leftPad(db, size))
			switch {
			case err != nil:
				return nil, fmt.Errorf(`"d": %w`, err)
			case !priv.PublicKey.Equal(pub):
				return nil, errors.New(`"d" does not belong to the public point in "x"/"y"`)
			}
			k.Private = priv
		}
	case "OKP":
		if j.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve %q (only Ed25519 can sign)", j.Crv)
		}
		pub := ed25519.PublicKey(b64("x", j.X))
		switch {
		case bad != nil:
			return nil, bad
		case len(pub) != ed25519.PublicKeySize:
			return nil, fmt.Errorf(`"x" is %d bytes; an Ed25519 public key is 32`, len(pub))
		}
		k.Kind, k.Public = KindEd25519, pub
		if j.D != "" {
			d := b64("d", j.D)
			switch {
			case bad != nil:
				return nil, bad
			case len(d) != ed25519.SeedSize:
				return nil, fmt.Errorf(`"d" is %d bytes; an Ed25519 private key seed is 32`, len(d))
			case !pub.Equal(ed25519.NewKeyFromSeed(d).Public()):
				return nil, errors.New(`"d" does not belong to the public key in "x"`)
			}
			k.Private = ed25519.NewKeyFromSeed(d)
		}
	case "":
		return nil, errors.New(`no "kty" member`)
	default:
		return nil, fmt.Errorf("unsupported kty %q", j.Kty)
	}
	if bad != nil {
		return nil, bad
	}
	return k, nil
}

func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	return append(make([]byte, n-len(b)), b...)
}

// keysFacts describes a public key: kind is "" if it can't sign, alg is its JWK's usual one.
type keysFacts struct {
	kind, name, curve, alg string
	bits                   int
}

func keysFactsOf(pub crypto.PublicKey) keysFacts {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		n := p.N.BitLen()
		return keysFacts{KindRSA, fmt.Sprintf("RSA %d-bit", n), "", "RS256", n}
	case *ecdsa.PublicKey:
		c := p.Curve.Params()
		return keysFacts{KindEC, "ECDSA " + c.Name, c.Name, ecCurves[c.Name], c.BitSize}
	case ed25519.PublicKey:
		return keysFacts{KindEd25519, "Ed25519", "Ed25519", "EdDSA", 0}
	case *ecdh.PublicKey:
		return keysFacts{name: fmt.Sprint(p.Curve())}
	case nil:
		return keysFacts{name: "unknown key type"}
	}
	return keysFacts{name: fmt.Sprintf("%T", pub)}
}

// keyName is a public key's kind and size: "RSA 2048-bit", "ECDSA P-256".
func keyName(pub crypto.PublicKey) string { return keysFactsOf(pub).name }

func keysB64Int(n *big.Int) string { return b64url.EncodeToString(n.Bytes()) }

// PublicJWK never carries d, p, q, dp, dq or qi, whatever key it came from.
// Integers drop leading zeros; EC coordinates keep the curve's size (RFC 7518 §6.2.1.2).
func PublicJWK(pub crypto.PublicKey) (JWK, error) {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		return JWK{Kty: "RSA", N: keysB64Int(p.N), E: keysB64Int(big.NewInt(int64(p.E)))}, nil
	case *ecdsa.PublicKey:
		crv := p.Curve.Params().Name
		if jwsAlgs[ecCurves[crv]].curve != p.Curve {
			return JWK{}, fmt.Errorf("no JWK name for curve %s", crv)
		}
		point, err := p.Bytes() // 0x04 ‖ X ‖ Y
		if err != nil {
			return JWK{}, err
		}
		size := len(point) / 2
		return JWK{Kty: "EC", Crv: crv, X: b64url.EncodeToString(point[1 : 1+size]), Y: b64url.EncodeToString(point[1+size:])}, nil
	case ed25519.PublicKey:
		return JWK{Kty: "OKP", Crv: "Ed25519", X: b64url.EncodeToString(p)}, nil
	}
	return JWK{}, fmt.Errorf("no JWK form for %s", keyName(pub))
}

// PrivateJWK adds d and, for RSA, the CRT members; EC's d keeps the curve's size.
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
		pp, q, one := p.Primes[0], p.Primes[1], big.NewInt(1)
		qi := new(big.Int).ModInverse(q, pp)
		if qi == nil {
			return JWK{}, errors.New("RSA key is inconsistent: q has no inverse mod p")
		}
		j.D, j.P, j.Q, j.QI = keysB64Int(p.D), keysB64Int(pp), keysB64Int(q), keysB64Int(qi)
		j.DP = keysB64Int(new(big.Int).Mod(p.D, new(big.Int).Sub(pp, one)))
		j.DQ = keysB64Int(new(big.Int).Mod(p.D, new(big.Int).Sub(q, one)))
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

// JWKThumbprint is RFC 7638's; take it of a PublicJWK so input padding can't change it.
func JWKThumbprint(j JWK) (string, error) {
	members, ok := map[string]map[string]string{
		"RSA": {"e": j.E, "n": j.N},
		"EC":  {"crv": j.Crv, "x": j.X, "y": j.Y},
		"OKP": {"crv": j.Crv, "x": j.X}, // RFC 8037 §2
		"oct": {"k": j.K},
	}[j.Kty]
	if !ok {
		return "", fmt.Errorf("no thumbprint for kty %q", j.Kty)
	}
	for _, name := range slices.Sorted(maps.Keys(members)) {
		if members[name] == "" {
			return "", fmt.Errorf("no %q member", name)
		}
	}
	members["kty"] = j.Kty
	b, _ := json.Marshal(members) // sorted keys, no whitespace
	sum := sha256.Sum256(b)
	return b64url.EncodeToString(sum[:]), nil
}

// fingerprintHex is openssl's form: uppercase hex pairs joined by colons.
func fingerprintHex(b []byte) string { return strings.ToUpper(hexColons(b)) }

func samePublicKey(a, b crypto.PublicKey) bool {
	e, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && b != nil && e.Equal(b)
}

var sshKeyTypes = map[string]bool{
	"ssh-rsa": true, "ssh-dss": true, "ssh-ed25519": true,
	"ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true, "ecdsa-sha2-nistp521": true,
	"sk-ssh-ed25519@openssh.com": true, "sk-ecdsa-sha2-nistp256@openssh.com": true,
}

// isSSHKeyType matches exact names, so a secret merely containing "ssh-" stays a secret.
func isSSHKeyType(f string) bool {
	t := strings.TrimSuffix(f, "-cert-v01@openssh.com")
	if t != f && strings.HasPrefix(t, "sk-") {
		t += "@openssh.com"
	}
	return sshKeyTypes[t]
}

// sshLines are s's lines that aren't blank or # comments, "\r" cut, and their 1-based numbers.
func sshLines(s string) (lines []string, nums []int) {
	for n, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "#") {
			lines, nums = append(lines, strings.TrimRight(line, "\r")), append(nums, n+1)
		}
	}
	return lines, nums
}

// looksLikeOpenSSH: the first line that isn't blank or a # comment names a key type.
func looksLikeOpenSSH(s string) bool {
	lines, _ := sshLines(s)
	return len(lines) > 0 && slices.ContainsFunc(strings.Fields(lines[0]), isSSHKeyType)
}

// parseOpenSSH runs after looksLikeOpenSSH, so there is always a line to read.
func parseOpenSSH(s string) ([]Key, error) {
	lines, nums := sshLines(s)
	var keys []Key
	for i, line := range lines {
		if i == maxKeys {
			return nil, errTooManyKeys
		}
		k, err := keyFromOpenSSH(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", nums[i], err)
		}
		keys = append(keys, *k)
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
	cp, ok := pk.(ssh.CryptoPublicKey)
	switch t := pk.Type(); {
	case strings.HasPrefix(t, "sk-"):
		return nil, fmt.Errorf("%s is a security-key (FIDO) key: its signatures are in a format only OpenSSH checks, so it has no PEM or JWK form", t)
	case t == "ssh-dss":
		return nil, errors.New("ssh-dss (DSA) keys are not supported; OpenSSH has disabled them by default since version 7.0")
	case !ok:
		return nil, fmt.Errorf("unsupported OpenSSH key type %s", t)
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

// openSSHLineError says why ssh.ParseAuthorizedKey refused a line; offsets count from its start.
func openSSHLineError(line string) error {
	fields := strings.Fields(line)
	i := slices.IndexFunc(fields, isSSHKeyType)
	switch {
	case i < 0:
		return errors.New("not an OpenSSH public key line")
	case i+1 == len(fields):
		return fmt.Errorf("%s with no key data after it", fields[i])
	}
	f, data, end := fields[i], fields[i+1], 0
	for _, s := range fields[:i+2] {
		end += strings.Index(line[end:], s) + len(s)
	}
	b, _, err := decodeBase64Any(strings.Repeat(" ", end-len(data)) + data)
	if err != nil {
		return fmt.Errorf("the key data after %s: %w", f, err)
	}
	if _, err := ssh.ParsePublicKey(b); err != nil {
		return fmt.Errorf("the %s key data doesn't parse: %v", f, err)
	}
	return fmt.Errorf("the line says %s, and its key data doesn't agree", f)
}
