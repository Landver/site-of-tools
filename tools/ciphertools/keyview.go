package ciphertools

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// C6 — generate a test key pair, or read a pasted key, and show it in every
// form: PEM (PKCS#8 / SPKI), JWK, OpenSSH, and the fingerprints each world
// uses. Parsing lives in keys.go, shared with JWT and Certificates; this file
// only turns a Key into what the page shows.
//
// Generating is Heavy (RSA-4096 takes seconds), and labelled "for testing"
// wherever its output appears: a key anything real depends on belongs in a KMS,
// or comes from ssh-keygen or openssl on the owner's own machine.

func init() {
	register(Op{Name: "keys-generate", Path: "/keys/generate", Page: "keys", Fragment: "cipher/keys-generated",
		Heavy: true, Run: runKeysGenerate})
	register(Op{Name: "keys-inspect", Path: "/keys/inspect", Page: "keys", Fragment: "cipher/keys-inspected",
		Run: runKeysInspect})
}

// KeyTypes are what generate accepts, in the form's menu order (the template
// lists them as literals). The list is also generate's whole CPU cap: no size
// outside it is accepted.
var KeyTypes = []struct{ ID, Name string }{
	{"ed25519", "Ed25519"},
	{"ec-p256", "ECDSA P-256"},
	{"ec-p384", "ECDSA P-384"},
	{"ec-p521", "ECDSA P-521"},
	{"rsa-2048", "RSA 2048"},
	{"rsa-3072", "RSA 3072"},
	{"rsa-4096", "RSA 4096 (takes a few seconds)"},
}

// generatedComment ends a generated key's OpenSSH line, so it is recognisable
// as a test key in an authorized_keys file later.
const generatedComment = "cipher-tools-test-key"

// KeyView is one key in every form the Keys page shows.
type KeyView struct {
	Kind    string `json:"kind"` // rsa | ec | ed25519 | secret
	Name    string `json:"name"` // "RSA 2048-bit", "ECDSA P-256", "Ed25519"
	Bits    int    `json:"bits,omitempty"`
	Curve   string `json:"curve,omitempty"`
	Private bool   `json:"private"`
	Source  string `json:"source"`
	// Alg is the JWK's own alg when it had one, else the usual one for the key.
	Alg string `json:"alg,omitempty"`

	PublicPEM  string `json:"public_pem,omitempty"`
	PublicJWK  *JWK   `json:"public_jwk,omitempty"`
	OpenSSH    string `json:"openssh,omitempty"`
	PrivatePEM string `json:"private_pem,omitempty"`
	PrivateJWK *JWK   `json:"private_jwk,omitempty"`
	// OpenSSHPrivate is the private key in OpenSSH's own format, the file
	// ssh-keygen writes to ~/.ssh/id_ed25519. OpenSSHEncrypted says it is
	// protected by the passphrase given to generate.
	OpenSSHPrivate   string `json:"openssh_private,omitempty"`
	OpenSSHEncrypted bool   `json:"openssh_encrypted,omitempty"`

	// Thumbprint is RFC 7638, over the public members.
	Thumbprint string `json:"jwk_thumbprint,omitempty"`
	// SPKISHA256 is the SHA-256 of the SubjectPublicKeyInfo DER as colon hex;
	// SPKIPin is the same digest as base64 (HPKP, curl --pinnedpubkey).
	SPKISHA256     string `json:"spki_sha256,omitempty"`
	SPKIPin        string `json:"spki_sha256_base64,omitempty"`
	SSHFingerprint string `json:"ssh_fingerprint,omitempty"`

	Warnings []Warning `json:"warnings,omitempty"`

	// Display only.
	PublicJWKJSON  string `json:"-"`
	PrivateJWKJSON string `json:"-"`
	Generated      bool   `json:"-"`
}

func (v *KeyView) warn(level, text string) { v.Warnings = append(v.Warnings, Warning{level, text}) }

// KeyGenResult is a freshly generated test key pair.
type KeyGenResult struct {
	Type string `json:"type"`
	// Where it was made: "browser" (the wasm engine) or "server" (the API,
	// or a browser with JavaScript off).
	Where  string  `json:"where"`
	TookMS float64 `json:"took_ms"`
	Key    KeyView `json:"key"`

	Took string `json:"-"`
}

// KeyInspectResult is every key found in the pasted input.
type KeyInspectResult struct {
	Keys []KeyView `json:"keys"`
	// PublicJWKS holds every key's public JWK, when there is more than one:
	// the thing to publish at a jwks_uri.
	PublicJWKS *JWKS `json:"public_jwks,omitempty"`

	PublicJWKSJSON string `json:"-"`
}

// JWKS is a JWK Set (RFC 7517 §5).
type JWKS struct {
	Keys []JWK `json:"keys"`
}

func runKeysGenerate(in Input) (any, error) {
	typ := strings.ToLower(strings.TrimSpace(in.Get("type")))
	if typ == "" {
		typ = KeyTypes[0].ID
	}
	start := time.Now()
	priv, err := generateKey(typ)
	if err != nil {
		return nil, err
	}
	took := time.Since(start)
	k, err := keyFromPrivate(priv, "generated just now")
	if err != nil {
		return nil, err
	}
	comment, err := sshComment(in.Get("comment"))
	if err != nil {
		return nil, err
	}
	k.Comment = comment
	v, err := viewKey(*k, true)
	if err != nil {
		return nil, err
	}
	// A passphrase encrypts the OpenSSH form (bcrypt_pbkdf + AES-256-CTR, as
	// ssh-keygen does). The PKCS#8 and JWK forms can't carry one here, so they
	// are dropped rather than handed out in the clear beside an encrypted copy
	// that suggests the key is protected.
	if pass := in.Get("passphrase"); pass != "" {
		blk, err := ssh.MarshalPrivateKeyWithPassphrase(k.Private, k.Comment, []byte(pass))
		if err != nil {
			return nil, fmt.Errorf("encrypting the OpenSSH key: %w", err)
		}
		v.OpenSSHPrivate, v.OpenSSHEncrypted = string(pem.EncodeToMemory(blk)), true
		v.PrivatePEM, v.PrivateJWK, v.PrivateJWKJSON = "", nil, ""
		v.warn(LevelInfo, "The private key is shown only in OpenSSH format, encrypted with your passphrase. The PKCS#8 and JWK forms are left out because they would be unencrypted.")
	}
	where := "browser"
	if runtime.GOOS != "js" {
		where = "server"
	}
	return &KeyGenResult{Type: typ, Where: where, TookMS: millis(took), Took: tookText(took), Key: v}, nil
}

// generateKey makes a key of one of KeyTypes, from crypto/rand.
func generateKey(typ string) (crypto.Signer, error) {
	switch typ {
	case "rsa-2048", "rsa-3072", "rsa-4096":
		bits := map[string]int{"rsa-2048": 2048, "rsa-3072": 3072, "rsa-4096": 4096}[typ]
		return rsa.GenerateKey(rand.Reader, bits)
	case "ec-p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ec-p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ec-p521":
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
	ids := make([]string, len(KeyTypes))
	for i, t := range KeyTypes {
		ids[i] = t.ID
	}
	return nil, fmt.Errorf("type: want one of %s, got %q", strings.Join(ids, ", "), typ)
}

func runKeysInspect(in Input) (any, error) {
	keys, err := ParseKeys(in.Get("key"))
	if err != nil {
		return nil, err
	}
	r := &KeyInspectResult{}
	var set JWKS
	for i, k := range keys {
		v, err := viewKey(k, false)
		if err != nil {
			return nil, fmt.Errorf("key %d (%s): %w", i+1, k.Source, err)
		}
		r.Keys = append(r.Keys, v)
		if v.PublicJWK != nil {
			set.Keys = append(set.Keys, *v.PublicJWK)
		}
	}
	if len(keys) > 1 && len(set.Keys) > 0 {
		r.PublicJWKS = &set
		r.PublicJWKSJSON = indentJSON(set)
	}
	return r, nil
}

// viewKey renders k in every form. Private forms appear only when k is a
// private key; the public JWK is built from the public key alone, so no
// private member can reach it.
func viewKey(k Key, generated bool) (KeyView, error) {
	v := KeyView{Kind: k.Kind, Source: k.Source, Private: k.Private != nil, Generated: generated}
	if k.Kind == KindSecret {
		v.Name = fmt.Sprintf("%d-byte shared secret", len(k.Secret))
		v.Bits = 8 * len(k.Secret)
		if len(k.Secret) > 0 {
			v.Thumbprint, _ = JWKThumbprint(JWK{Kty: "oct", K: b64url.EncodeToString(k.Secret)})
		}
		v.warn(LevelInfo, "A shared secret (kty oct) has no public half, so there is no PEM, public JWK or OpenSSH form of it.")
		return v, nil
	}

	v.Name = keyName(k.Public)
	switch p := k.Public.(type) {
	case *rsa.PublicKey:
		v.Bits = p.N.BitLen()
	case *ecdsa.PublicKey:
		v.Curve, v.Bits = p.Curve.Params().Name, p.Curve.Params().BitSize
	case ed25519.PublicKey:
		v.Curve = "Ed25519"
	}
	v.Alg = k.Alg
	if v.Alg == "" {
		v.Alg = jwsAlgFor(k.Public)
	}

	der, err := x509.MarshalPKIXPublicKey(k.Public)
	if err != nil {
		return v, err
	}
	v.PublicPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	sum, _ := spkiSHA256(k.Public)
	v.SPKISHA256, v.SPKIPin = fingerprintHex(sum), base64.StdEncoding.EncodeToString(sum)

	pub, err := PublicJWK(k.Public)
	if err != nil {
		return v, err
	}
	if v.Thumbprint, err = JWKThumbprint(pub); err != nil {
		return v, err
	}
	pub.Kid, pub.Alg, pub.Use = k.KID, v.Alg, k.Use
	if pub.Kid == "" {
		pub.Kid = v.Thumbprint
	}
	v.PublicJWK, v.PublicJWKJSON = &pub, indentJSON(pub)

	if pk, err := ssh.NewPublicKey(k.Public); err == nil {
		v.OpenSSH = openSSHLine(pk, k.Comment)
		v.SSHFingerprint = ssh.FingerprintSHA256(pk)
	}

	if k.Private != nil {
		der, err := x509.MarshalPKCS8PrivateKey(k.Private)
		if err != nil {
			return v, err
		}
		v.PrivatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		if blk, err := ssh.MarshalPrivateKey(k.Private, k.Comment); err == nil {
			v.OpenSSHPrivate = string(pem.EncodeToMemory(blk))
		}
		if priv, err := PrivateJWK(k.Private); err == nil {
			priv.Kid, priv.Alg, priv.Use = pub.Kid, pub.Alg, pub.Use
			v.PrivateJWK, v.PrivateJWKJSON = &priv, indentJSON(priv)
		} else {
			v.warn(LevelInfo, "No private JWK: "+err.Error()+".")
		}
	}
	v.keyWarnings(k, generated)
	return v, nil
}

// sshComment is the -C of ssh-keygen: one line, printable, bounded. Empty means
// the default, which marks the key as a test key wherever it ends up.
func sshComment(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return generatedComment, nil
	}
	if len(s) > 256 {
		return "", errors.New("comment: keep it under 256 characters")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", errors.New("comment: one line of printable text")
		}
	}
	return s, nil
}

func (v *KeyView) keyWarnings(k Key, generated bool) {
	if k.Private != nil && !generated {
		v.warn(LevelWarn, "This is a private key. Share only the public forms; the private ones are folded away below.")
	}
	if p, ok := k.Public.(*rsa.PublicKey); ok {
		if p.N.BitLen() < 2048 {
			v.warn(LevelWarn, fmt.Sprintf("RSA %d-bit: below 2048 bits, the minimum NIST, RFC 7518 and certificate authorities accept.", p.N.BitLen()))
		}
		if p.E != 65537 {
			v.warn(LevelInfo, fmt.Sprintf("The public exponent is %d. Almost every RSA key uses 65537.", p.E))
		}
	}
	for _, legacy := range []string{"PKCS#1", "SEC 1"} {
		if strings.HasPrefix(k.Source, legacy) {
			v.warn(LevelInfo, "Read as "+k.Source+", the older format. The PEM below is PKCS#8 / SPKI, which most libraries expect now.")
		}
	}
	if spec, ok := jwsAlgs[k.Alg]; ok {
		ec, isEC := k.Public.(*ecdsa.PublicKey)
		if spec.kind != k.Kind || spec.curve != nil && isEC && spec.curve != ec.Curve {
			v.warn(LevelWarn, fmt.Sprintf("The JWK says alg %s, but %s key signs %s. A library that trusts the alg member will refuse it.",
				k.Alg, article(v.Name), jwsAlgFor(k.Public)))
		}
	}
}

// article puts "a" or "an" in front of a key name.
func article(name string) string {
	if strings.HasPrefix(name, "RSA") || strings.HasPrefix(name, "ECDSA") || strings.HasPrefix(name, "Ed") {
		return "an " + name
	}
	return "a " + name
}

func indentJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}
