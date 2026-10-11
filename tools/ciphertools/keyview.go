package ciphertools

import (
	"cmp"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// Generated keys say "for testing" wherever they appear: anything real belongs in a KMS.
func init() {
	register(Op{Name: "keys-generate", Path: "/keys/generate", Page: "keys", Fragment: "cipher/keys-generated",
		Heavy: true, Run: runKeysGenerate,
		Fields: []Field{
			{Name: "type", Kind: KindEnum, Enum: keyTypeIDs, Default: keyTypeIDs[0],
				Description: "The key pair to generate: Ed25519, ECDSA on P-256, P-384 or P-521, or RSA of 2048, 3072 or 4096 bits (RSA-4096 takes seconds)."},
			{Name: "comment", Kind: KindString,
				Description: "The comment ending the OpenSSH public key line, one printable line of up to 256 characters; default cipher-tools-test-key."},
			{Name: "passphrase", Kind: KindString,
				Description: "A passphrase to encrypt the private key with: it then comes back only in OpenSSH format (bcrypt_pbkdf and AES-256-CTR), without the unencrypted PKCS#8 and JWK forms."},
		}})
	register(Op{Name: "keys-inspect", Path: "/keys/inspect", Page: "keys", Fragment: "cipher/keys-inspected",
		Run: runKeysInspect,
		Fields: []Field{
			{Name: "key", Kind: KindString, Required: true,
				Description: "The key or keys to convert and fingerprint: PEM (PKCS#8, PKCS#1, SEC 1, SPKI, an OpenSSH private key or a certificate), a JWK or JWKS, or OpenSSH public key lines; up to 64 keys."},
		}})
}

// keyTypeIDs is generate's menu (keys.html repeats it) and its whole CPU cap.
var keyTypeIDs = []string{"ed25519", "ec-p256", "ec-p384", "ec-p521", "rsa-2048", "rsa-3072", "rsa-4096"}

// KeyView is one key in every form the Keys page shows.
type KeyView struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Bits    int    `json:"bits,omitempty"`
	Curve   string `json:"curve,omitempty"`
	Private bool   `json:"private"`
	Source  string `json:"source"`
	Alg     string `json:"alg,omitempty"` // the JWK's own, else the usual one for the key

	PublicPEM        string `json:"public_pem,omitempty"`
	PublicJWK        *JWK   `json:"public_jwk,omitempty"`
	OpenSSH          string `json:"openssh,omitempty"`
	PrivatePEM       string `json:"private_pem,omitempty"`
	PrivateJWK       *JWK   `json:"private_jwk,omitempty"`
	OpenSSHPrivate   string `json:"openssh_private,omitempty"` // the file ssh-keygen writes
	OpenSSHEncrypted bool   `json:"openssh_encrypted,omitempty"`

	Thumbprint     string `json:"jwk_thumbprint,omitempty"`
	SPKISHA256     string `json:"spki_sha256,omitempty"`
	SPKIPin        string `json:"spki_sha256_base64,omitempty"` // HPKP, curl --pinnedpubkey
	SSHFingerprint string `json:"ssh_fingerprint,omitempty"`

	Warnings Warnings `json:"warnings,omitempty"`

	PublicJWKJSON  string `json:"-"`
	PrivateJWKJSON string `json:"-"`
	Generated      bool   `json:"-"`
}

// keysPane is one format tab of the key view; the page skips those with no Public.
type keysPane struct{ ID, Label, Public, Private string }

func (v KeyView) Panes() []keysPane {
	return []keysPane{{"openssh", "OpenSSH", v.OpenSSH, v.OpenSSHPrivate},
		{"pem", "PEM", v.PublicPEM, v.PrivatePEM}, {"jwk", "JWK", v.PublicJWKJSON, v.PrivateJWKJSON}}
}

type KeyGenResult struct {
	Type   string  `json:"type"`
	Where  string  `json:"where"` // "browser" (the wasm engine) or "server"
	TookMS float64 `json:"took_ms"`
	Key    KeyView `json:"key"`

	Took string `json:"-"`
}

type KeyInspectResult struct {
	Keys       []KeyView `json:"keys"`
	PublicJWKS *JWKS     `json:"public_jwks,omitempty"` // when there is more than one key

	PublicJWKSJSON string `json:"-"`
}

// JWKS is a JWK Set (RFC 7517 §5).
type JWKS struct {
	Keys []JWK `json:"keys"`
}

func runKeysGenerate(in Input) (any, error) {
	typ := choice(in.Get("type"), keyTypeIDs[0])
	start := time.Now()
	priv, err := generateKey(typ)
	if err != nil {
		return nil, err
	}
	took := time.Since(start)
	comment, err := sshComment(in.Get("comment"))
	if err != nil {
		return nil, err
	}
	k, _ := keyFromPrivate(priv, "generated just now")
	k.Comment = comment
	v, _ := viewKey(*k, true)
	// PKCS#8 and JWK can't carry a passphrase: drop them, never hand them out in the clear.
	if pass := in.Get("passphrase"); pass != "" {
		blk, err := ssh.MarshalPrivateKeyWithPassphrase(k.Private, k.Comment, []byte(pass))
		if err != nil {
			return nil, fmt.Errorf("encrypting the OpenSSH key: %w", err)
		}
		v.OpenSSHPrivate, v.OpenSSHEncrypted = string(pem.EncodeToMemory(blk)), true
		v.PrivatePEM, v.PrivateJWK, v.PrivateJWKJSON = "", nil, ""
		v.Warnings.add(LevelInfo, "The private key is shown only in OpenSSH format, encrypted with your passphrase. The PKCS#8 and JWK forms are left out because they would be unencrypted.")
	}
	where := "browser"
	if runtime.GOOS != "js" {
		where = "server"
	}
	return &KeyGenResult{Type: typ, Where: where, TookMS: millis(took), Took: tookText(took), Key: v}, nil
}

func generateKey(typ string) (crypto.Signer, error) {
	switch typ {
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	case "ec-p256", "ec-p384", "ec-p521":
		return ecdsa.GenerateKey(jwsAlgs[ecCurves["P-"+typ[4:]]].curve, rand.Reader)
	case "rsa-2048", "rsa-3072", "rsa-4096":
		bits, _ := strconv.Atoi(typ[4:])
		return rsa.GenerateKey(rand.Reader, bits)
	}
	return nil, fmt.Errorf("type: want one of %s, got %q", strings.Join(keyTypeIDs, ", "), typ)
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
		r.PublicJWKS, r.PublicJWKSJSON = &set, indentJSON(set)
	}
	return r, nil
}

// viewKey builds the public JWK from the public key alone, so no private member can reach it.
func viewKey(k Key, generated bool) (KeyView, error) {
	v := KeyView{Kind: k.Kind, Source: k.Source, Private: k.Private != nil, Generated: generated}
	if k.Kind == KindSecret {
		v.Name, v.Bits = fmt.Sprintf("%d-byte shared secret", len(k.Secret)), 8*len(k.Secret)
		v.Thumbprint, _ = JWKThumbprint(JWK{Kty: "oct", K: b64url.EncodeToString(k.Secret)})
		v.Warnings.add(LevelInfo, "A shared secret (kty oct) has no public half, so there is no PEM, public JWK or OpenSSH form of it.")
		return v, nil
	}
	f := keysFactsOf(k.Public)
	v.Name, v.Bits, v.Curve, v.Alg = f.name, f.bits, f.curve, cmp.Or(k.Alg, f.alg)
	der, err := x509.MarshalPKIXPublicKey(k.Public)
	if err != nil {
		return v, err
	}
	sum := sha256.Sum256(der)
	v.PublicPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	v.SPKISHA256, v.SPKIPin = fingerprintHex(sum[:]), base64.StdEncoding.EncodeToString(sum[:])
	pub, err := PublicJWK(k.Public)
	if err == nil {
		v.Thumbprint, err = JWKThumbprint(pub)
	}
	if err != nil {
		return v, err
	}
	pub.Kid, pub.Alg, pub.Use = cmp.Or(k.KID, v.Thumbprint), v.Alg, k.Use
	v.PublicJWK, v.PublicJWKJSON = &pub, indentJSON(pub)
	if pk, err := ssh.NewPublicKey(k.Public); err == nil {
		v.OpenSSH = strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pk)), "\n")
		if k.Comment != "" {
			v.OpenSSH += " " + k.Comment
		}
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
			v.Warnings.add(LevelInfo, "No private JWK: "+err.Error()+".")
		}
	}
	v.keyWarnings(k, generated)
	return v, nil
}

// sshComment is ssh-keygen's -C; empty marks the key as a test key wherever it ends up.
func sshComment(s string) (string, error) {
	switch s = strings.TrimSpace(s); {
	case s == "":
		return "cipher-tools-test-key", nil
	case utf8.RuneCountInString(s) > 256:
		return "", errors.New("comment: keep it under 256 characters")
	case strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return "", errors.New("comment: one line of printable text")
	}
	return s, nil
}

func (v *KeyView) keyWarnings(k Key, generated bool) {
	if k.Private != nil && !generated {
		v.Warnings.add(LevelWarn, "This is a private key. Share only the public forms; the private ones are folded away below.")
	}
	if p, ok := k.Public.(*rsa.PublicKey); ok {
		if p.N.BitLen() < 2048 {
			v.Warnings.add(LevelWarn, fmt.Sprintf("RSA %d-bit: below 2048 bits, the minimum NIST, RFC 7518 and certificate authorities accept.", p.N.BitLen()))
		}
		if p.E != 65537 {
			v.Warnings.add(LevelInfo, fmt.Sprintf("The public exponent is %d. Almost every RSA key uses 65537.", p.E))
		}
	}
	if strings.HasPrefix(k.Source, "PKCS#1") || strings.HasPrefix(k.Source, "SEC 1") {
		v.Warnings.add(LevelInfo, "Read as "+k.Source+", the older format. The PEM below is PKCS#8 / SPKI, which most libraries expect now.")
	}
	if spec, ok := jwsAlgs[k.Alg]; ok && !jwtKeyFits(spec, k) {
		// Every name keyName gives an asymmetric key (RSA, ECDSA, Ed25519) takes "an".
		v.Warnings.add(LevelWarn, fmt.Sprintf("The JWK says alg %s, but an %s key signs %s. A library that trusts the alg member will refuse it.",
			k.Alg, v.Name, keysFactsOf(k.Public).alg))
	}
}

func indentJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
