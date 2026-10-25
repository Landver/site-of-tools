package ciphertools

import (
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var (
	dpopAlgField = Field{Name: "alg", Kind: KindEnum, Enum: []string{"ES256", "RS256", "EdDSA"}, Default: "ES256",
		Description: "The signing algorithm: ES256 (ECDSA P-256, RFC 9449's usual choice), RS256 (RSA) or EdDSA (Ed25519)."}
	dpopLeewayField = Field{Name: "leeway", Kind: KindInt, Min: ptr(0), Max: ptr(86400),
		Description: "Clock skew in seconds allowed when checking the iat creation timestamp."}.withDefault(60)
)

// dpopKeyTypes is the keys-generate type made for each alg when no key is given.
var dpopKeyTypes = map[string]string{"ES256": "ec-p256", "RS256": "rsa-2048", "EdDSA": "ed25519"}

func init() {
	register(Op{Name: "dpop-generate", Path: "/dpop/generate", Page: "dpop", Fragment: "cipher/dpop-generated", Heavy: true,
		Fields: []Field{
			{
				Name:        "htm",
				Kind:        KindString,
				Required:    true,
				Description: "The HTTP request method (e.g. GET, POST, PUT, DELETE, PATCH).",
			},
			{
				Name:        "htu",
				Kind:        KindString,
				Required:    true,
				Description: "The target HTTP request URI; its query and fragment are left out of the proof (e.g. https://api.example.com/resource).",
			},
			{
				Name:        "access_token",
				Kind:        KindString,
				Description: "The access token the request carries, if any: the proof gets its hash as the ath claim, and the curl line an Authorization: DPoP header with the token itself.",
			},
			{
				Name:        "nonce",
				Kind:        KindString,
				Description: "An optional server-provided DPoP nonce challenge string from a DPoP-Nonce response header.",
			},
			dpopAlgField,
			{
				Name:        "key",
				Kind:        KindString,
				Description: "A private key for alg as PEM or JWK; omit it to have a fresh one generated (P-256, RSA-2048 or Ed25519) and returned as PKCS#8 PEM.",
			},
			nowField,
		},
		Run: runDPoPGenerate,
	})

	register(Op{Name: "dpop-verify", Path: "/dpop/verify", Page: "dpop", Fragment: "cipher/dpop-verified",
		Fields: []Field{
			{
				Name:        "token",
				Kind:        KindString,
				Required:    true,
				Description: "The DPoP proof JWT to verify (header.payload.signature); a DPoP: header name, quotes and line breaks around it are removed.",
			},
			{
				Name:        "htm",
				Kind:        KindString,
				Required:    true,
				Description: "The expected HTTP request method that the proof was issued for (e.g. GET, POST).",
			},
			{
				Name:        "htu",
				Kind:        KindString,
				Required:    true,
				Description: "The URI of the request the proof came with; its query and fragment are ignored, as RFC 9449 compares htu without them.",
			},
			{
				Name:        "access_token",
				Kind:        KindString,
				Description: "The optional raw access token presented with the request, to verify against the ath claim.",
			},
			dpopLeewayField,
			nowField,
		},
		Run: runDPoPVerify,
	})
}

// DPoPCheck is one check on a DPoP proof.
type DPoPCheck struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

type DPoPGenerateResult struct {
	Token         string          `json:"token"`
	HTM           string          `json:"htm"`
	HTU           string          `json:"htu"`
	Alg           string          `json:"alg"`
	Header        json.RawMessage `json:"header"`
	Payload       json.RawMessage `json:"payload"`
	PublicJWK     JWK             `json:"public_jwk"`
	JWKThumbprint string          `json:"jwk_thumbprint"`
	Curl          string          `json:"curl"`
	Key           string          `json:"key,omitempty"` // the generated private key as PKCS#8 PEM, when none was given

	HeaderJSON  string `json:"-"`
	PayloadJSON string `json:"-"`
}

type DPoPVerifyResult struct {
	Valid         bool            `json:"valid"`
	Status        string          `json:"status"` // "valid" or "invalid"
	HTM           string          `json:"htm"`
	HTU           string          `json:"htu"`
	Summary       string          `json:"summary"`
	JWKThumbprint string          `json:"jwk_thumbprint,omitempty"`
	Header        json.RawMessage `json:"header"`
	Payload       json.RawMessage `json:"payload"`
	Checks        []DPoPCheck     `json:"checks"`

	HeaderJSON  string `json:"-"`
	PayloadJSON string `json:"-"`
}

// dpopHeader and dpopClaims are a proof's members in the order a proof is written.
type dpopHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	JWK *JWK   `json:"jwk,omitempty"`
}

type dpopClaims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	ATH   string `json:"ath,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

func runDPoPGenerate(in Input) (any, error) {
	now, err := in.now()
	if err != nil {
		return nil, err
	}
	htm, htu, err := dpopRequest(in)
	if err != nil {
		return nil, err
	}
	alg, err := enumField(in.Get("alg"), dpopAlgField)
	if err != nil {
		return nil, err
	}
	key, generated, err := dpopSigningKey(alg, in.Get("key"))
	if err != nil {
		return nil, err
	}
	r := &DPoPGenerateResult{HTM: htm, HTU: htu, Alg: alg, Key: generated}
	if r.PublicJWK, err = PublicJWK(key.Public); err == nil {
		r.JWKThumbprint, err = JWKThumbprint(r.PublicJWK)
	}
	if err != nil {
		return nil, err
	}
	claims := dpopClaims{JTI: b64url.EncodeToString(randomBytes(16)), HTM: htm, HTU: htu, IAT: now.Unix(),
		Nonce: strings.TrimSpace(in.Get("nonce"))}
	accessToken := strings.TrimSpace(in.Get("access_token"))
	if accessToken != "" {
		claims.ATH = s256(accessToken)
	}
	// Structs of strings and ints always marshal.
	r.Header, _ = json.Marshal(dpopHeader{Typ: "dpop+jwt", Alg: alg, JWK: &r.PublicJWK})
	r.Payload, _ = json.Marshal(claims)
	input := b64url.EncodeToString(r.Header) + "." + b64url.EncodeToString(r.Payload)
	sig, err := signJWS(jwsAlgs[alg], key, []byte(input))
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}
	r.Token = input + "." + b64url.EncodeToString(sig)
	r.HeaderJSON, r.PayloadJSON = pretty(r.Header), pretty(r.Payload)
	r.Curl = fmt.Sprintf("curl -X %s \\\n  -H \"DPoP: %s\" \\\n", htm, r.Token)
	if accessToken != "" {
		r.Curl += fmt.Sprintf("  -H \"Authorization: DPoP %s\" \\\n", accessToken)
	}
	r.Curl += fmt.Sprintf("  \"%s\"", htu)
	return r, nil
}

// dpopSigningKey is the pasted private key for alg or, with none pasted, a fresh one and its PKCS#8 PEM.
func dpopSigningKey(alg, pasted string) (Key, string, error) {
	if strings.TrimSpace(pasted) != "" {
		k, err := signingKey(jwsAlgs[alg], alg, pasted, "", "")
		return k, "", err
	}
	priv, err := generateKey(dpopKeyTypes[alg])
	if err != nil {
		return Key{}, "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Key{}, "", err
	}
	k, _ := keyFromPrivate(priv, "generated just now")
	return *k, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func runDPoPVerify(in Input) (any, error) {
	now, err := in.now()
	if err != nil {
		return nil, err
	}
	leeway, err := intField(in, dpopLeewayField)
	if err != nil {
		return nil, err
	}
	htm, htu, err := dpopRequest(in)
	if err != nil {
		return nil, err
	}
	tok := cleanToken(in.Get("token"))
	if tok == "" {
		return nil, errors.New("no DPoP proof given")
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%d dot-separated parts: a DPoP proof is a signed JWT of three (header.payload.signature)", len(parts))
	}
	r := &DPoPVerifyResult{HTM: htm, HTU: htu}
	var hdr dpopHeader
	var claims dpopClaims
	if r.Header, err = dpopPart(parts[0], "header", &hdr); err != nil {
		return nil, err
	}
	if r.Payload, err = dpopPart(parts[1], "payload", &claims); err != nil {
		return nil, err
	}
	sig, err := segment(parts[2], "signature")
	if err != nil {
		return nil, err
	}
	r.HeaderJSON, r.PayloadJSON = pretty(r.Header), pretty(r.Payload)

	add := func(name string, ok bool, detail string) {
		r.Checks = append(r.Checks, DPoPCheck{Name: name, Passed: ok, Detail: detail})
	}
	add("Header typ is dpop+jwt", strings.EqualFold(hdr.Typ, "dpop+jwt"),
		fmt.Sprintf("typ is %q; RFC 9449 requires \"dpop+jwt\".", hdr.Typ))
	spec, known := jwsAlgs[hdr.Alg]
	algOK := known && spec.kind != KindSecret
	add("Asymmetric algorithm", algOK,
		fmt.Sprintf("alg is %q; it must be an asymmetric signature algorithm (RS*, PS*, ES*, EdDSA).", hdr.Alg))

	key, keyDetail := dpopHeaderKey(hdr.JWK)
	add("Embedded public JWK", key != nil, keyDetail)
	if key != nil {
		pub, _ := PublicJWK(key.Public) // every key dpopHeaderKey passes has one
		r.JWKThumbprint, _ = JWKThumbprint(pub)
	}

	sigOK, sigDetail := false, "Not checked: it needs an asymmetric alg and a usable jwk."
	switch {
	case !algOK || key == nil:
	case !jwtKeyFits(spec, *key):
		sigDetail = fmt.Sprintf("The jwk is %s, but %s needs %s.", keyName(key.Public), hdr.Alg, algNeeds(spec))
	default:
		sigOK = verifyJWS(spec, *key, []byte(parts[0]+"."+parts[1]), sig)
		sigDetail = ifElse(sigOK, "Valid for the embedded public key.", "Does not verify: the proof was altered, or signed with another key.")
	}
	add("Signature verification", sigOK, sigDetail)

	add("HTTP method (htm)", claims.HTM == htm, fmt.Sprintf("The proof's htm is %q; the request's is %q.", claims.HTM, htm))
	proofHTU, err := dpopURI(claims.HTU)
	bare := !strings.ContainsAny(claims.HTU, "?#")
	htuDetail := fmt.Sprintf("The proof's htu is %q; the request's is %q.", claims.HTU, htu)
	if !bare {
		htuDetail += " RFC 9449 leaves the query and fragment out of htu."
	}
	add("HTTP URI (htu)", bare && err == nil && proofHTU == htu, htuDetail)

	iat, skew := time.Unix(claims.IAT, 0), time.Duration(leeway)*time.Second
	add("Creation timestamp (iat)", iat.Sub(now).Abs() <= skew, fmt.Sprintf("iat is %s; the time is %s, with %s of skew allowed either way.",
		iat.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339), skew))
	add("Unique identifier (jti)", claims.JTI != "", ifElse(claims.JTI != "",
		fmt.Sprintf("jti is %q; a server refuses one it has seen before.", claims.JTI),
		"The proof has no jti, which RFC 9449 requires."))

	if accessToken := strings.TrimSpace(in.Get("access_token")); accessToken != "" || claims.ATH != "" {
		athOK, athDetail := false, "The proof has an ath, but no access token was given to check it against."
		switch {
		case accessToken == "":
		case claims.ATH == "":
			athDetail = "An access token was given, but the proof has no ath to bind it."
		default:
			want := s256(accessToken)
			athOK = subtle.ConstantTimeCompare([]byte(claims.ATH), []byte(want)) == 1
			athDetail = ifElse(athOK, "ath is the SHA-256 of the access token.", fmt.Sprintf("ath is %q; the access token's SHA-256 is %q.", claims.ATH, want))
		}
		add("Access token hash (ath)", athOK, athDetail)
	}

	failed := 0
	for _, c := range r.Checks {
		if !c.Passed {
			failed++
		}
	}
	r.Valid, r.Status = failed == 0, ifElse(failed == 0, "valid", "invalid")
	r.Summary = ifElse(r.Valid, "Every check below passed. Left to the server: refusing a jti it has seen before, and checking any nonce it issued.",
		fmt.Sprintf("%d of %d checks failed; see below.", failed, len(r.Checks)))
	return r, nil
}

// dpopRequest reads the request a proof binds: htm upper-cased, htu as dpopURI compares it.
func dpopRequest(in Input) (htm, htu string, err error) {
	htm = strings.ToUpper(strings.TrimSpace(in.Get("htm")))
	raw := strings.TrimSpace(in.Get("htu"))
	switch {
	case htm == "":
		return "", "", errors.New("HTTP method (htm) is required")
	case raw == "":
		return "", "", errors.New("HTTP URI (htu) is required")
	}
	if htu, err = dpopURI(raw); err != nil {
		return "", "", fmt.Errorf("invalid htu URI: %w", err)
	}
	return htm, htu, nil
}

// dpopURI is raw as RFC 9449 §4.3 compares htu: no query or fragment, scheme and host lower-cased,
// a default port and an empty path normalised (RFC 3986 §6.2.2-6.2.3); the path keeps its case.
func dpopURI(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err == nil && (u.Scheme == "" || u.Host == "") {
		err = errors.New("it needs a scheme and a host")
	}
	if err != nil {
		return "", err
	}
	u.Host = strings.TrimSuffix(strings.ToLower(u.Host), map[string]string{"http": ":80", "https": ":443"}[u.Scheme])
	u.RawQuery, u.ForceQuery, u.Fragment = "", false, ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

// dpopPart decodes a proof's JSON segment into v and returns its bytes as sent.
func dpopPart(seg, name string, v any) (json.RawMessage, error) {
	b, err := segment(seg, name)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return nil, fmt.Errorf("the %s: %w", name, jsonError(err))
	}
	return b, nil
}

// dpopHeaderKey reads the header's jwk, which RFC 9449 requires to be a public key and nothing more.
func dpopHeaderKey(j *JWK) (*Key, string) {
	if j == nil {
		return nil, "The header has no jwk."
	}
	if j.D+j.P+j.Q+j.DP+j.DQ+j.QI+j.K != "" {
		return nil, "RFC 9449 security violation: private key material in the header jwk, which must hold the public key alone."
	}
	k, err := keyFromJWK(*j, "header jwk")
	switch {
	case err != nil:
		return nil, "The jwk does not read as a public key: " + err.Error() + "."
	case k.Kind == KindSecret:
		return nil, "The jwk is a symmetric key (kty oct); a proof carries a public key."
	}
	return k, keyName(k.Public) + " public key."
}
