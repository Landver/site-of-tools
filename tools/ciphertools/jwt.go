package ciphertools

import (
	"bytes"
	"cmp"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // registers crypto.SHA256 for rsa/hmac
	_ "crypto/sha512" // registers crypto.SHA384/SHA512
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"
)

// A token that decodes is not one that verifies, so every result carries a Verification.

var jwtLeewayField = Field{Name: "leeway", Kind: KindInt, Min: ptr(0), Max: ptr(86400),
	Description: "Clock skew in seconds allowed when checking exp and nbf."}.withDefault(int(DefaultLeeway / time.Second))

func init() {
	register(Op{Name: "jwt-decode", Path: "/jwt/decode", Page: "jwt", Fragment: "cipher/jwt-result", Run: runJWTDecode,
		Fields: []Field{
			{Name: "token", Kind: KindString, Required: true,
				Description: "The token to decode: a signed JWT (header.payload.signature), or an encrypted JWE of five parts, of which only the header is readable; a Bearer prefix, quotes and line breaks around it are removed."},
			{Name: "key", Kind: KindString,
				Description: "A key to verify the signature with: the shared secret for HS256/384/512, or a public (or private) key as PEM, JWK, JWKS or an OpenSSH line for RS*, PS*, ES* and EdDSA; omit it to decode without verifying."},
			{Name: "key_enc", Kind: KindEnum, Enum: append([]string{EncAuto}, byteEncodings...), Default: EncAuto,
				Description: "How a shared-secret key is written: auto tries UTF-8 text, base64 and hex and reports which reading verified; ignored for PEM and JWK keys."},
			jwtLeewayField,
			nowField,
		}})
	register(Op{Name: "jwt-sign", Path: "/jwt/sign", Page: "jwt", Fragment: "cipher/jwt-signed", Heavy: true, Run: runJWTSign,
		Fields: []Field{
			{Name: "alg", Kind: KindEnum, Enum: append(append([]string(nil), SignAlgs...), "Ed25519"), Default: "HS256",
				Description: "The signature algorithm: HS* sign with a shared secret, RS* and PS* with an RSA private key, ES256/384/512 with an ECDSA P-256/384/521 private key, EdDSA (or its other name Ed25519) with an Ed25519 private key."},
			{Name: "key", Kind: KindString, Required: true,
				Description: "The signing key: the shared secret for HS*, or the private key as PEM (PKCS#8, PKCS#1, SEC 1 or OpenSSH), JWK or JWKS for the others."},
			{Name: "key_enc", Kind: KindEnum, Enum: byteEncodings, Default: EncUTF8,
				Description: "How a shared-secret key is written (signing has no auto); ignored for PEM and JWK keys."},
			{Name: "kid", Kind: KindString,
				Description: "A key id: added to the header unless header has one, and used to pick the signing key out of a JWKS."},
			{Name: "header", Kind: KindJSON,
				Description: `Extra header members as a JSON object, e.g. {"cty":"JWT"}; alg always comes from alg, and typ defaults to "JWT".`},
			{Name: "payload", Kind: KindJSON, Default: "{}",
				Description: `The claims as a JSON object, e.g. {"sub":"42","name":"Ada"}, signed with their order kept.`},
			{Name: "iat", Kind: KindBool, Default: "false",
				Description: "Add an iat claim of the current time (or now), unless payload has one."},
			{Name: "exp", Kind: KindEnum, Enum: []string{"5m", "15m", "1h", "1d", "7d"},
				Description: "A lifetime to add as an exp claim, counted from the current time (or now), unless payload has one; omit it for a token that never expires."},
			nowField,
		}})
}

// Row is one header parameter or claim.
type Row struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Meaning string `json:"meaning,omitempty"`
	When    string `json:"when,omitempty"`
	Note    string `json:"note,omitempty"`
}

const (
	VerifyUnchecked = "unchecked" // no key: anyone could have written this
	VerifyValid     = "valid"
	VerifyInvalid   = "invalid"
	VerifyRefused   = "refused" // not checked, on principle (alg none, alg confusion, crit)
	VerifyError     = "error"   // the key could not be read
)

type Verification struct {
	State  string `json:"state"`
	Detail string `json:"detail"`
	Key    string `json:"key,omitempty"`
}

// Validity is the time-claim verdict, kept apart from the signature: either can fail alone.
type Validity struct {
	State  string `json:"state"` // valid | expired | not-yet-valid | no-expiry | bad-expiry
	Detail string `json:"detail"`
}

// JWTPart is one dot-separated segment, for the colour-coded token view.
type JWTPart struct{ Label, Value string }

type JWT struct {
	Kind         string          `json:"kind"` // JWS | JWE
	Alg          string          `json:"alg"`
	Header       json.RawMessage `json:"header"`
	Payload      json.RawMessage `json:"payload,omitempty"`
	PayloadText  *Text           `json:"payload_text,omitempty"`
	Signature    string          `json:"signature,omitempty"`
	HeaderRows   []Row           `json:"header_rows"`
	Claims       []Row           `json:"claims,omitempty"`
	Validity     *Validity       `json:"validity,omitempty"`
	Verification Verification    `json:"verification"`
	Warnings     Warnings        `json:"warnings,omitempty"`

	// Display only.
	Parts       []JWTPart `json:"-"`
	HeaderJSON  string    `json:"-"`
	PayloadJSON string    `json:"-"`
	SigBytes    int       `json:"-"`
}

// jwsAlg binds an algorithm to the one key kind allowed to use it: the algorithm-confusion defence.
type jwsAlg struct {
	kind  string
	hash  crypto.Hash
	pss   bool
	curve elliptic.Curve
}

// size is an ES* curve's coordinate size in bytes.
func (a jwsAlg) size() int { return (a.curve.Params().BitSize + 7) / 8 }

var jwsAlgs = map[string]jwsAlg{
	"HS256": {kind: KindSecret, hash: crypto.SHA256},
	"HS384": {kind: KindSecret, hash: crypto.SHA384},
	"HS512": {kind: KindSecret, hash: crypto.SHA512},
	"RS256": {kind: KindRSA, hash: crypto.SHA256},
	"RS384": {kind: KindRSA, hash: crypto.SHA384},
	"RS512": {kind: KindRSA, hash: crypto.SHA512},
	"PS256": {kind: KindRSA, hash: crypto.SHA256, pss: true},
	"PS384": {kind: KindRSA, hash: crypto.SHA384, pss: true},
	"PS512": {kind: KindRSA, hash: crypto.SHA512, pss: true},
	"ES256": {kind: KindEC, hash: crypto.SHA256, curve: elliptic.P256()},
	"ES384": {kind: KindEC, hash: crypto.SHA384, curve: elliptic.P384()},
	// P-521, not "P-512": the coordinates are 66 bytes.
	"ES512": {kind: KindEC, hash: crypto.SHA512, curve: elliptic.P521()},
	// RFC 8037's name, and RFC 9864's fully-specified one.
	"EdDSA":   {kind: KindEd25519},
	"Ed25519": {kind: KindEd25519},
}

// SignAlgs lists the algorithms the sign form offers, in menu order.
var SignAlgs = []string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

var kindNames = map[string]string{
	KindSecret: "a shared secret", KindRSA: "an RSA key", KindEC: "an ECDSA key", KindEd25519: "an Ed25519 key",
}

const DefaultLeeway = 60 * time.Second

func runJWTDecode(in Input) (any, error) {
	now, err := in.now()
	if err != nil {
		return nil, err
	}
	leeway, err := intField(in, jwtLeewayField)
	if err != nil {
		return nil, err
	}
	return DecodeJWT(in.Get("token"), in.Get("key"), in.Get("key_enc"), now, time.Duration(leeway)*time.Second)
}

// cleanToken drops what a copy from a header, log or terminal drags along; a JWT's alphabet has none of it.
func cleanToken(s string) string {
	s = strings.TrimSpace(s)
	for _, p := range []string{"Authorization:", "authorization:"} {
		s = strings.TrimSpace(strings.TrimPrefix(s, p))
	}
	if f := strings.Fields(s); len(f) > 1 && strings.EqualFold(f[0], "bearer") {
		s = strings.TrimSpace(s[len(f[0]):])
	}
	return strings.Join(strings.Fields(strings.Trim(s, "\"'`")), "")
}

// DecodeJWT decodes token and, when key is non-empty, verifies it.
func DecodeJWT(token, key, keyEnc string, now time.Time, leeway time.Duration) (*JWT, error) {
	tok := cleanToken(token)
	if tok == "" {
		return nil, errors.New("no token given")
	}
	parts := strings.Split(tok, ".")
	j := &JWT{}
	if tok != strings.TrimSpace(token) {
		j.Warnings.add(LevelInfo, "Removed a Bearer prefix, quotes or line breaks from around the token before decoding.")
	}
	switch len(parts) {
	case 3:
		j.Kind = "JWS"
		j.Parts = []JWTPart{{"header", parts[0]}, {"payload", parts[1]}, {"signature", parts[2]}}
	case 5:
		j.Kind = "JWE"
		j.Parts = []JWTPart{{"header", parts[0]}, {"encrypted key", parts[1]}, {"iv", parts[2]},
			{"ciphertext", parts[3]}, {"tag", parts[4]}}
	case 2:
		return nil, errors.New("only two parts: a JWT has three (header.payload.signature). Did the copy stop at the second dot?")
	default:
		return nil, fmt.Errorf("%d dot-separated parts: a JWT has three (signed) or five (encrypted)", len(parts))
	}

	hdr, err := segment(parts[0], "header")
	if err != nil {
		return nil, err
	}
	members, err := orderedObject(hdr)
	if err != nil {
		return nil, fmt.Errorf("header is not a JSON object: %w", err)
	}
	j.Header, j.HeaderJSON = hdr, pretty(hdr)
	crit, kid := false, ""
	for _, m := range members {
		j.HeaderRows = append(j.HeaderRows, Row{Name: m.Key, Value: display(m.Raw), Meaning: headerMeanings[m.Key]})
		switch m.Key {
		case "alg":
			if json.Unmarshal(m.Raw, &j.Alg) != nil {
				return nil, errors.New(`header "alg" is not a string`)
			}
		case "crit":
			crit = true
		case "kid":
			_ = json.Unmarshal(m.Raw, &kid)
		case "jku", "x5u":
			j.Warnings.add(LevelWarn, fmt.Sprintf("The header names a URL (%s) to fetch the signing key from. A verifier that follows it lets the token choose its own key; trust only keys you already hold.", m.Key))
		case "jwk", "x5c":
			j.Warnings.add(LevelWarn, fmt.Sprintf("The header embeds a key (%s). Verifying with a key the token brought along proves nothing unless that key is pinned.", m.Key))
		}
	}
	if strings.ContainsAny(kid, "/\\'\";") || strings.Contains(kid, "..") {
		j.Warnings.add(LevelWarn, fmt.Sprintf("The kid %q contains path or quote characters, the shape of a path-traversal or SQL-injection probe against key lookup.", kid))
	}
	if strings.EqualFold(j.Alg, "none") {
		j.Warnings.add(LevelDanger, `alg is "none": the token is unsigned, and anyone can write one. Never accept it.`)
	}

	if j.Kind == "JWE" {
		j.Verification = Verification{State: VerifyUnchecked,
			Detail: "This is an encrypted token (JWE). Only the header is readable; the payload needs the recipient's private key, and decrypting isn't supported here."}
		return j, nil
	}
	payload, err := segment(parts[1], "payload")
	if err != nil {
		return nil, err
	}
	j.decodePayload(payload, now, leeway)

	sig, sigErr := b64url.DecodeString(parts[2])
	j.Signature, j.SigBytes = parts[2], len(sig)
	if sigErr != nil {
		j.Verification = Verification{State: VerifyInvalid, Detail: "The signature segment is not base64url: " + sigErr.Error()}
	} else {
		j.Verification = j.verify([]byte(parts[0]+"."+parts[1]), sig, key, keyEnc, kid, crit)
	}
	return j, nil
}

// segment decodes one base64url part, accepting the padding JOSE forbids but careless encoders add.
func segment(s, name string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("the %s is empty", name)
	}
	b, err := b64url.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		if strings.ContainsAny(s, "+/") {
			return nil, fmt.Errorf("the %s uses '+' or '/', which is standard base64; JWTs use base64url ('-' and '_')", name)
		}
		return nil, fmt.Errorf("the %s is not base64url: %w", name, err)
	}
	return b, nil
}

func pretty(raw []byte) string {
	var b bytes.Buffer
	if json.Indent(&b, raw, "", "  ") != nil {
		return string(raw)
	}
	return b.String()
}

func (j *JWT) decodePayload(payload []byte, now time.Time, leeway time.Duration) {
	members, err := orderedObject(payload)
	if err != nil {
		t := textOf(payload)
		j.PayloadText = &t
		j.Warnings.add(LevelInfo, "The payload isn't a JSON object, so this is a signed blob (JWS) but not a JWT claims set.")
		return
	}
	j.Payload, j.PayloadJSON = payload, pretty(payload)

	times := map[string]time.Time{}
	badExp := false
	for _, m := range members {
		r := Row{Name: m.Key, Value: display(m.Raw), Meaning: claimMeanings[m.Key]}
		switch m.Key {
		case "exp", "nbf", "iat", "auth_time":
			t, ok := numericDate(m.Raw)
			if !ok {
				r.Note = "not a NumericDate (seconds since 1970), so it can't be checked"
				badExp = badExp || m.Key == "exp"
				break
			}
			if t.Year() > 3000 {
				r.Note = "far in the future: this looks like milliseconds, but NumericDate is seconds"
			}
			r.When = stamp(t) + " · " + relative(t, now)
			times[m.Key] = t
		}
		j.Claims = append(j.Claims, r)
	}
	exp, hasExp := times["exp"]
	nbf, hasNbf := times["nbf"]
	iat, hasIat := times["iat"]

	skew := fmt.Sprintf(" (%s of clock skew allowed.)", humanDuration(leeway))
	switch {
	case hasExp && now.After(exp.Add(leeway)):
		j.Validity = &Validity{"expired", "Expired " + relative(exp, now) + "." + skew}
	case hasNbf && now.Add(leeway).Before(nbf):
		j.Validity = &Validity{"not-yet-valid", "Not valid until " + stamp(nbf) + ", " + relative(nbf, now) + "." + skew}
	case badExp:
		j.Validity = &Validity{"bad-expiry", "exp is present but isn't a NumericDate (seconds since 1970), so expiry can't be checked. Verifiers following RFC 7519 reject the token."}
	case !hasExp:
		j.Validity = &Validity{"no-expiry", "No exp claim: this token never expires, so it can't be revoked by waiting."}
	default:
		j.Validity = &Validity{"valid", "Within its validity window; expires " + relative(exp, now) + "." + skew}
	}
	if hasIat && iat.After(now.Add(leeway)) {
		j.Warnings.add(LevelWarn, "iat is in the future: either the issuer's clock is wrong or the claim was forged.")
	}
	if hasExp && hasIat && exp.Sub(iat) > 24*time.Hour {
		j.Warnings.add(LevelInfo, "Lifetime is "+humanDuration(exp.Sub(iat))+". Access tokens usually live minutes, not days.")
	}
}

// verify refuses on principle before trying anything that would let the token choose how it is checked.
func (j *JWT) verify(input, sig []byte, keyInput, keyEnc, kid string, crit bool) Verification {
	refuse := func(detail string) Verification { return Verification{State: VerifyRefused, Detail: detail} }
	spec, known := jwsAlgs[j.Alg]
	switch {
	case strings.EqualFold(j.Alg, "none"):
		return refuse(`alg "none" is never accepted, with or without a key.`)
	case strings.TrimSpace(keyInput) == "":
		return Verification{State: VerifyUnchecked,
			Detail: "Signature NOT checked: no key given. Decoding proves nothing; anyone can write a token that decodes. Paste the secret or public key to verify."}
	case crit:
		return refuse(`The header has "crit": extensions a verifier must understand or reject. This tool implements none, so a conforming verifier rejects the token.`)
	case !known:
		return refuse(fmt.Sprintf("Unsupported alg %q.", j.Alg))
	}

	material := looksLikeKeyMaterial(keyInput)
	if !material && spec.kind != KindSecret {
		return refuse(fmt.Sprintf("The token says %s, which needs %s (PEM or JWK), and what you pasted reads as a shared secret. Refused rather than guessed.", j.Alg, kindNames[spec.kind]))
	}
	read, what := ParseKeys, "key"
	if !material {
		read, what = func(s string) ([]Key, error) { return secretReadings(s, keyEnc) }, "secret"
	}
	keys, err := read(keyInput)
	if err != nil {
		return Verification{State: VerifyError, Detail: "Couldn't read the " + what + ": " + err.Error()}
	}

	var fit []Key
	mismatch := ""
	for _, k := range keys {
		switch {
		case !jwtKeyFits(spec, k):
			mismatch = k.Describe()
		case k.Alg != "" && k.Alg != j.Alg:
			mismatch = fmt.Sprintf("%s, which its JWK restricts to %s", k.Describe(), k.Alg)
		default:
			fit = append(fit, k)
		}
	}
	if len(fit) == 0 {
		detail := fmt.Sprintf("The token says %s, which needs %s; the key is %s. Refused.", j.Alg, algNeeds(spec), mismatch)
		if spec.kind == KindSecret && keys[0].Kind != KindSecret {
			detail += " Using a public key as an HMAC secret is the classic algorithm-confusion attack: anyone holding the public key could forge tokens."
		}
		return refuse(detail)
	}
	if material && kid != "" && len(fit) > 1 {
		if fit = slices.DeleteFunc(fit, func(k Key) bool { return k.KID != kid }); len(fit) == 0 {
			return Verification{State: VerifyInvalid, Detail: fmt.Sprintf("No key in the set has kid %q, the one the token names.", kid)}
		}
	}

	for _, k := range fit {
		if !verifyJWS(spec, k, input, sig) {
			continue
		}
		v := Verification{State: VerifyValid, Detail: "Whoever holds this key signed exactly this header and payload.", Key: k.Describe()}
		if k.Private != nil {
			v.Detail += " (Checked with the public half of the private key you pasted; verifying only ever needs the public key.)"
		}
		// UTF-8 text first is the reading anyone would assume; only another one is news.
		if !material && k.Source != fit[0].Source {
			v.Detail += fmt.Sprintf(" It matched with the secret %s, so that is how this secret is stored.", k.Source)
		}
		if k.Kind == KindSecret && len(k.Secret) < spec.hash.Size() {
			j.Warnings.add(LevelWarn, fmt.Sprintf("The secret is %d bytes; RFC 7518 §3.2 requires at least %d for %s. Short HMAC secrets can be brute-forced offline from one token.",
				len(k.Secret), spec.hash.Size(), j.Alg))
		}
		if pub, ok := k.Public.(*rsa.PublicKey); ok && pub.N.BitLen() < 2048 {
			j.Warnings.add(LevelWarn, fmt.Sprintf("RSA key is %d bits; 2048 is the minimum RFC 7518 allows.", pub.N.BitLen()))
		}
		return v
	}
	detail := "Signature does NOT match. The token was altered, or it wasn't signed with this key."
	switch {
	case material:
	case keyEnc == "" || keyEnc == EncAuto:
		var names []string
		for _, k := range fit {
			names = append(names, strings.TrimPrefix(k.Source, "read as "))
		}
		detail += " Tried the secret as " + joinAnd(names) + "."
	default:
		// The key may be right and only its encoding wrong.
		all, _ := secretReadings(keyInput, EncAuto)
		for _, k := range all {
			if !bytes.Equal(k.Secret, fit[0].Secret) && verifyJWS(spec, k, input, sig) {
				detail = fmt.Sprintf("Signature does NOT match with the secret %s, but it DOES with the secret %s. Set \"Secret is\" to match.", fit[0].Source, k.Source)
				break
			}
		}
	}
	return Verification{State: VerifyInvalid, Detail: detail, Key: fit[0].Describe()}
}

// jwtKeyFits: the key is of the kind the algorithm needs and, for ES*, on its curve.
func jwtKeyFits(spec jwsAlg, k Key) bool {
	ec, _ := k.Public.(*ecdsa.PublicKey)
	return k.Kind == spec.kind && (spec.curve == nil || ec != nil && ec.Curve == spec.curve)
}

func algNeeds(spec jwsAlg) string {
	if spec.curve != nil {
		return "an ECDSA key on " + spec.curve.Params().Name
	}
	return kindNames[spec.kind]
}

// secretReadings is the secret as the one encoding asked for or, under EncAuto, every distinct reading, UTF-8 first.
// A token doesn't record how its secret was written down; three candidate keys leave forging at 3 in 2^256.
func secretReadings(s, enc string) ([]Key, error) {
	if enc != "" && enc != EncAuto {
		b, _, err := decodeInput(s, enc)
		return []Key{{Kind: KindSecret, Secret: b, Source: "read as " + encName(enc)}}, err
	}
	var out []Key
	for _, e := range []string{EncUTF8, EncBase64, EncHex} {
		if b, _, err := decodeInput(s, e); err == nil && !slices.ContainsFunc(out, func(k Key) bool { return bytes.Equal(k.Secret, b) }) {
			out = append(out, Key{Kind: KindSecret, Secret: b, Source: "read as " + encName(e)})
		}
	}
	return out, nil
}

func encName(enc string) string {
	if enc == "" || enc == EncUTF8 {
		return "UTF-8 text"
	}
	return enc
}

func digest(h crypto.Hash, data []byte) []byte {
	w := h.New()
	w.Write(data)
	return w.Sum(nil)
}

func verifyJWS(spec jwsAlg, k Key, input, sig []byte) bool {
	switch spec.kind {
	case KindSecret:
		mac, _ := signJWS(spec, k, input)
		return hmac.Equal(mac, sig)
	case KindRSA:
		pub := k.Public.(*rsa.PublicKey)
		if spec.pss {
			return rsa.VerifyPSS(pub, spec.hash, digest(spec.hash, input), sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
		}
		return rsa.VerifyPKCS1v15(pub, spec.hash, digest(spec.hash, input), sig) == nil
	case KindEC:
		// Raw r‖s, not DER (RFC 7518 §3.4).
		return len(sig) == 2*spec.size() && ecdsa.Verify(k.Public.(*ecdsa.PublicKey), digest(spec.hash, input),
			new(big.Int).SetBytes(sig[:spec.size()]), new(big.Int).SetBytes(sig[spec.size():]))
	}
	return ed25519.Verify(k.Public.(ed25519.PublicKey), input, sig)
}

func signJWS(spec jwsAlg, k Key, input []byte) ([]byte, error) {
	switch spec.kind {
	case KindSecret:
		mac := hmac.New(spec.hash.New, k.Secret)
		mac.Write(input)
		return mac.Sum(nil), nil
	case KindRSA:
		priv := k.Private.(*rsa.PrivateKey)
		if spec.pss {
			return rsa.SignPSS(rand.Reader, priv, spec.hash, digest(spec.hash, input), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		return rsa.SignPKCS1v15(rand.Reader, priv, spec.hash, digest(spec.hash, input))
	case KindEC:
		r, s, err := ecdsa.Sign(rand.Reader, k.Private.(*ecdsa.PrivateKey), digest(spec.hash, input))
		if err != nil {
			return nil, err
		}
		return append(r.FillBytes(make([]byte, spec.size())), s.FillBytes(make([]byte, spec.size()))...), nil
	}
	return ed25519.Sign(k.Private.(ed25519.PrivateKey), input), nil
}

// JWTSigned is the token, and the token decoded and verified back with the same key.
type JWTSigned struct {
	Token   string `json:"token"`
	Decoded *JWT   `json:"decoded"`
}

var expiryPresets = map[string]time.Duration{
	"5m": 5 * time.Minute, "15m": 15 * time.Minute, "1h": time.Hour, "1d": 24 * time.Hour, "7d": 7 * 24 * time.Hour,
}

func runJWTSign(in Input) (any, error) {
	now, err := in.now()
	if err != nil {
		return nil, err
	}
	alg := cmp.Or(strings.TrimSpace(in.Get("alg")), "HS256")
	if strings.EqualFold(alg, "none") {
		return nil, errors.New(`won't sign with alg "none": an unsigned token is accepted by nothing that should be trusted`)
	}
	spec, ok := jwsAlgs[alg]
	if !ok {
		return nil, fmt.Errorf("unsupported alg %q", alg)
	}
	keyInput, keyEnc, kid := in.Get("key"), in.Get("key_enc"), strings.TrimSpace(in.Get("kid"))
	key, err := signingKey(spec, alg, keyInput, keyEnc, kid)
	if err != nil {
		return nil, err
	}
	header, err := buildHeader(alg, in.Get("header"), kid)
	if err != nil {
		return nil, err
	}
	payload, err := buildPayload(in.Get("payload"), now, checked(in.Get("iat")), in.Get("exp"))
	if err != nil {
		return nil, err
	}
	input := b64url.EncodeToString(header) + "." + b64url.EncodeToString(payload)
	sig, err := signJWS(spec, key, []byte(input))
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}
	token := input + "." + b64url.EncodeToString(sig)
	// A token built above always decodes; a private key verifies through its public half.
	decoded, _ := DecodeJWT(token, keyInput, keyEnc, now, DefaultLeeway)
	return &JWTSigned{Token: token, Decoded: decoded}, nil
}

func signingKey(spec jwsAlg, alg, keyInput, keyEnc, kid string) (Key, error) {
	if strings.TrimSpace(keyInput) == "" {
		return Key{}, errors.New("no key given")
	}
	if !looksLikeKeyMaterial(keyInput) {
		if spec.kind != KindSecret {
			return Key{}, fmt.Errorf("%s signs with %s's private half (PEM or JWK); this reads as a shared secret", alg, kindNames[spec.kind])
		}
		secret, _, err := decodeInput(keyInput, keyEnc)
		if err != nil {
			return Key{}, fmt.Errorf("secret: %w", err)
		}
		return Key{Kind: KindSecret, Secret: secret}, nil
	}
	keys, err := ParseKeys(keyInput)
	if err != nil {
		return Key{}, fmt.Errorf("key: %w", err)
	}
	for _, k := range keys {
		if !jwtKeyFits(spec, k) || kid != "" && k.KID != "" && k.KID != kid {
			continue
		}
		if k.Kind != KindSecret && k.Private == nil {
			return Key{}, errors.New("that's a public key; signing needs the private key")
		}
		return k, nil
	}
	return Key{}, fmt.Errorf("%s needs %s, and none was found in the key you pasted", alg, algNeeds(spec))
}

// buildHeader writes alg, typ, then the visitor's members in their order, which a marshalled map would sort.
func buildHeader(alg, extra, kid string) ([]byte, error) {
	members, err := orderedObject([]byte(cmp.Or(strings.TrimSpace(extra), "{}")))
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	a, _ := json.Marshal(alg)
	out := []member{{"alg", a}, {"typ", json.RawMessage(`"JWT"`)}}
	if kid != "" && !slices.ContainsFunc(members, func(m member) bool { return m.Key == "kid" }) {
		k, _ := json.Marshal(kid)
		out = append(out, member{"kid", k})
	}
	for _, m := range members {
		if m.Key == "typ" {
			out[1].Raw = m.Raw
		} else if m.Key != "alg" {
			out = append(out, m)
		}
	}
	var b bytes.Buffer
	for _, m := range out {
		k, _ := json.Marshal(m.Key)
		b.WriteString("," + string(k) + ":")
		_ = json.Compact(&b, m.Raw) // already valid JSON
	}
	return []byte("{" + b.String()[1:] + "}"), nil
}

// buildPayload compacts the claims, keeping their order, and appends iat/exp when asked and absent.
func buildPayload(src string, now time.Time, setIat bool, expPreset string) ([]byte, error) {
	src = cmp.Or(strings.TrimSpace(src), "{}")
	members, err := orderedObject([]byte(src))
	if err != nil {
		return nil, fmt.Errorf("payload must be a JSON object: %w", err)
	}
	var b bytes.Buffer
	if err := json.Compact(&b, []byte(src)); err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	has := func(claim string) bool {
		return slices.ContainsFunc(members, func(m member) bool { return m.Key == claim })
	}
	out := strings.TrimSuffix(b.String(), "}")
	if setIat && !has("iat") {
		out += fmt.Sprintf(`,"iat":%d`, now.Unix())
	}
	if d, ok := expiryPresets[expPreset]; ok && !has("exp") {
		out += fmt.Sprintf(`,"exp":%d`, now.Add(d).Unix())
	} else if expPreset != "" && !ok {
		return nil, fmt.Errorf("unknown expiry preset %q", expPreset)
	}
	return []byte("{" + strings.TrimPrefix(out[1:], ",") + "}"), nil
}
