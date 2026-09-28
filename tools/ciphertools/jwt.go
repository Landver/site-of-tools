package ciphertools

import (
	"bytes"
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
	"strconv"
	"strings"
	"time"
)

// C1 — JWT decode / verify / sign. The page the suite is named after in search
// results, and the one where the category's signature bug lives: a token that
// decodes is not a token that verifies (docs/00-landscape.md finding 2). Every
// result therefore carries a Verification whose "unchecked" state is shown as
// prominently as "invalid".

func init() {
	register(Op{Name: "jwt-decode", Path: "/jwt/decode", Page: "jwt", Fragment: "cipher/jwt-result", Run: runJWTDecode})
	register(Op{Name: "jwt-sign", Path: "/jwt/sign", Page: "jwt", Fragment: "cipher/jwt-signed", Run: runJWTSign})
}

// Warning levels.
const (
	LevelDanger = "danger"
	LevelWarn   = "warn"
	LevelInfo   = "info"
)

// Warning is one thing worth knowing about the input.
type Warning struct {
	Level string `json:"level"`
	Text  string `json:"text"`
}

// Row is one header parameter or claim.
type Row struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Meaning string `json:"meaning,omitempty"`
	When    string `json:"when,omitempty"`
	Note    string `json:"note,omitempty"`
}

// Verification states.
const (
	VerifyUnchecked = "unchecked" // no key: anyone could have written this
	VerifyValid     = "valid"
	VerifyInvalid   = "invalid" // checked, and the signature does not match
	VerifyRefused   = "refused" // not checked, on principle (alg none, alg confusion, crit)
	VerifyError     = "error"   // the key could not be read
)

// Verification is the answer to "did the holder of this key sign it".
type Verification struct {
	State  string `json:"state"`
	Detail string `json:"detail"`
	Key    string `json:"key,omitempty"`
}

// Validity is the time-claim verdict, separate from the signature on purpose:
// an expired token can have a perfect signature and vice versa.
type Validity struct {
	State  string `json:"state"` // valid | expired | not-yet-valid | no-expiry
	Detail string `json:"detail"`
}

// JWTPart is one dot-separated segment, for the colour-coded token view.
type JWTPart struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// JWT is a decoded token.
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
	Warnings     []Warning       `json:"warnings,omitempty"`

	// Display only.
	Parts       []JWTPart `json:"-"`
	HeaderJSON  string    `json:"-"`
	PayloadJSON string    `json:"-"`
	SigBytes    int       `json:"-"`
}

// jwsAlg describes one JWS algorithm and the only key kind allowed to use it.
// The table is the algorithm-confusion defence: the key's kind picks the
// permitted algorithms, and the header's alg must merely agree.
type jwsAlg struct {
	kind  string
	hash  crypto.Hash
	pss   bool
	curve elliptic.Curve
	size  int // ECDSA coordinate size in bytes
}

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
	"ES256": {kind: KindEC, hash: crypto.SHA256, curve: elliptic.P256(), size: 32},
	"ES384": {kind: KindEC, hash: crypto.SHA384, curve: elliptic.P384(), size: 48},
	// P-521, not "P-512": the coordinates are 66 bytes.
	"ES512": {kind: KindEC, hash: crypto.SHA512, curve: elliptic.P521(), size: 66},
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

// DefaultLeeway is the clock skew allowed on exp/nbf.
const DefaultLeeway = 60 * time.Second

func runJWTDecode(in Input) (any, error) {
	now, err := in.now()
	if err != nil {
		return nil, err
	}
	leeway := DefaultLeeway
	if v := strings.TrimSpace(in.Get("leeway")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 86400 {
			return nil, errors.New("leeway: want seconds between 0 and 86400")
		}
		leeway = time.Duration(n) * time.Second
	}
	return DecodeJWT(in.Get("token"), in.Get("key"), in.Get("key_enc"), now, leeway)
}

// cleanToken removes what a copy from a header, a log line or a terminal drags
// along. A JWT's alphabet has no spaces, quotes or "Bearer", so dropping them
// can't change a valid token.
func cleanToken(s string) (string, bool) {
	orig := s
	s = strings.TrimSpace(s)
	for _, p := range []string{"Authorization:", "authorization:"} {
		s = strings.TrimSpace(strings.TrimPrefix(s, p))
	}
	if len(s) > 7 && strings.EqualFold(s[:7], "bearer ") {
		s = s[7:]
	}
	s = strings.Trim(s, "\"'`")
	s = strings.Join(strings.Fields(s), "")
	return s, s != orig
}

// DecodeJWT decodes token and, when key is non-empty, verifies it.
func DecodeJWT(token, key, keyEnc string, now time.Time, leeway time.Duration) (*JWT, error) {
	tok, cleaned := cleanToken(token)
	if tok == "" {
		return nil, errors.New("no token given")
	}
	parts := strings.Split(tok, ".")
	j := &JWT{}
	if cleaned && tok != strings.TrimSpace(token) {
		j.warn(LevelInfo, "Removed a Bearer prefix, quotes or line breaks from around the token before decoding.")
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
	j.Header = hdr
	j.HeaderJSON = pretty(hdr)
	var crit bool
	var kid string
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
		}
	}
	j.headerWarnings(members, kid)

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
	switch {
	case sigErr != nil:
		j.Verification = Verification{State: VerifyInvalid, Detail: "The signature segment is not base64url: " + sigErr.Error()}
	default:
		j.Verification = j.verify([]byte(parts[0]+"."+parts[1]), sig, key, keyEnc, kid, crit)
	}
	return j, nil
}

// segment decodes one base64url part. JOSE forbids padding, but tokens padded
// by a careless encoder are common enough to accept with a note.
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

func (j *JWT) warn(level, text string) { j.Warnings = append(j.Warnings, Warning{level, text}) }

func (j *JWT) headerWarnings(members []member, kid string) {
	for _, m := range members {
		switch m.Key {
		case "jku", "x5u":
			j.warn(LevelWarn, fmt.Sprintf("The header names a URL (%s) to fetch the signing key from. A verifier that follows it lets the token choose its own key; trust only keys you already hold.", m.Key))
		case "jwk", "x5c":
			j.warn(LevelWarn, fmt.Sprintf("The header embeds a key (%s). Verifying with a key the token brought along proves nothing unless that key is pinned.", m.Key))
		}
	}
	if strings.ContainsAny(kid, "/\\'\";") || strings.Contains(kid, "..") {
		j.warn(LevelWarn, fmt.Sprintf("The kid %q contains path or quote characters, the shape of a path-traversal or SQL-injection probe against key lookup.", kid))
	}
	if strings.EqualFold(j.Alg, "none") {
		j.warn(LevelDanger, `alg is "none": the token is unsigned, and anyone can write one. Never accept it.`)
	}
}

func (j *JWT) decodePayload(payload []byte, now time.Time, leeway time.Duration) {
	members, err := orderedObject(payload)
	if err != nil {
		t := textOf(payload)
		j.PayloadText = &t
		j.warn(LevelInfo, "The payload isn't a JSON object, so this is a signed blob (JWS) but not a JWT claims set.")
		return
	}
	j.Payload = payload
	j.PayloadJSON = pretty(payload)

	var exp, nbf, iat *time.Time
	for _, m := range members {
		r := Row{Name: m.Key, Value: display(m.Raw), Meaning: claimMeanings[m.Key]}
		switch m.Key {
		case "exp", "nbf", "iat", "auth_time":
			t, ok := numericDate(m.Raw)
			if !ok {
				r.Note = "not a NumericDate (seconds since 1970), so it can't be checked"
				break
			}
			if t.Year() > 3000 {
				r.Note = "far in the future: this looks like milliseconds, but NumericDate is seconds"
			}
			r.When = t.Format("2006-01-02 15:04:05 UTC") + " · " + relative(t, now)
			switch m.Key {
			case "exp":
				exp = &t
			case "nbf":
				nbf = &t
			case "iat":
				iat = &t
			}
		}
		j.Claims = append(j.Claims, r)
	}

	v := &Validity{State: "valid"}
	switch {
	case exp != nil && now.After(exp.Add(leeway)):
		v.State, v.Detail = "expired", "Expired "+relative(*exp, now)+"."
	case nbf != nil && now.Add(leeway).Before(*nbf):
		v.State, v.Detail = "not-yet-valid", "Not valid until "+nbf.Format("2006-01-02 15:04:05 UTC")+", "+relative(*nbf, now)+"."
	case exp == nil:
		v.State, v.Detail = "no-expiry", "No exp claim: this token never expires."
	default:
		v.Detail = "Within its validity window; expires " + relative(*exp, now) + "."
	}
	if v.State == "valid" || v.State == "expired" || v.State == "not-yet-valid" {
		v.Detail += fmt.Sprintf(" (%s of clock skew allowed.)", humanDuration(leeway))
	}
	j.Validity = v
	if exp == nil {
		j.warn(LevelWarn, "No exp claim. A token that never expires can't be revoked by waiting.")
	}
	if iat != nil && iat.After(now.Add(leeway)) {
		j.warn(LevelWarn, "iat is in the future: either the issuer's clock is wrong or the claim was forged.")
	}
	if exp != nil && iat != nil && exp.Sub(*iat) > 24*time.Hour {
		j.warn(LevelInfo, "Lifetime is "+humanDuration(exp.Sub(*iat))+". Access tokens usually live minutes, not days.")
	}
}

// verify checks the signature, refusing on principle before trying anything
// that would let the token choose how it is checked.
func (j *JWT) verify(input, sig []byte, keyInput, keyEnc, kid string, crit bool) Verification {
	if strings.EqualFold(j.Alg, "none") {
		return Verification{State: VerifyRefused, Detail: `alg "none" is never accepted, with or without a key.`}
	}
	if strings.TrimSpace(keyInput) == "" {
		return Verification{State: VerifyUnchecked,
			Detail: "Signature NOT checked: no key given. Decoding proves nothing; anyone can write a token that decodes. Paste the secret or public key to verify."}
	}
	if crit {
		return Verification{State: VerifyRefused,
			Detail: `The header has "crit": extensions a verifier must understand or reject. This tool implements none, so a conforming verifier rejects the token.`}
	}
	spec, ok := jwsAlgs[j.Alg]
	if !ok {
		return Verification{State: VerifyRefused, Detail: fmt.Sprintf("Unsupported alg %q.", j.Alg)}
	}

	var keys []Key
	if looksLikeKeyMaterial(keyInput) {
		ks, err := ParseKeys(keyInput)
		if err != nil {
			return Verification{State: VerifyError, Detail: "Couldn't read the key: " + err.Error()}
		}
		keys = ks
	} else {
		if spec.kind != KindSecret {
			return Verification{State: VerifyRefused, Detail: fmt.Sprintf(
				"The token says %s, which needs %s (PEM or JWK), and what you pasted reads as a shared secret. Refused rather than guessed.", j.Alg, kindNames[spec.kind])}
		}
		secret, err := DecodeBytes(keyInput, keyEnc)
		if err != nil {
			return Verification{State: VerifyError, Detail: "Couldn't read the secret: " + err.Error()}
		}
		keys = []Key{{Kind: KindSecret, Secret: secret, Source: "read as " + encName(keyEnc)}}
	}

	var fit []Key
	var mismatch string
	for _, k := range keys {
		if k.Kind != spec.kind {
			mismatch = k.Describe()
			continue
		}
		if spec.curve != nil && k.Public.(*ecdsa.PublicKey).Curve != spec.curve {
			mismatch = k.Describe()
			continue
		}
		if k.Alg != "" && k.Alg != j.Alg {
			mismatch = fmt.Sprintf("%s, which its JWK restricts to %s", k.Describe(), k.Alg)
			continue
		}
		fit = append(fit, k)
	}
	if len(fit) == 0 {
		detail := fmt.Sprintf("The token says %s, which needs %s; the key is %s. Refused.", j.Alg, algNeeds(j.Alg, spec), mismatch)
		if spec.kind == KindSecret && keys[0].Kind != KindSecret {
			detail += " Using a public key as an HMAC secret is the classic algorithm-confusion attack: anyone holding the public key could forge tokens."
		}
		return Verification{State: VerifyRefused, Detail: detail}
	}
	if kid != "" && len(fit) > 1 {
		var byKid []Key
		for _, k := range fit {
			if k.KID == kid {
				byKid = append(byKid, k)
			}
		}
		if len(byKid) == 0 {
			return Verification{State: VerifyInvalid, Detail: fmt.Sprintf("No key in the set has kid %q, the one the token names.", kid)}
		}
		fit = byKid
	}

	for _, k := range fit {
		if verifyJWS(spec, k, input, sig) == nil {
			v := Verification{State: VerifyValid, Detail: "Signature verified.", Key: k.Describe()}
			if k.Private != nil && k.Kind != KindSecret {
				v.Detail += " (Checked with the public half of the private key you pasted; verifying only ever needs the public key.)"
			}
			j.keyWarnings(spec, k)
			return v
		}
	}
	detail := "Signature does NOT match. The token was altered, or it wasn't signed with this key."
	if spec.kind == KindSecret {
		detail += " If the secret is stored base64-encoded, set its encoding to base64 — the usual cause of this with a key that is otherwise right."
	}
	return Verification{State: VerifyInvalid, Detail: detail, Key: fit[0].Describe()}
}

func algNeeds(alg string, spec jwsAlg) string {
	if spec.curve != nil {
		return "an ECDSA key on " + spec.curve.Params().Name
	}
	return kindNames[spec.kind]
}

func encName(enc string) string {
	switch enc {
	case "", EncUTF8:
		return "UTF-8 text"
	}
	return enc
}

func (j *JWT) keyWarnings(spec jwsAlg, k Key) {
	switch k.Kind {
	case KindSecret:
		if len(k.Secret) < spec.hash.Size() {
			j.warn(LevelWarn, fmt.Sprintf("The secret is %d bytes; RFC 7518 §3.2 requires at least %d for %s. Short HMAC secrets can be brute-forced offline from one token.",
				len(k.Secret), spec.hash.Size(), j.Alg))
		}
	case KindRSA:
		if n := k.Public.(*rsa.PublicKey).N.BitLen(); n < 2048 {
			j.warn(LevelWarn, fmt.Sprintf("RSA key is %d bits; 2048 is the minimum RFC 7518 allows.", n))
		}
	}
}

func digest(h crypto.Hash, data []byte) []byte {
	w := h.New()
	w.Write(data)
	return w.Sum(nil)
}

var errBadSig = errors.New("signature mismatch")

func verifyJWS(spec jwsAlg, k Key, input, sig []byte) error {
	switch spec.kind {
	case KindSecret:
		mac := hmac.New(spec.hash.New, k.Secret)
		mac.Write(input)
		if !hmac.Equal(mac.Sum(nil), sig) {
			return errBadSig
		}
		return nil
	case KindRSA:
		pub := k.Public.(*rsa.PublicKey)
		if spec.pss {
			return rsa.VerifyPSS(pub, spec.hash, digest(spec.hash, input), sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		return rsa.VerifyPKCS1v15(pub, spec.hash, digest(spec.hash, input), sig)
	case KindEC:
		// Raw r‖s, not DER (RFC 7518 §3.4).
		if len(sig) != 2*spec.size {
			return fmt.Errorf("an ECDSA signature for this curve is %d bytes, got %d", 2*spec.size, len(sig))
		}
		r := new(big.Int).SetBytes(sig[:spec.size])
		s := new(big.Int).SetBytes(sig[spec.size:])
		if !ecdsa.Verify(k.Public.(*ecdsa.PublicKey), digest(spec.hash, input), r, s) {
			return errBadSig
		}
		return nil
	case KindEd25519:
		if !ed25519.Verify(k.Public.(ed25519.PublicKey), input, sig) {
			return errBadSig
		}
		return nil
	}
	return errors.New("unsupported key kind")
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
		out := make([]byte, 2*spec.size)
		r.FillBytes(out[:spec.size])
		s.FillBytes(out[spec.size:])
		return out, nil
	case KindEd25519:
		return ed25519.Sign(k.Private.(ed25519.PrivateKey), input), nil
	}
	return nil, errors.New("unsupported key kind")
}

// JWTSigned is the sign op's result: the token, and the token decoded and
// verified back with the same key — proof the output is what was asked for.
type JWTSigned struct {
	Token   string `json:"token"`
	Decoded *JWT   `json:"decoded"`
}

// expiryPresets are the sign form's quick lifetimes.
var expiryPresets = map[string]time.Duration{
	"5m": 5 * time.Minute, "15m": 15 * time.Minute, "1h": time.Hour, "1d": 24 * time.Hour, "7d": 7 * 24 * time.Hour,
}

func runJWTSign(in Input) (any, error) {
	now, err := in.now()
	if err != nil {
		return nil, err
	}
	alg := strings.TrimSpace(in.Get("alg"))
	if alg == "" {
		alg = "HS256"
	}
	if strings.EqualFold(alg, "none") {
		return nil, errors.New(`won't sign with alg "none": an unsigned token is accepted by nothing that should be trusted`)
	}
	spec, ok := jwsAlgs[alg]
	if !ok {
		return nil, fmt.Errorf("unsupported alg %q", alg)
	}
	keyInput, keyEnc := in.Get("key"), in.Get("key_enc")
	kidField := strings.TrimSpace(in.Get("kid"))

	key, err := signingKey(spec, alg, keyInput, keyEnc, kidField)
	if err != nil {
		return nil, err
	}

	header, err := buildHeader(alg, in.Get("header"), kidField)
	if err != nil {
		return nil, err
	}
	payload, err := buildPayload(in.Get("payload"), now, in.Get("iat") != "", in.Get("exp"))
	if err != nil {
		return nil, err
	}
	input := b64url.EncodeToString(header) + "." + b64url.EncodeToString(payload)
	sig, err := signJWS(spec, key, []byte(input))
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}
	token := input + "." + b64url.EncodeToString(sig)

	// Verify with the key the visitor gave. For an asymmetric key that is the
	// private key, and verify() uses its public half.
	decoded, err := DecodeJWT(token, keyInput, keyEnc, now, DefaultLeeway)
	if err != nil {
		return nil, err
	}
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
		secret, err := DecodeBytes(keyInput, keyEnc)
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
		if k.Kind != spec.kind || kid != "" && k.KID != "" && k.KID != kid {
			continue
		}
		if spec.curve != nil && k.Public.(*ecdsa.PublicKey).Curve != spec.curve {
			continue
		}
		if k.Kind != KindSecret && k.Private == nil {
			return Key{}, errors.New("that's a public key; signing needs the private key")
		}
		return k, nil
	}
	return Key{}, fmt.Errorf("%s needs %s, and none was found in the key you pasted", alg, algNeeds(alg, spec))
}

// buildHeader writes alg first and typ second, then the visitor's extra
// members in their own order. Built by hand rather than marshalled from a map,
// which would sort the keys and turn "the header I typed" into something else.
func buildHeader(alg, extra, kid string) ([]byte, error) {
	var members []member
	if strings.TrimSpace(extra) != "" {
		m, err := orderedObject([]byte(extra))
		if err != nil {
			return nil, fmt.Errorf("header: %w", err)
		}
		members = m
	}
	var b bytes.Buffer
	a, _ := json.Marshal(alg)
	b.WriteString(`{"alg":` + string(a))
	typ := json.RawMessage(`"JWT"`)
	hasKid := false
	for _, m := range members {
		if m.Key == "typ" {
			typ = m.Raw
		}
		hasKid = hasKid || m.Key == "kid"
	}
	b.WriteString(`,"typ":`)
	if err := json.Compact(&b, typ); err != nil {
		return nil, fmt.Errorf("header typ: %w", err)
	}
	if kid != "" && !hasKid {
		k, _ := json.Marshal(kid)
		b.WriteString(`,"kid":` + string(k))
	}
	for _, m := range members {
		if m.Key == "alg" || m.Key == "typ" {
			continue
		}
		k, _ := json.Marshal(m.Key)
		b.WriteString("," + string(k) + ":")
		if err := json.Compact(&b, m.Raw); err != nil {
			return nil, fmt.Errorf("header %s: %w", m.Key, err)
		}
	}
	b.WriteString("}")
	return b.Bytes(), nil
}

// buildPayload compacts the visitor's claims, keeping their order, and appends
// iat/exp when asked and not already present.
func buildPayload(src string, now time.Time, setIat bool, expPreset string) ([]byte, error) {
	if strings.TrimSpace(src) == "" {
		src = "{}"
	}
	members, err := orderedObject([]byte(src))
	if err != nil {
		return nil, fmt.Errorf("payload must be a JSON object: %w", err)
	}
	var b bytes.Buffer
	if err := json.Compact(&b, []byte(strings.TrimSpace(src))); err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	has := map[string]bool{}
	for _, m := range members {
		has[m.Key] = true
	}
	var add []string
	if setIat && !has["iat"] {
		add = append(add, fmt.Sprintf(`"iat":%d`, now.Unix()))
	}
	if d, ok := expiryPresets[expPreset]; ok && !has["exp"] {
		add = append(add, fmt.Sprintf(`"exp":%d`, now.Add(d).Unix()))
	} else if expPreset != "" && !ok {
		return nil, fmt.Errorf("unknown expiry preset %q", expPreset)
	}
	if len(add) == 0 {
		return b.Bytes(), nil
	}
	out := bytes.TrimSuffix(b.Bytes(), []byte("}"))
	sep := ","
	if len(members) == 0 {
		sep = ""
	}
	return append(append(out, sep+strings.Join(add, ",")...), '}'), nil
}
