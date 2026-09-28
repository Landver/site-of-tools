package ciphertools

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// C11 — "what is this string?". Every recogniser below looks at the input and
// adds what it could be, each with a score; the answer is the list, ranked.
// Never one verdict: 32 hex digits is MD5, NTLM, MD4 or LM, and saying "MD5"
// would be a guess dressed as a fact (docs/03-correctness-traps.md, Identify).
//
// Each candidate names the page that opens it. Live on every keystroke, so
// every recogniser is a shape check plus at most one parse; nothing here is
// expensive, and nothing trusts the input to be well formed.

func init() {
	register(Op{Name: "identify", Path: "/identify", Page: "identify", Fragment: "cipher/identify-result", Run: runIdentify})
}

// Confidence levels, from the score bands in level.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// maxIdentify bounds the input. Anything real (a certificate chain, a JWKS)
// is far smaller, and the page re-runs on every keystroke.
const maxIdentify = 1 << 20

// Candidate is one thing the input could be.
type Candidate struct {
	Name       string `json:"name"`
	Confidence string `json:"confidence"`
	Why        string `json:"why"`
	// Page is the path of the page that opens it here, when there is one.
	Page     string `json:"page,omitempty"`
	PageName string `json:"page_name,omitempty"`
	// Hashcat is the hashcat -m mode, only where it is certain.
	Hashcat string `json:"hashcat,omitempty"`
	// Preview is the start of the decoded bytes, as text or as hex.
	Preview    string `json:"preview,omitempty"`
	PreviewHex bool   `json:"preview_is_hex,omitempty"`

	score int
}

// IdentifyResult is the identify op's answer.
type IdentifyResult struct {
	Bytes      int         `json:"bytes"`
	Lines      int         `json:"lines"`
	Candidates []Candidate `json:"candidates"`
}

var pageNames = map[string]string{
	"/": "JWT", "/hash": "Hash", "/hmac": "HMAC", "/password": "Passwords", "/encrypt": "Encrypt",
	"/keys": "Keys", "/cert": "Certs", "/totp": "TOTP", "/random": "Random", "/encode": "Encode",
}

func runIdentify(in Input) (any, error) { return Identify(in.Get("text")) }

// Identify ranks what s could be, most likely first.
func Identify(s string) (*IdentifyResult, error) {
	if len(s) > maxIdentify {
		return nil, fmt.Errorf("%s is too much to identify; this page reads up to 1 MiB", bytesText(len(s)))
	}
	t := strings.TrimSpace(s)
	if t == "" {
		return nil, errors.New("nothing to identify: paste a token, key, certificate, hash or encoded value")
	}
	x := &idents{}
	for _, rec := range []func(string){
		x.pemBlocks, x.otpauth, x.jose, x.authHeader, x.ssh, x.jsonValue, x.passwordHash, x.uuid,
		x.webhookSignature, x.colonHex, x.hexDigest, x.digits, x.hexBytes, x.base64, x.base32, x.text,
	} {
		rec(t)
	}
	sort.SliceStable(x.c, func(i, j int) bool { return x.c[i].score > x.c[j].score })
	for i := range x.c {
		x.c[i].Confidence = level(x.c[i].score)
		x.c[i].PageName = pageNames[x.c[i].Page]
	}
	return &IdentifyResult{Bytes: len(t), Lines: strings.Count(t, "\n") + 1, Candidates: x.c}, nil
}

// level: 70 and up is a parse that succeeded on an unambiguous shape; 40 to
// 69 is a plausible reading among others; below 40 is possible, no more.
func level(score int) string {
	switch {
	case score >= 70:
		return ConfidenceHigh
	case score >= 40:
		return ConfidenceMedium
	}
	return ConfidenceLow
}

type idents struct{ c []Candidate }

func (x *idents) add(score int, c Candidate) {
	c.score = score
	x.c = append(x.c, c)
}

func (x *idents) any(min int) bool {
	for _, c := range x.c {
		if c.score >= min {
			return true
		}
	}
	return false
}

// singleToken: no spaces or line breaks inside.
func singleToken(t string) bool { return !strings.ContainsAny(t, " \t\r\n") }

// ---- PEM ----

var pemKinds = map[string]struct{ name, page string }{
	"CERTIFICATE":             {"X.509 certificate", "/cert"},
	"TRUSTED CERTIFICATE":     {"X.509 certificate (OpenSSL trusted form)", "/cert"},
	"CERTIFICATE REQUEST":     {"certificate signing request (CSR)", "/cert"},
	"NEW CERTIFICATE REQUEST": {"certificate signing request (CSR)", "/cert"},
	"X509 CRL":                {"certificate revocation list", ""},
	"PRIVATE KEY":             {"private key (PKCS#8)", "/keys"},
	"ENCRYPTED PRIVATE KEY":   {"passphrase-encrypted private key (PKCS#8)", "/keys"},
	"RSA PRIVATE KEY":         {"RSA private key (PKCS#1)", "/keys"},
	"EC PRIVATE KEY":          {"EC private key (SEC 1)", "/keys"},
	"PUBLIC KEY":              {"public key (SPKI)", "/keys"},
	"RSA PUBLIC KEY":          {"RSA public key (PKCS#1)", "/keys"},
	"OPENSSH PRIVATE KEY":     {"OpenSSH private key", "/keys"},
	"EC PARAMETERS":           {"EC parameters (names a curve; not a key)", "/keys"},
	"DH PARAMETERS":           {"Diffie-Hellman parameters", ""},
}

func (x *idents) pemBlocks(t string) {
	if !strings.Contains(t, "-----BEGIN ") {
		return
	}
	type seen struct {
		n, parsed int
		encrypted bool
		preview   string
	}
	var order []string
	kinds := map[string]*seen{}
	rest := []byte(t)
	for range maxPEMBlocks {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		k := kinds[b.Type]
		if k == nil {
			k = &seen{}
			kinds[b.Type] = k
			order = append(order, b.Type)
		}
		k.n++
		if strings.Contains(b.Headers["Proc-Type"], "ENCRYPTED") {
			k.encrypted = true
		}
		if ok, preview := pemParses(b); ok {
			k.parsed++
			if k.preview == "" {
				k.preview = preview
			}
		}
	}
	if len(order) == 0 {
		typ := t[strings.Index(t, "-----BEGIN ")+len("-----BEGIN "):]
		if i := strings.Index(typ, "-----"); i >= 0 && i < 64 {
			typ = typ[:i]
		} else {
			typ = "?"
		}
		x.add(60, Candidate{Name: "PEM block that doesn't decode (" + typ + ")", Page: pemPage(typ),
			Why: "There is a -----BEGIN " + typ + "----- line but no complete block: the END line, or part of the base64 between them, is missing or damaged."})
		return
	}
	for _, typ := range order {
		k := kinds[typ]
		name := pemName(typ)
		why := fmt.Sprintf("%d PEM block%s of type %s", k.n, plural(k.n), typ)
		score := 95
		switch {
		case typ == "CERTIFICATE" && k.n > 1:
			name = fmt.Sprintf("X.509 certificate chain (%d certificates)", k.n)
		case k.n > 1:
			name = fmt.Sprintf("%s (%d)", name, k.n)
		}
		switch {
		case k.encrypted || typ == "ENCRYPTED PRIVATE KEY":
			why += ", passphrase-encrypted: decrypt it locally first (openssl pkey -in key.pem -out plain.pem)"
		case k.parsed == 0 && pemChecked[typ]:
			why += ", but the DER inside doesn't parse as one"
			score = 60
		case k.parsed < k.n && pemChecked[typ]:
			why += fmt.Sprintf(", of which %d parse", k.parsed)
		}
		x.add(score, Candidate{Name: name, Why: why + ".", Page: pemPage(typ), Preview: k.preview})
	}
}

func pemName(typ string) string {
	if k, ok := pemKinds[typ]; ok {
		return k.name
	}
	if strings.HasPrefix(typ, "PGP ") {
		return "OpenPGP armored data (" + typ + ")"
	}
	return "PEM block (" + typ + ")"
}

func pemPage(typ string) string { return pemKinds[typ].page }

// pemChecked are the types pemParses actually parses.
var pemChecked = map[string]bool{
	"CERTIFICATE": true, "CERTIFICATE REQUEST": true, "NEW CERTIFICATE REQUEST": true, "PUBLIC KEY": true,
	"PRIVATE KEY": true, "RSA PRIVATE KEY": true, "EC PRIVATE KEY": true, "RSA PUBLIC KEY": true,
}

// pemParses confirms a block is what its type says, and names a certificate
// by its first SAN or CN.
func pemParses(b *pem.Block) (bool, string) {
	var err error
	switch b.Type {
	case "CERTIFICATE":
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return false, ""
		}
		return true, title(sansOf(c.DNSNames, c.IPAddresses, c.EmailAddresses, c.URIs), c.Subject.CommonName, c.Subject.String())
	case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
		c, err := x509.ParseCertificateRequest(b.Bytes)
		if err != nil {
			return false, ""
		}
		return true, title(sansOf(c.DNSNames, c.IPAddresses, c.EmailAddresses, c.URIs), c.Subject.CommonName, c.Subject.String())
	case "PUBLIC KEY":
		_, err = x509.ParsePKIXPublicKey(b.Bytes)
	case "PRIVATE KEY":
		_, err = x509.ParsePKCS8PrivateKey(b.Bytes)
	case "RSA PRIVATE KEY":
		_, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	case "EC PRIVATE KEY":
		_, err = x509.ParseECPrivateKey(b.Bytes)
	case "RSA PUBLIC KEY":
		_, err = x509.ParsePKCS1PublicKey(b.Bytes)
	default:
		return false, ""
	}
	return err == nil, ""
}

// ---- otpauth:// ----

func (x *idents) otpauth(t string) {
	switch {
	case hasPrefixFold(t, "otpauth-migration://"):
		x.add(80, Candidate{Name: "Google Authenticator export (otpauth-migration://)",
			Why: "A batch of accounts packed in a protobuf. The TOTP page reads one otpauth:// URI at a time, so export or scan the accounts one by one."})
	case hasPrefixFold(t, "otpauth://"):
		s, _, err := ParseOTPURI(t)
		if err != nil {
			x.add(60, Candidate{Name: "otpauth:// URI that doesn't parse", Why: err.Error() + ".", Page: "/totp"})
			return
		}
		why := fmt.Sprintf("%s, %d digits", s.Algorithm, s.Digits)
		if s.Type == OTPTypeTOTP {
			why += fmt.Sprintf(", %d-second period", s.Period)
		} else {
			why += fmt.Sprintf(", counter %d", s.Counter)
		}
		if s.Issuer != "" {
			why += ", issuer " + strconv.Quote(s.Issuer)
		}
		if s.Account != "" {
			why += ", account " + strconv.Quote(s.Account)
		}
		x.add(95, Candidate{Name: "otpauth:// URI for an authenticator app (" + strings.ToUpper(s.Type) + ")", Why: why + ".", Page: "/totp"})
	}
}

// ---- JWT / JWE ----

// joseHeader splits a compact JWS or JWE and decodes its header, or reports
// that it isn't one.
func joseHeader(t string) (parts []string, hdr map[string]any, ok bool) {
	tok, _ := cleanToken(t)
	parts = strings.Split(tok, ".")
	if len(parts) != 3 && len(parts) != 5 {
		return nil, nil, false
	}
	for _, p := range parts {
		if !isBase64URLChars(p) {
			return nil, nil, false
		}
	}
	h, err := segment(parts[0], "header")
	if err != nil || json.Unmarshal(h, &hdr) != nil || hdr == nil {
		return nil, nil, false
	}
	return parts, hdr, true
}

func isBase64URLChars(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '=') {
			return false
		}
	}
	return true
}

func (x *idents) jose(t string) {
	if len(t) > 64<<10 && !singleToken(t) {
		return
	}
	parts, hdr, ok := joseHeader(t)
	if !ok {
		return
	}
	alg, _ := hdr["alg"].(string)
	enc, _ := hdr["enc"].(string)
	switch {
	case len(parts) == 5 && alg != "" && enc != "":
		x.add(95, Candidate{Name: "JWE (encrypted JWT)", Page: "/",
			Why: fmt.Sprintf("Five base64url parts, and the header decodes to JSON with alg %s and enc %s. Only the header is readable without the recipient's key.", alg, enc)})
	case len(parts) == 3 && alg != "":
		why := fmt.Sprintf("Three base64url parts, and the header decodes to JSON with alg %s", alg)
		if typ, _ := hdr["typ"].(string); typ != "" {
			why += " and typ " + typ
		}
		if strings.EqualFold(alg, "none") {
			why += ". alg none means it is unsigned: anyone could have written it"
		}
		x.add(95, Candidate{Name: "JWT (signed, JWS)", Why: why + ".", Page: "/"})
	default:
		x.add(55, Candidate{Name: "JOSE-shaped value", Page: "/",
			Why: fmt.Sprintf("%d base64url parts with a JSON header, but the header lacks %s.", len(parts), map[bool]string{true: "alg or enc", false: "alg"}[len(parts) == 5])})
	}
}

// ---- Authorization headers ----

func (x *idents) authHeader(t string) {
	v := t
	if hasPrefixFold(v, "authorization:") {
		v = strings.TrimSpace(v[len("authorization:"):])
	}
	switch {
	case hasPrefixFold(v, "basic ") || hasPrefixFold(v, "basic\t"):
		a, err := DecodeBasic(t)
		if err != nil {
			x.add(55, Candidate{Name: "HTTP Basic auth header that doesn't decode", Why: err.Error() + ".", Page: "/encode"})
			return
		}
		user := "the user name is " + strconv.Quote(a.User.Value)
		if !a.User.IsText {
			user = "the user name isn't printable text"
		}
		x.add(95, Candidate{Name: "HTTP Basic auth credentials", Page: "/encode",
			Why: "Basic, then the base64 of user:password; " + user + ". It is an encoding, not encryption: the password is in there too."})
	case hasPrefixFold(v, "bearer "):
		if _, _, ok := joseHeader(v); ok {
			return // the JWT reading covers it
		}
		x.add(50, Candidate{Name: "Bearer token (opaque)",
			Why: "An Authorization: Bearer value that isn't a JWT. Its format is private to whoever issued it."})
	}
}

// ---- OpenSSH ----

func (x *idents) ssh(t string) {
	switch {
	case strings.HasPrefix(t, "SHA256:") && len(t) == 50:
		if b, err := b64RawStd(t[7:]); err == nil && len(b) == 32 {
			x.add(90, Candidate{Name: "OpenSSH key fingerprint (SHA-256)", Page: "/keys",
				Why: "SHA256: and 43 characters of unpadded base64, 32 bytes: what ssh-keygen -l prints."})
		}
		return
	case strings.HasPrefix(t, "MD5:"):
		if n, ok := colonBytes(t[4:]); ok && n == 16 {
			x.add(85, Candidate{Name: "OpenSSH key fingerprint (MD5, legacy)", Page: "/keys",
				Why: "MD5: and 16 colon-separated bytes: what ssh-keygen -l -E md5 prints."})
		}
		return
	}
	if !looksLikeOpenSSH(t) {
		return
	}
	var lines []string
	for _, line := range strings.Split(t, "\n") {
		if s := strings.TrimSpace(line); s != "" && !strings.HasPrefix(s, "#") {
			lines = append(lines, s)
		}
	}
	k, err := keyFromOpenSSH(lines[0])
	if err != nil {
		x.add(60, Candidate{Name: "OpenSSH public key line that doesn't parse", Why: err.Error() + ".", Page: "/keys"})
		return
	}
	why := "authorized_keys format: the key type, the key as base64, then a comment"
	if len(lines) > 1 {
		why += fmt.Sprintf("; %d lines", len(lines))
	}
	name := "OpenSSH public key (" + keyName(k.Public) + ")"
	if strings.HasPrefix(k.Source, "OpenSSH certificate") {
		name = "OpenSSH certificate (" + keyName(k.Public) + ")"
	}
	x.add(95, Candidate{Name: name, Why: why + ".", Page: "/keys", Preview: k.Comment})
}

func b64RawStd(s string) ([]byte, error) {
	b, variant, err := decodeBase64Any(s)
	if err != nil || variant != VariantStdRaw {
		return nil, errors.New("not unpadded base64")
	}
	return b, nil
}

// colonBytes: "ab:cd:ef" is 3 bytes; anything else is not ok.
func colonBytes(s string) (int, bool) {
	parts := strings.Split(s, ":")
	for _, p := range parts {
		if len(p) != 2 || !allHex(p) {
			return 0, false
		}
	}
	return len(parts), true
}

// ---- JSON: JWK, JWKS ----

func (x *idents) jsonValue(t string) {
	if !strings.HasPrefix(t, "{") && !strings.HasPrefix(t, "[") {
		return
	}
	var v any
	if err := json.Unmarshal([]byte(t), &v); err != nil {
		why := err.Error()
		var se *json.SyntaxError
		if errors.As(err, &se) {
			why = fmt.Sprintf("%v, at offset %d", se, se.Offset)
		}
		// Wrapped in matching brackets, it was meant as JSON: above the
		// plain-text reading, which is all that is left otherwise.
		score := 25
		if open, end := t[0], t[len(t)-1]; open == '{' && end == '}' || open == '[' && end == ']' {
			score = 45
		}
		x.add(score, Candidate{Name: "JSON-like, but not valid JSON", Why: why + "."})
		return
	}
	obj, _ := v.(map[string]any)
	if kty, ok := obj["kty"].(string); ok {
		part := "public"
		if _, priv := obj["d"]; priv {
			part = "private"
		}
		x.add(90, Candidate{Name: "JWK (" + kty + " " + part + " key)", Page: "/keys",
			Why: fmt.Sprintf("A JSON object with kty %s%s.", kty, map[bool]string{true: " and the private member d", false: ""}[part == "private"])})
		return
	}
	if keys, ok := obj["keys"].([]any); ok {
		x.add(90, Candidate{Name: fmt.Sprintf("JWKS (%d key%s)", len(keys), plural(len(keys))), Page: "/keys",
			Why: "A JSON object with a keys array: a JSON Web Key Set, as served at /.well-known/jwks.json."})
		return
	}
	x.add(50, Candidate{Name: "JSON", Why: "Valid JSON, and not a JWK or a JWKS."})
}

// ---- password hashes ----

// passwordHashcat are the modes that take these strings as they are.
var passwordHashcat = map[string]string{
	AlgoBcrypt: "3200", "md5crypt": "500", "apr1": "1600", "sha256crypt": "7400", "sha512crypt": "1800", "phpass": "400",
}

func (x *idents) passwordHash(t string) {
	if !singleToken(t) || !strings.HasPrefix(t, "$") && !strings.HasPrefix(t, "pbkdf2_sha256$") {
		return
	}
	h, err := ParsePasswordHash(t)
	if err == nil {
		why := h.Format
		if h.Variant != "" {
			why += " " + h.Variant
		}
		var ps []string
		for _, p := range h.Params {
			switch p.Name {
			case "salt", "variant", "params":
			default:
				ps = append(ps, p.Name+"="+p.Value)
			}
		}
		if len(ps) > 0 {
			why += ": " + strings.Join(ps, ", ")
		}
		mode := passwordHashcat[h.Algorithm]
		if h.Format == "Django" {
			mode = "10000"
		}
		x.add(95, Candidate{Name: h.Name + " password hash", Why: why + ".", Page: "/password", Hashcat: mode})
		return
	}
	id := ""
	if f := strings.Split(t, "$"); len(f) > 2 {
		id = f[1]
	}
	switch {
	case bcryptVariants[id] != "" || strings.HasPrefix(id, "argon2") || id == "scrypt" || strings.HasPrefix(id, "pbkdf2") || legacyCrypt[id].name != "" || strings.HasPrefix(t, "pbkdf2_sha256$"):
		x.add(60, Candidate{Name: "password hash that doesn't parse", Why: err.Error() + ".", Page: "/password"})
	case id != "":
		x.add(30, Candidate{Name: "$-delimited hash string", Page: "/password",
			Why: fmt.Sprintf("Shaped like crypt(3) or a PHC string, but $%s$ is not an id this site knows.", id)})
	}
}

// ---- UUID ----

var uuidVersions = map[byte]string{
	'1': "time and MAC address", '2': "DCE security", '3': "name-based, MD5", '4': "random",
	'5': "name-based, SHA-1", '6': "time-ordered, reordered v1", '7': "time-ordered, unix milliseconds", '8': "custom",
}

func (x *idents) uuid(t string) {
	u := strings.ToLower(t)
	u = strings.TrimPrefix(u, "urn:uuid:")
	if strings.HasPrefix(u, "{") && strings.HasSuffix(u, "}") {
		u = u[1 : len(u)-1]
	}
	if len(u) != 36 || u[8] != '-' || u[13] != '-' || u[18] != '-' || u[23] != '-' {
		return
	}
	h := strings.ReplaceAll(u, "-", "")
	if len(h) != 32 || !allHex(h) {
		return
	}
	name, why := uuidReading(h)
	x.add(95, Candidate{Name: name, Why: "8-4-4-4-12 hex digits; " + why + ".", Page: "/random"})
}

// uuidReading names a UUID by its version and variant (RFC 9562).
func uuidReading(h string) (name, why string) {
	switch h {
	case strings.Repeat("0", 32):
		return "the nil UUID", "all zeros, which RFC 9562 reserves to mean no UUID"
	case strings.Repeat("f", 32):
		return "the max UUID", "all ones, which RFC 9562 reserves"
	}
	v, _ := strconv.ParseUint(h[16:17], 16, 8)
	switch {
	case v&0x8 == 0:
		return "UUID-shaped value (NCS variant)", "the variant bits are 0, the pre-1990 NCS layout"
	case v&0xc == 0xc:
		return "UUID-shaped value (Microsoft variant)", "the variant bits are 110, Microsoft's legacy GUID layout"
	}
	ver := h[12]
	desc, ok := uuidVersions[ver]
	if !ok {
		return "UUID-shaped value", fmt.Sprintf("the version digit is %c, which RFC 9562 doesn't define", ver)
	}
	why = fmt.Sprintf("the version digit is %c and the variant is RFC 9562", ver)
	if ver == '7' {
		ms, _ := strconv.ParseInt(h[:12], 16, 64)
		why += ", and it was made at " + time.UnixMilli(ms).UTC().Format("2006-01-02 15:04:05.000 UTC")
	}
	return fmt.Sprintf("UUID version %c (%s)", ver, desc), why
}

// ---- webhook signatures ----

func (x *idents) webhookSignature(t string) {
	low := strings.ToLower(t)
	switch {
	case strings.HasPrefix(low, "sha256=") && len(t) == 7+64 && allHex(t[7:]):
		x.add(90, Candidate{Name: "GitHub webhook signature (X-Hub-Signature-256)", Page: "/hmac",
			Why: "sha256= and 64 hex digits: HMAC-SHA256 of the raw request body."})
	case strings.HasPrefix(low, "sha1=") && len(t) == 5+40 && allHex(t[5:]):
		x.add(85, Candidate{Name: "GitHub webhook signature, legacy (X-Hub-Signature)", Page: "/hmac",
			Why: "sha1= and 40 hex digits: HMAC-SHA1 of the raw request body."})
	case strings.HasPrefix(low, "v0=") && len(t) == 3+64 && allHex(t[3:]):
		x.add(85, Candidate{Name: "Slack request signature (X-Slack-Signature)", Page: "/hmac",
			Why: "v0= and 64 hex digits: HMAC-SHA256 of v0:timestamp:body."})
	case strings.HasPrefix(t, "t=") && strings.Contains(t, ",v1=") && singleToken(t):
		x.add(90, Candidate{Name: "Stripe-Signature header", Page: "/hmac",
			Why: "t=<timestamp>,v1=<hex>: HMAC-SHA256 of timestamp.body, in v1."})
	}
}

// ---- colon-separated hex ----

func (x *idents) colonHex(t string) {
	if !strings.Contains(t, ":") {
		return
	}
	n, ok := colonBytes(t)
	if !ok {
		return
	}
	switch n {
	case 6:
		x.add(45, Candidate{Name: "MAC address", Why: "6 colon-separated bytes."})
	case 16:
		x.add(50, Candidate{Name: "MD5 fingerprint", Page: "/keys",
			Why: "16 colon-separated bytes: an MD5 fingerprint, as older ssh-keygen and some certificate viewers print."})
	case 20:
		x.add(60, Candidate{Name: "SHA-1 fingerprint (certificate thumbprint)", Page: "/cert",
			Why: "20 colon-separated bytes: a certificate's SHA-1 fingerprint, as openssl x509 -fingerprint prints."})
	case 32:
		x.add(60, Candidate{Name: "SHA-256 fingerprint", Page: "/cert",
			Why: "32 colon-separated bytes: a certificate's or a key's SHA-256 fingerprint, as openssl x509 -fingerprint -sha256 prints."})
	default:
		x.add(35, Candidate{Name: "colon-separated hex bytes", Page: "/encode", Why: fmt.Sprintf("%d bytes.", n)})
	}
}

// ---- hex digests ----

type digestGuess struct {
	name, hashcat, page string
	score               int
	note                string
}

// hexDigests: the digests each hex length could be, commonest first. A mode
// is listed only where it is certain, and the note says when hashcat wants
// more than the bare hex; a page only where that page computes the algorithm.
var hexDigests = map[int][]digestGuess{
	8: {{name: "CRC-32 or Adler-32 checksum", page: "/hash", score: 30}},
	32: {
		{name: "MD5", hashcat: "0", page: "/hash", score: 55},
		{name: "NTLM", hashcat: "1000", score: 50, note: "Windows password hashes"},
		{name: "MD4", hashcat: "900", score: 30},
		// No mode: hashcat -m 3000 takes each 16-digit half on its own.
		{name: "LM", score: 25, note: "legacy Windows password hashes, usually upper case; hashcat -m 3000 takes each 16-digit half separately"},
	},
	40: {
		{name: "SHA-1", hashcat: "100", page: "/hash", score: 55, note: "also the length of a git commit id"},
		{name: "RIPEMD-160", hashcat: "6000", score: 30},
	},
	56: {
		{name: "SHA-224", hashcat: "1300", page: "/hash", score: 55},
		{name: "SHA3-224", hashcat: "17300", score: 35},
	},
	64: {
		{name: "SHA-256", hashcat: "1400", page: "/hash", score: 55},
		{name: "SHA3-256", hashcat: "17400", page: "/hash", score: 35},
		{name: "Keccak-256", hashcat: "17800", page: "/hash", score: 35, note: "what Ethereum calls SHA3"},
		{name: "BLAKE2s-256", page: "/hash", score: 30},
		{name: "BLAKE2b-256", page: "/hash", score: 28},
		{name: "SHA-512/256", page: "/hash", score: 28},
	},
	96: {
		{name: "SHA-384", hashcat: "10800", page: "/hash", score: 55},
		{name: "SHA3-384", hashcat: "17500", score: 35},
	},
	128: {
		{name: "SHA-512", hashcat: "1700", page: "/hash", score: 55},
		{name: "SHA3-512", hashcat: "17600", page: "/hash", score: 35},
		{name: "BLAKE2b-512", hashcat: "600", page: "/hash", score: 35, note: "hashcat -m 600 wants it prefixed $BLAKE2$"},
	},
}

func (x *idents) hexDigest(t string) {
	if !allHex(t) {
		return
	}
	for _, g := range hexDigests[len(t)] {
		why := fmt.Sprintf("%d hex digits, %d bytes: the output length of %s", len(t), len(t)/2, g.name)
		if g.note != "" {
			why += "; " + g.note
		}
		if g.page == "/hash" {
			why += ". To confirm, hash the input on the Hash page and paste this as the expected value"
		}
		x.add(g.score, Candidate{Name: g.name + " digest", Why: why + ".", Page: g.page, Hashcat: g.hashcat})
	}
	if len(t) == 32 {
		if name, why := uuidReading(strings.ToLower(t)); strings.HasPrefix(name, "UUID version") {
			x.add(25, Candidate{Name: name + ", without dashes", Why: why + ". One random hex string in eight has these bits by chance.", Page: "/random"})
		}
	}
}

// ---- digits ----

func (x *idents) digits(t string) {
	if !allDigits(t) {
		return
	}
	switch len(t) {
	case 6:
		x.add(45, Candidate{Name: "one-time code (TOTP or HOTP)", Page: "/totp", Why: "6 digits, the usual length of an authenticator code."})
	case 7, 8:
		x.add(30, Candidate{Name: "one-time code (TOTP or HOTP)", Page: "/totp", Why: fmt.Sprintf("%d digits: some authenticators make codes this long.", len(t))})
	}
}

// ---- hex bytes ----

func (x *idents) hexBytes(t string) {
	h := strings.TrimPrefix(strings.TrimPrefix(t, "0x"), "0X")
	if len(h) < 2 || len(h)%2 != 0 || !allHex(h) {
		return
	}
	b, _ := hex.DecodeString(h)
	c := Candidate{Name: "hex-encoded bytes", Page: "/encode"}
	score, why := 22, fmt.Sprintf("%d bytes", len(b))
	if desc, page := recognise(b); desc != "" {
		score, why, c.Page = 60, fmt.Sprintf("%d bytes, and they are %s", len(b), desc), page
	} else if isText(b) {
		score, why = 50, fmt.Sprintf("%d bytes, and they are printable UTF-8 text", len(b))
	} else if note := sizeNote(len(b)); note != "" {
		why += ", " + note
	}
	c.Why = why + "."
	c.Preview, c.PreviewHex = preview(b)
	if c.PreviewHex {
		c.Preview = "" // it would only repeat the input
	}
	x.add(score, c)
}

// ---- base64 ----

func (x *idents) base64(t string) {
	// Wrapped base64 has line breaks, never spaces.
	if strings.ContainsAny(t, " \t") {
		return
	}
	c, _ := stripSpace(t)
	if len(c) < 8 {
		return
	}
	for i := 0; i < len(c); i++ {
		ch := c[i]
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || strings.IndexByte("+/-_=", ch) >= 0) {
			return
		}
	}
	b, variant, err := decodeBase64Any(c)
	if err != nil || len(b) == 0 {
		return
	}
	// Hex digits and plain numbers are valid base64 too; that reading is only
	// worth a line when it decodes to something recognisable.
	encodedLooking := allHex(c) || allDigits(c)
	cand := Candidate{Name: variant, Page: "/encode"}
	var score int
	var why string
	if desc, page := recognise(b); desc != "" {
		score, why, cand.Page = 65, fmt.Sprintf("Decodes to %d bytes, and they are %s", len(b), desc), page
	} else if isText(b) {
		score, why = 55, fmt.Sprintf("Decodes to %d bytes of printable UTF-8 text", len(b))
		if encodedLooking {
			score = 40
		}
	} else if encodedLooking {
		return
	} else {
		score, why = 20, fmt.Sprintf("Decodes to %d bytes of binary", len(b))
		if strings.HasSuffix(c, "=") || strings.ContainsAny(c, "+/-_") {
			score = 28 // characters only base64 uses
		}
		if note := sizeNote(len(b)); note != "" {
			why += ", " + note
		}
	}
	cand.Why = why + "."
	cand.Preview, cand.PreviewHex = preview(b)
	x.add(score, cand)
}

// ---- base32 ----

func (x *idents) base32(t string) {
	// TOTP secrets come grouped in fours; anything else with spaces is prose.
	groups := strings.Fields(t)
	for i, g := range groups {
		if len(groups) > 1 && i < len(groups)-1 && len(g) != 4 {
			return
		}
	}
	c := strings.TrimRight(strings.Join(groups, ""), "=")
	if len(c) < 16 || c != strings.ToUpper(c) && c != strings.ToLower(c) {
		return
	}
	digit := false
	for i := 0; i < len(c); i++ {
		ch := c[i] &^ 0x20 // upper-case a letter; digits are checked before this matters
		switch {
		case c[i] >= '2' && c[i] <= '7':
			digit = true
		case ch >= 'A' && ch <= 'Z':
		default:
			return
		}
	}
	if !digit {
		return
	}
	b, err := DecodeBytes(c, EncBase32)
	if err != nil || len(b) == 0 {
		return
	}
	score := 30
	switch len(b) {
	case 10, 16, 20, 32, 64:
		score = 45 // the usual TOTP secret sizes
	}
	x.add(score, Candidate{Name: "base32", Page: "/totp",
		Why: fmt.Sprintf("Only A to Z and 2 to 7, decoding to %d bytes: base32 is how authenticator secrets are written.", len(b))})
}

// ---- plain text ----

func (x *idents) text(t string) {
	if x.any(70) {
		return
	}
	score := 15 // one token in an encoding's alphabet: probably not prose
	switch {
	case strings.ContainsAny(t, " \t\n"):
		score = 38
	case strings.IndexFunc(t, func(r rune) bool { return !unicode.IsLetter(r) }) < 0:
		score = 25 // a single word
	case strings.IndexFunc(t, func(r rune) bool {
		return !(r < 0x80 && (unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("+/-_=", r)))
	}) >= 0:
		score = 30
	}
	why := "Matches none of the formats this page knows."
	if len(x.c) > 0 {
		why = "If none of the readings above fits, it is text: the Encode page shows its bytes, and the Hash page hashes it."
	}
	x.add(score, Candidate{Name: fmt.Sprintf("plain text (%d characters)", utf8.RuneCountInString(t)), Why: why, Page: "/encode"})
}

// ---- decoded bytes ----

// recognise says what decoded bytes are, when they are something this site
// reads, and which page reads them.
func recognise(b []byte) (desc, page string) {
	s := strings.TrimSpace(string(b))
	switch {
	case len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b:
		return "gzip-compressed data", ""
	case len(b) > 4 && b[0] == 0x30:
		if _, err := x509.ParseCertificate(b); err == nil {
			return "a DER X.509 certificate", "/cert"
		}
		if _, err := x509.ParseCertificateRequest(b); err == nil {
			return "a DER certificate signing request", "/cert"
		}
		if _, err := x509.ParsePKIXPublicKey(b); err == nil {
			return "a DER public key (SPKI)", "/keys"
		}
		if _, err := x509.ParsePKCS8PrivateKey(b); err == nil {
			return "a DER private key (PKCS#8)", "/keys"
		}
		return "", ""
	case !utf8.Valid(b):
		return "", ""
	case strings.Contains(s, "-----BEGIN "):
		return "PEM text", "/cert"
	case hasPrefixFold(s, "otpauth://"):
		return "an otpauth:// URI", "/totp"
	case (strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")) && json.Valid([]byte(s)):
		var obj map[string]any
		_ = json.Unmarshal([]byte(s), &obj)
		if _, ok := obj["kty"]; ok {
			return "a JWK", "/keys"
		}
		if _, ok := obj["alg"]; ok {
			return "JSON with alg: a JWT header?", "/"
		}
		return "JSON", "/encode"
	}
	if _, _, ok := joseHeader(s); ok && singleToken(s) {
		return "a JWT", "/"
	}
	return "", ""
}

func isText(b []byte) bool {
	return utf8.Valid(b) && printable(string(b)) && strings.IndexFunc(string(b), unicode.IsLetter) >= 0
}

// sizeNote says what a binary value of n bytes often is.
func sizeNote(n int) string {
	switch n {
	case 16:
		return "the size of an AES-128 key, an MD5 digest or a UUID"
	case 20:
		return "the size of a SHA-1 digest"
	case 24:
		return "the size of an AES-192 key"
	case 32:
		return "the size of an AES-256 key or a SHA-256 digest"
	case 48:
		return "the size of a SHA-384 digest"
	case 64:
		return "the size of a SHA-512 digest"
	}
	return ""
}

// preview is the start of b: up to 80 characters of text, or 32 bytes as hex.
func preview(b []byte) (string, bool) {
	t := textOf(b)
	if !t.IsText {
		if len(b) > 32 {
			return hex.EncodeToString(b[:32]) + "…", true
		}
		return t.Hex, true
	}
	if utf8.RuneCountInString(t.Value) <= 80 {
		return t.Value, false
	}
	n := 0
	for i := range t.Value {
		if n == 80 {
			return t.Value[:i] + "…", false
		}
		n++
	}
	return t.Value, false
}
