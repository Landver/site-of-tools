package ciphertools

import (
	"cmp"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Recognisers add scored readings; the answer is the ranked list, never one verdict (docs/03-correctness-traps.md).

func init() {
	register(Op{Name: "identify", Path: "/identify", Page: "identify", Fragment: "cipher/identify-result",
		Run: func(in Input) (any, error) { return Identify(in.Get("text")) },
		Fields: []Field{
			{Name: "text", Kind: KindString, Required: true,
				Description: "The string to identify, up to 1 MiB: a hash, token, key, certificate, password hash, UUID, otpauth:// URI or encoded value; the answer ranks what it could be, with hashcat modes."},
		}})
}

// maxIdentify: anything real (a chain, a JWKS) is far smaller, and the page re-runs on every keystroke.
const maxIdentify = 1 << 20

// Candidate is one thing the input could be.
type Candidate struct {
	Name       string `json:"name"`
	Confidence string `json:"confidence"`
	Why        string `json:"why"`
	Page       string `json:"page,omitempty"`
	PageName   string `json:"page_name,omitempty"`
	// Field on Page takes the value, with Set ("name=value") chosen beside it. Display only.
	Field      string `json:"-"`
	Set        string `json:"-"`
	Hashcat    string `json:"hashcat,omitempty"` // only where the mode is certain
	Preview    string `json:"preview,omitempty"`
	PreviewHex bool   `json:"preview_is_hex,omitempty"`

	score int
}

type IdentifyResult struct {
	Bytes      int         `json:"bytes"`
	Lines      int         `json:"lines"`
	Candidates []Candidate `json:"candidates"`
}

// identifyPages: each page's name, and the field on it that takes a pasted value.
var identifyPages = map[string]struct{ name, field string }{
	"/": {"JWT", "token"}, "/hash": {"Hash", "expected"}, "/hmac": {"HMAC", "expected"}, "/password": {"Passwords", "hash"},
	"/keys": {"Keys", "key"}, "/cert": {"Certs", "cert"}, "/totp": {"TOTP", "secret"}, "/random": {"Random", ""},
	"/encode": {"Encode", "text"},
}

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
	return &IdentifyResult{Bytes: len(t), Lines: strings.Count(t, "\n") + 1, Candidates: x.c}, nil
}

type idents struct{ c []Candidate }

// add files a reading. Score 70 and up is a parse that succeeded on an unambiguous
// shape, 40 to 69 a plausible reading among others, below 40 possible, no more.
func (x *idents) add(score int, name, page, why string) *Candidate {
	c := Candidate{Name: name, Confidence: "low", Why: why, Page: page, score: score,
		PageName: identifyPages[page].name, Field: identifyPages[page].field}
	if score >= 70 {
		c.Confidence = "high"
	} else if score >= 40 {
		c.Confidence = "medium"
	}
	switch low := strings.ToLower(name); {
	case strings.Contains(low, "fingerprint"): // nowhere to paste it
		c.Field = ""
	case page == "/totp" && strings.Contains(low, "one-time code"):
		c.Field = "code"
	case page == "/encode" && strings.Contains(low, "basic auth"):
		c.Field = "header"
	case page == "/encode":
		for _, enc := range []string{"base64url", "base64", "hex"} {
			if strings.Contains(low, enc) {
				c.Set = "from=" + enc
				break
			}
		}
	}
	x.c = append(x.c, c)
	return &x.c[len(x.c)-1]
}

func singleToken(t string) bool { return !strings.ContainsAny(t, " \t\r\n") }

// identifyOnly: every character of s is in set.
func identifyOnly(s, set string) bool { return strings.Trim(s, set) == "" }

// pemKinds: each PEM type's name, the page that reads it and, where set, its DER parser.
// cert.go's key-alongside check reads page and keyFromPEM reads parse, so edits reach both.
var pemKinds = map[string]struct {
	name, page string
	parse      func([]byte) (any, error)
}{
	"CERTIFICATE":             {"X.509 certificate", "/cert", identifyDER(x509.ParseCertificate)},
	"TRUSTED CERTIFICATE":     {"X.509 certificate (OpenSSL trusted form)", "/cert", nil},
	"CERTIFICATE REQUEST":     {"certificate signing request (CSR)", "/cert", identifyDER(x509.ParseCertificateRequest)},
	"NEW CERTIFICATE REQUEST": {"certificate signing request (CSR)", "/cert", identifyDER(x509.ParseCertificateRequest)},
	"X509 CRL":                {"certificate revocation list", "", nil},
	"PRIVATE KEY":             {"private key (PKCS#8)", "/keys", identifyDER(x509.ParsePKCS8PrivateKey)},
	"ENCRYPTED PRIVATE KEY":   {"passphrase-encrypted private key (PKCS#8)", "/keys", nil},
	"RSA PRIVATE KEY":         {"RSA private key (PKCS#1)", "/keys", identifyDER(x509.ParsePKCS1PrivateKey)},
	"EC PRIVATE KEY":          {"EC private key (SEC 1)", "/keys", identifyDER(x509.ParseECPrivateKey)},
	"PUBLIC KEY":              {"public key (SPKI)", "/keys", identifyDER(x509.ParsePKIXPublicKey)},
	"RSA PUBLIC KEY":          {"RSA public key (PKCS#1)", "/keys", identifyDER(x509.ParsePKCS1PublicKey)},
	"OPENSSH PRIVATE KEY":     {"OpenSSH private key", "/keys", nil},
	"EC PARAMETERS":           {"EC parameters (names a curve; not a key)", "/keys", nil},
	"DH PARAMETERS":           {"Diffie-Hellman parameters", "", nil},
}

func identifyDER[T any](parse func([]byte) (T, error)) func([]byte) (any, error) {
	return func(der []byte) (any, error) { return parse(der) }
}

// identifyTitle names a certificate or CSR by its first SAN or CN.
func identifyTitle(v any) string {
	switch c := v.(type) {
	case *x509.Certificate:
		return title(sansOf(c.DNSNames, c.IPAddresses, c.EmailAddresses, c.URIs), c.Subject.CommonName, c.Subject.String())
	case *x509.CertificateRequest:
		return title(sansOf(c.DNSNames, c.IPAddresses, c.EmailAddresses, c.URIs), c.Subject.CommonName, c.Subject.String())
	}
	return ""
}

func (x *idents) pemBlocks(t string) {
	_, after, ok := strings.Cut(t, "-----BEGIN ")
	if !ok {
		return
	}
	type seen struct {
		typ, preview         string
		n, parsed            int
		encrypted, oversized bool
	}
	var kinds []seen
	rest := []byte(t)
	for range maxPEMBlocks {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		i := slices.IndexFunc(kinds, func(k seen) bool { return k.typ == b.Type })
		if i < 0 {
			i, kinds = len(kinds), append(kinds, seen{typ: b.Type})
		}
		k := &kinds[i]
		k.n++
		k.encrypted = k.encrypted || strings.Contains(b.Headers["Proc-Type"], "ENCRYPTED")
		if checkPrivateDER(b) != nil {
			k.oversized = true
		} else if parse := pemKinds[b.Type].parse; parse != nil {
			if v, err := parse(b.Bytes); err == nil {
				k.parsed++
				k.preview = cmp.Or(k.preview, identifyTitle(v))
			}
		}
	}
	if len(kinds) == 0 {
		typ, _, ok := strings.Cut(after, "-----")
		if !ok || len(typ) >= 64 {
			typ = "?"
		}
		x.add(60, "PEM block that doesn't decode ("+typ+")", pemKinds[typ].page,
			"There is a -----BEGIN "+typ+"----- line but no complete block: the END line, or part of the base64 between them, is missing or damaged.")
		return
	}
	for _, k := range kinds {
		typ, kind := k.typ, pemKinds[k.typ]
		name := cmp.Or(kind.name, "PEM block ("+typ+")")
		if strings.HasPrefix(typ, "PGP ") {
			name = "OpenPGP armored data (" + typ + ")"
		}
		switch {
		case typ == "CERTIFICATE" && k.n > 1:
			name = fmt.Sprintf("X.509 certificate chain (%d certificates)", k.n)
		case k.n > 1:
			name = fmt.Sprintf("%s (%d)", name, k.n)
		}
		why, score := fmt.Sprintf("%d PEM block%s of type %s", k.n, plural(k.n), typ), 95
		switch {
		case k.encrypted || typ == "ENCRYPTED PRIVATE KEY":
			why += ", passphrase-encrypted: decrypt it locally first (openssl pkey -in key.pem -out plain.pem)"
		case k.oversized:
			why += fmt.Sprintf(", but larger than any real key (over %s of DER), so not parsed", bytesText(maxPrivateKeyDER))
			score = 60
		case k.parsed == 0 && kind.parse != nil:
			why += ", but the DER inside doesn't parse as one"
			score = 60
		case k.parsed < k.n && kind.parse != nil:
			why += fmt.Sprintf(", of which %d parse", k.parsed)
		}
		x.add(score, name, kind.page, why+".").Preview = k.preview
	}
}

func (x *idents) otpauth(t string) {
	switch {
	case hasPrefixFold(t, "otpauth-migration://"):
		x.add(80, "Google Authenticator export (otpauth-migration://)", "",
			"A batch of accounts packed in a protobuf. The TOTP page reads one otpauth:// URI at a time, so export or scan the accounts one by one.")
	case hasPrefixFold(t, "otpauth://"):
		s, _, err := ParseOTPURI(t)
		if err != nil {
			x.add(60, "otpauth:// URI that doesn't parse", "/totp", err.Error()+".")
			return
		}
		why := fmt.Sprintf("%s, %d digits, counter %d", s.Algorithm, s.Digits, s.Counter)
		if s.Type == OTPTypeTOTP {
			why = fmt.Sprintf("%s, %d digits, %d-second period", s.Algorithm, s.Digits, s.Period)
		}
		if s.Issuer != "" {
			why += ", issuer " + strconv.Quote(s.Issuer)
		}
		if s.Account != "" {
			why += ", account " + strconv.Quote(s.Account)
		}
		x.add(95, "otpauth:// URI for an authenticator app ("+strings.ToUpper(s.Type)+")", "/totp", why+".")
	}
}

func joseHeader(t string) (parts []string, hdr map[string]any, ok bool) {
	tok := cleanToken(t)
	if parts = strings.Split(tok, "."); len(parts) != 3 && len(parts) != 5 || !identifyOnly(tok, alnum+"-_=.") {
		return nil, nil, false
	}
	h, err := segment(parts[0], "header")
	if err != nil || json.Unmarshal(h, &hdr) != nil || hdr == nil {
		return nil, nil, false
	}
	return parts, hdr, true
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
		x.add(95, "JWE (encrypted JWT)", "/", fmt.Sprintf(
			"Five base64url parts, and the header decodes to JSON with alg %s and enc %s. Only the header is readable without the recipient's key.", alg, enc))
	case len(parts) == 3 && alg != "":
		why := "Three base64url parts, and the header decodes to JSON with alg " + alg
		if typ, _ := hdr["typ"].(string); typ != "" {
			why += " and typ " + typ
		}
		if strings.EqualFold(alg, "none") {
			why += ". alg none means it is unsigned: anyone could have written it"
		}
		x.add(95, "JWT (signed, JWS)", "/", why+".")
	default:
		lacks := map[int]string{3: "alg", 5: "alg or enc"}[len(parts)]
		x.add(55, "JOSE-shaped value", "/", fmt.Sprintf("%d base64url parts with a JSON header, but the header lacks %s.", len(parts), lacks))
	}
}

func (x *idents) authHeader(t string) {
	v := t
	if hasPrefixFold(v, "authorization:") {
		v = strings.TrimSpace(v[len("authorization:"):])
	}
	switch {
	case hasPrefixFold(v, "basic ") || hasPrefixFold(v, "basic\t"):
		a, err := DecodeBasic(t)
		if err != nil {
			x.add(55, "HTTP Basic auth header that doesn't decode", "/encode", err.Error()+".")
			return
		}
		user := "the user name is " + strconv.Quote(a.User.Value)
		if !a.User.IsText {
			user = "the user name isn't printable text"
		}
		x.add(95, "HTTP Basic auth credentials", "/encode",
			"Basic, then the base64 of user:password; "+user+". It is an encoding, not encryption: the password is in there too.")
	case hasPrefixFold(v, "bearer "):
		if _, _, ok := joseHeader(v); !ok { // a JWT is the jose reading's
			x.add(50, "Bearer token (opaque)", "", "An Authorization: Bearer value that isn't a JWT. Its format is private to whoever issued it.")
		}
	}
}

func (x *idents) ssh(t string) {
	switch {
	case strings.HasPrefix(t, "SHA256:") && len(t) == 50:
		if b, v, err := decodeBase64Any(t[7:]); err == nil && v == VariantStdRaw && len(b) == 32 {
			x.add(90, "OpenSSH key fingerprint (SHA-256)", "/keys", "SHA256: and 43 characters of unpadded base64, 32 bytes: what ssh-keygen -l prints.")
		}
	case strings.HasPrefix(t, "MD5:"):
		if n, ok := colonBytes(t[4:]); ok && n == 16 {
			x.add(85, "OpenSSH key fingerprint (MD5, legacy)", "/keys", "MD5: and 16 colon-separated bytes: what ssh-keygen -l -E md5 prints.")
		}
	case looksLikeOpenSSH(t):
		lines, _ := sshLines(t)
		k, err := keyFromOpenSSH(strings.TrimSpace(lines[0]))
		if err != nil {
			x.add(60, "OpenSSH public key line that doesn't parse", "/keys", err.Error()+".")
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
		x.add(95, name, "/keys", why+".").Preview = k.Comment
	}
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

func (x *idents) jsonValue(t string) {
	if !strings.HasPrefix(t, "{") && !strings.HasPrefix(t, "[") {
		return
	}
	var v any
	if err := json.Unmarshal([]byte(t), &v); err != nil {
		why := err.Error()
		if se, ok := errors.AsType[*json.SyntaxError](err); ok {
			why = fmt.Sprintf("%v, at offset %d", se, se.Offset)
		}
		score := 25
		if open, end := t[0], t[len(t)-1]; open == '{' && end == '}' || open == '[' && end == ']' {
			score = 45 // meant as JSON: rank it above plain text
		}
		x.add(score, "JSON-like, but not valid JSON", "", why+".")
		return
	}
	obj, _ := v.(map[string]any)
	if kty, ok := obj["kty"].(string); ok {
		part, why := "public", "A JSON object with kty "+kty
		if _, priv := obj["d"]; priv {
			part, why = "private", why+" and the private member d"
		}
		x.add(90, "JWK ("+kty+" "+part+" key)", "/keys", why+".")
		return
	}
	if keys, ok := obj["keys"].([]any); ok {
		x.add(90, fmt.Sprintf("JWKS (%d key%s)", len(keys), plural(len(keys))), "/keys",
			"A JSON object with a keys array: a JSON Web Key Set, as served at /.well-known/jwks.json.")
		return
	}
	x.add(50, "JSON", "", "Valid JSON, and not a JWK or a JWKS.")
}

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
		why, sep := h.Format, ": "
		if h.Variant != "" {
			why += " " + h.Variant
		}
		for _, p := range h.Params {
			if p.Name != "salt" && p.Name != "variant" && p.Name != "params" {
				why, sep = why+sep+p.Name+"="+p.Value, ", "
			}
		}
		mode := passwordHashcat[h.Algorithm]
		if h.Format == "Django" {
			mode = "10000"
		}
		x.add(95, h.Name+" password hash", "/password", why+".").Hashcat = mode
		return
	}
	id := ""
	if f := strings.Split(t, "$"); len(f) > 2 {
		id = f[1]
	}
	switch {
	case id != "" && (!errors.Is(err, errUnknownHash) || strings.HasPrefix(id, "pbkdf2")) || strings.HasPrefix(t, "pbkdf2_sha256$"):
		x.add(60, "password hash that doesn't parse", "/password", err.Error()+".")
	case id != "":
		x.add(30, "$-delimited hash string", "/password", fmt.Sprintf("Shaped like crypt(3) or a PHC string, but $%s$ is not an id this site knows.", id))
	}
}

var uuidVersions = map[byte]string{
	'1': "time and MAC address", '2': "DCE security", '3': "name-based, MD5", '4': "random",
	'5': "name-based, SHA-1", '6': "time-ordered, reordered v1", '7': "time-ordered, unix milliseconds", '8': "custom",
}

func (x *idents) uuid(t string) {
	u := strings.TrimPrefix(strings.ToLower(t), "urn:uuid:")
	if strings.HasPrefix(u, "{") && strings.HasSuffix(u, "}") {
		u = u[1 : len(u)-1]
	}
	if len(u) != 36 || u[8] != '-' || u[13] != '-' || u[18] != '-' || u[23] != '-' {
		return
	}
	if h := strings.ReplaceAll(u, "-", ""); len(h) == 32 && allHex(h) {
		name, why := uuidReading(h)
		x.add(95, name, "/random", "8-4-4-4-12 hex digits; "+why+".")
	}
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

func (x *idents) webhookSignature(t string) {
	switch {
	case hasPrefixFold(t, "sha256=") && len(t) == 7+64 && allHex(t[7:]):
		x.add(90, "GitHub webhook signature (X-Hub-Signature-256)", "/hmac", "sha256= and 64 hex digits: HMAC-SHA256 of the raw request body.")
	case hasPrefixFold(t, "sha1=") && len(t) == 5+40 && allHex(t[5:]):
		x.add(85, "GitHub webhook signature, legacy (X-Hub-Signature)", "/hmac", "sha1= and 40 hex digits: HMAC-SHA1 of the raw request body.")
	case hasPrefixFold(t, "v0=") && len(t) == 3+64 && allHex(t[3:]):
		x.add(85, "Slack request signature (X-Slack-Signature)", "/hmac", "v0= and 64 hex digits: HMAC-SHA256 of v0:timestamp:body.")
	case strings.HasPrefix(t, "t=") && strings.Contains(t, ",v1=") && singleToken(t):
		x.add(90, "Stripe-Signature header", "/hmac", "t=<timestamp>,v1=<hex>: HMAC-SHA256 of timestamp.body, in v1.")
	}
}

func (x *idents) colonHex(t string) {
	switch n, ok := colonBytes(t); {
	case !ok || !strings.Contains(t, ":"):
	case n == 6:
		x.add(45, "MAC address", "", "6 colon-separated bytes.")
	case n == 16:
		x.add(50, "MD5 fingerprint", "/keys", "16 colon-separated bytes: an MD5 fingerprint, as older ssh-keygen and some certificate viewers print.")
	case n == 20:
		x.add(60, "SHA-1 fingerprint (certificate thumbprint)", "/cert",
			"20 colon-separated bytes: a certificate's SHA-1 fingerprint, as openssl x509 -fingerprint prints.")
	case n == 32:
		x.add(60, "SHA-256 fingerprint", "/cert",
			"32 colon-separated bytes: a certificate's or a key's SHA-256 fingerprint, as openssl x509 -fingerprint -sha256 prints.")
	default:
		x.add(35, "colon-separated hex bytes", "/encode", fmt.Sprintf("%d bytes.", n))
	}
}

// hexDigests: commonest first; a mode only where certain, a page only where it computes the algorithm.
var hexDigests = []struct {
	n                      int
	name, mode, page, note string
	score                  int
}{
	{n: 8, name: "CRC-32 or Adler-32 checksum", page: "/hash", score: 30},
	{n: 32, name: "MD5", mode: "0", page: "/hash", score: 55},
	{n: 32, name: "NTLM", mode: "1000", score: 50, note: "Windows password hashes"},
	{n: 32, name: "MD4", mode: "900", score: 30},
	{n: 32, name: "LM", score: 25, note: "legacy Windows password hashes, usually upper case; hashcat -m 3000 takes each 16-digit half separately"},
	{n: 40, name: "SHA-1", mode: "100", page: "/hash", score: 55, note: "also the length of a git commit id"},
	{n: 40, name: "RIPEMD-160", mode: "6000", score: 30},
	{n: 56, name: "SHA-224", mode: "1300", page: "/hash", score: 55},
	{n: 56, name: "SHA3-224", mode: "17300", score: 35},
	{n: 64, name: "SHA-256", mode: "1400", page: "/hash", score: 55},
	{n: 64, name: "SHA3-256", mode: "17400", page: "/hash", score: 35},
	{n: 64, name: "Keccak-256", mode: "17800", page: "/hash", score: 35, note: "what Ethereum calls SHA3"},
	{n: 64, name: "BLAKE2s-256", page: "/hash", score: 30},
	{n: 64, name: "BLAKE2b-256", page: "/hash", score: 28},
	{n: 64, name: "SHA-512/256", page: "/hash", score: 28},
	{n: 96, name: "SHA-384", mode: "10800", page: "/hash", score: 55},
	{n: 96, name: "SHA3-384", mode: "17500", score: 35},
	{n: 128, name: "SHA-512", mode: "1700", page: "/hash", score: 55},
	{n: 128, name: "SHA3-512", mode: "17600", page: "/hash", score: 35},
	{n: 128, name: "BLAKE2b-512", mode: "600", page: "/hash", score: 35, note: "hashcat -m 600 wants it prefixed $BLAKE2$"},
}

func (x *idents) hexDigest(t string) {
	if !allHex(t) {
		return
	}
	for _, g := range hexDigests {
		if g.n != len(t) {
			continue
		}
		why := fmt.Sprintf("%d hex digits, %d bytes: the output length of %s", len(t), len(t)/2, g.name)
		if g.note != "" {
			why += "; " + g.note
		}
		if g.page == "/hash" {
			why += ". To confirm, hash the input on the Hash page and paste this as the expected value"
		}
		x.add(g.score, g.name+" digest", g.page, why+".").Hashcat = g.mode
	}
	if len(t) == 32 {
		if name, why := uuidReading(strings.ToLower(t)); strings.HasPrefix(name, "UUID version") {
			x.add(25, name+", without dashes", "/random", why+". One random hex string in eight has these bits by chance.")
		}
	}
}

func (x *idents) digits(t string) {
	switch {
	case !allDigits(t):
	case len(t) == 6:
		x.add(45, "one-time code (TOTP or HOTP)", "/totp", "6 digits, the usual length of an authenticator code.")
	case len(t) == 7 || len(t) == 8:
		x.add(30, "one-time code (TOTP or HOTP)", "/totp", fmt.Sprintf("%d digits: some authenticators make codes this long.", len(t)))
	}
}

func (x *idents) hexBytes(t string) {
	h := strings.TrimPrefix(strings.TrimPrefix(t, "0x"), "0X")
	if len(h) < 2 || len(h)%2 != 0 || !allHex(h) {
		return
	}
	b, _ := hex.DecodeString(h)
	score, page, why := 22, "/encode", fmt.Sprintf("%d bytes", len(b))
	if desc, p := recognise(b); desc != "" {
		score, page, why = 60, p, fmt.Sprintf("%d bytes, and they are %s", len(b), desc)
	} else if isText(b) {
		score, why = 50, fmt.Sprintf("%d bytes, and they are printable UTF-8 text", len(b))
	} else if note := identifySizes[len(b)]; note != "" {
		why += ", the size of " + note
	}
	c := x.add(score, "hex-encoded bytes", page, why+".")
	if c.Preview, c.PreviewHex = preview(b); c.PreviewHex {
		c.Preview = "" // it would only repeat the input
	}
}

func (x *idents) base64(t string) {
	if strings.ContainsAny(t, " \t") { // wrapped base64 has line breaks, never spaces
		return
	}
	c, _ := stripSpace(t)
	if len(c) < 8 || !identifyOnly(c, alnum+"+/-_=") {
		return
	}
	b, variant, err := decodeBase64Any(c)
	if err != nil || len(b) == 0 {
		return
	}
	// Hex digits and plain numbers are base64 too: worth a line only if they decode to something.
	encodedLooking := allHex(c) || allDigits(c)
	score, page, why := 20, "/encode", fmt.Sprintf("Decodes to %d bytes of binary", len(b))
	switch desc, p := recognise(b); {
	case desc != "":
		score, page, why = 65, p, fmt.Sprintf("Decodes to %d bytes, and they are %s", len(b), desc)
	case isText(b):
		score, why = 55, fmt.Sprintf("Decodes to %d bytes of printable UTF-8 text", len(b))
		if encodedLooking {
			score = 40
		}
	case encodedLooking:
		return
	default:
		if strings.HasSuffix(c, "=") || strings.ContainsAny(c, "+/-_") {
			score = 28 // characters only base64 uses
		}
		if note := identifySizes[len(b)]; note != "" {
			why += ", the size of " + note
		}
	}
	cand := x.add(score, variant, page, why+".")
	cand.Preview, cand.PreviewHex = preview(b)
}

func (x *idents) base32(t string) {
	groups := strings.Fields(t)
	if slices.ContainsFunc(groups[:len(groups)-1], func(g string) bool { return len(g) != 4 }) {
		return // TOTP secrets come grouped in fours; other spaces are prose
	}
	c := strings.TrimRight(strings.Join(groups, ""), "=")
	if len(c) < 16 || c != strings.ToUpper(c) && c != strings.ToLower(c) ||
		!identifyOnly(c, letters+"234567") || !strings.ContainsAny(c, "234567") {
		return
	}
	b, err := decodeBase32(c)
	if err != nil || len(b) == 0 {
		return
	}
	score := 30
	if slices.Contains([]int{10, 16, 20, 32, 64}, len(b)) {
		score = 45 // the usual TOTP secret sizes
	}
	x.add(score, "base32", "/totp", fmt.Sprintf("Only A to Z and 2 to 7, decoding to %d bytes: base32 is how authenticator secrets are written.", len(b)))
}

func (x *idents) text(t string) {
	if slices.ContainsFunc(x.c, func(c Candidate) bool { return c.score >= 70 }) {
		return
	}
	score := 15 // one token in an encoding's alphabet: probably not prose
	switch {
	case strings.ContainsAny(t, " \t\n"):
		score = 38
	case strings.IndexFunc(t, func(r rune) bool { return !unicode.IsLetter(r) }) < 0:
		score = 25 // a single word
	case !identifyOnly(t, alnum+"+/-_="):
		score = 30
	}
	why := "Matches none of the formats this page knows."
	if len(x.c) > 0 {
		why = "If none of the readings above fits, it is text: the Encode page shows its bytes, and the Hash page hashes it."
	}
	x.add(score, fmt.Sprintf("plain text (%d characters)", utf8.RuneCountInString(t)), "/encode", why)
}

// recognise says what decoded bytes are when a page here reads them, and which page.
func recognise(b []byte) (desc, page string) {
	s := strings.TrimSpace(string(b))
	switch {
	case len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b:
		return "gzip-compressed data", ""
	case len(b) > 4 && b[0] == 0x30:
		for _, d := range [][2]string{
			{"CERTIFICATE", "a DER X.509 certificate"}, {"CERTIFICATE REQUEST", "a DER certificate signing request"},
			{"PUBLIC KEY", "a DER public key (SPKI)"}, {"PRIVATE KEY", "a DER private key (PKCS#8)"},
		} {
			if _, err := pemKinds[d[0]].parse(b); err == nil {
				return d[1], pemKinds[d[0]].page
			}
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

// identifySizes: what a binary value of each size often is.
var identifySizes = map[int]string{
	16: "an AES-128 key, an MD5 digest or a UUID", 20: "a SHA-1 digest", 24: "an AES-192 key",
	32: "an AES-256 key or a SHA-256 digest", 48: "a SHA-384 digest", 64: "a SHA-512 digest",
}

// preview is the start of b: up to 80 characters of text, or 32 bytes as hex.
func preview(b []byte) (string, bool) {
	if t := textOf(b); t.IsText {
		n := 0
		for i := range t.Value {
			if n++; n > 80 {
				return t.Value[:i] + "…", false
			}
		}
		return t.Value, false
	}
	if len(b) > 32 {
		return hex.EncodeToString(b[:32]) + "…", true
	}
	return hex.EncodeToString(b), true
}
