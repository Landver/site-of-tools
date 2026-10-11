package ciphertools

import (
	"cmp"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"math/bits"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

// Both ops are Heavy and every cost parameter is capped, on verify too, where the
// pasted string sets them: slow on purpose, they are the cheapest way to burn the CPU (docs/03).

func init() {
	register(Op{Name: "password-hash", Path: "/password/hash", Page: "password", Fragment: "cipher/password-hashed", Heavy: true, Run: runPasswordHash,
		Fields: []Field{
			{Name: "password", Kind: KindString,
				Description: "The password to hash, read per password_enc; whitespace is part of it, and bcrypt refuses more than 72 bytes."},
			passwordEncField,
			{Name: "algo", Kind: KindEnum, Enum: []string{AlgoBcrypt, AlgoArgon2id, AlgoScrypt, AlgoPBKDF2SHA256, AlgoPBKDF2SHA512}, Default: AlgoBcrypt,
				Description: "The algorithm; each reads only its own cost fields, and argon2id is what OWASP recommends for new systems."},
			bcryptCostField, argon2MField, argon2TField, argon2PField, scryptNField, scryptRField, scryptPField, pbkdf2IterField,
		}})
	register(Op{Name: "password-verify", Path: "/password/verify", Page: "password", Fragment: "cipher/password-verified", Heavy: true, Run: runPasswordVerify,
		Fields: []Field{
			{Name: "hash", Kind: KindString, Required: true,
				Description: "The stored hash to read and check: bcrypt ($2b$…), Argon2 ($argon2id$…), scrypt ($scrypt$…) or PBKDF2 ($pbkdf2-sha256$…, Django's pbkdf2_sha256$…); other crypt(3) formats are named but not verified."},
			{Name: "password", Kind: KindString,
				Description: "The password to check against hash, read per password_enc; omit it to only read the hash's algorithm, parameters and salt."},
			passwordEncField,
		}})
}

var (
	passwordEncField = Field{Name: "password_enc", Kind: KindEnum, Enum: byteEncodings, Default: EncUTF8,
		Description: "How password is written: utf8 takes it as typed; hex, base64, base64url or base32 decode it first."}
	bcryptCostField = Field{Name: "bcrypt_cost", Kind: KindInt, Default: strconv.Itoa(bcryptDefaultCost),
		Min: ptr(bcryptMinCost), Max: ptr(bcryptMaxCost),
		Description: "bcrypt's cost when algo is bcrypt: 2^cost rounds, each step doubling the time; OWASP's minimum is 10."}
	argon2MField = Field{Name: "argon2_m", Kind: KindInt, Default: strconv.Itoa(argon2DefaultMemory),
		Min: ptr(argon2MinMemory), Max: ptr(argon2MaxMemory),
		Description: "Argon2id's memory in KiB when algo is argon2id, at least 8 per lane, e.g. 19456 (19 MiB, OWASP's minimum with argon2_t 2)."}
	argon2TField = Field{Name: "argon2_t", Kind: KindInt, Default: strconv.Itoa(argon2DefaultTime), Min: ptr(1), Max: ptr(argon2MaxTime),
		Description: "Argon2id's passes over its memory when algo is argon2id."}
	argon2PField = Field{Name: "argon2_p", Kind: KindInt, Default: strconv.Itoa(argon2DefaultThreads), Min: ptr(1), Max: ptr(argon2MaxThreads),
		Description: "Argon2id's lanes (parallelism) when algo is argon2id."}
	scryptNField = Field{Name: "scrypt_n", Kind: KindInt, Default: strconv.Itoa(1 << scryptDefaultLogN),
		Min: ptr(1 << scryptMinLogN), Max: ptr(1 << scryptMaxLogN),
		Description: "scrypt's cost N when algo is scrypt: a power of two, and 128 × N × scrypt_r bytes of memory may not pass 128 MiB."}
	scryptRField = Field{Name: "scrypt_r", Kind: KindInt, Default: strconv.Itoa(scryptDefaultR), Min: ptr(1), Max: ptr(scryptMaxR),
		Description: "scrypt's block size r when algo is scrypt."}
	scryptPField = Field{Name: "scrypt_p", Kind: KindInt, Default: strconv.Itoa(scryptDefaultP), Min: ptr(1), Max: ptr(scryptMaxP),
		Description: "scrypt's parallelism p when algo is scrypt: how many times the memory-hard step runs."}
	pbkdf2IterField = Field{Name: "pbkdf2_iterations", Kind: KindInt, Min: ptr(pbkdf2MinIter), Max: ptr(pbkdf2MaxIter),
		Description: "PBKDF2's iterations when algo is pbkdf2-sha256 or pbkdf2-sha512; the default is OWASP's minimum, 600000 and 210000 respectively."}
)

// Algorithm ids: the algo field's values, and PasswordHashInfo.Algorithm.
const (
	AlgoBcrypt       = "bcrypt"
	AlgoArgon2id     = "argon2id"
	AlgoArgon2i      = "argon2i"
	AlgoArgon2d      = "argon2d"
	AlgoScrypt       = "scrypt"
	AlgoPBKDF2SHA256 = "pbkdf2-sha256"
	AlgoPBKDF2SHA512 = "pbkdf2-sha512"
)

// The maxima bound hash and verify alike; the minima only hashing, since checking an
// old, weak hash is cheap and exactly when someone needs to be told it is weak.
const (
	bcryptMinCost, bcryptMaxCost, bcryptDefaultCost = 4, 14, 12
	bcryptMaxPassword                               = 72 // bytes bcrypt reads

	argon2MinMemory, argon2MaxMemory, argon2DefaultMemory = 8, 64 << 10, 19456 // KiB
	argon2MaxTime, argon2DefaultTime                      = 10, 2
	argon2MaxThreads, argon2DefaultThreads                = 4, 1

	scryptMinLogN, scryptMaxLogN, scryptDefaultLogN = 10, 17, 15
	scryptMaxR, scryptDefaultR                      = 16, 8
	scryptMaxP, scryptDefaultP                      = 4, 3      // p=3 at N=2^15 is an OWASP minimum; p=1 is not
	scryptMaxMemory                                 = 128 << 20 // of 128·N·r: the N and r caps alone allow 256 MiB

	pbkdf2MinIter, pbkdf2MaxIter = 1000, 2_000_000

	passwordSaltBytes, passwordKeyBytes = 16, 32
	maxStoredBytes                      = 1024 // of a salt or hash decoded from a pasted string
)

var phcB64 = base64.RawStdEncoding

type pbkdf2Hash struct {
	id, name string
	new      func() hash.Hash
	size     int
	owasp    int // OWASP's minimum iteration count
}

var pbkdf2Hashes = map[string]pbkdf2Hash{
	"sha256": {id: "sha256", name: "PBKDF2-HMAC-SHA256", new: sha256.New, size: sha256.Size, owasp: 600_000},
	"sha512": {id: "sha512", name: "PBKDF2-HMAC-SHA512", new: sha512.New, size: sha512.Size, owasp: 210_000},
}

type PasswordHashResult struct {
	Encoded        string            `json:"encoded"`
	Info           *PasswordHashInfo `json:"parsed"`
	PasswordBytes  int               `json:"password_bytes"`
	PasswordReadAs string            `json:"password_read_as"`
	TookMS         float64           `json:"took_ms"`
	Warnings       Warnings          `json:"warnings,omitempty"`

	Took string `json:"-"`
}

func runPasswordHash(in Input) (any, error) {
	raw, enc := in.Get("password"), in.Get("password_enc")
	pw, how, err := decodeInput(raw, enc)
	if err != nil {
		return nil, fmt.Errorf("password: %w", err)
	}
	algo := choice(in.Get("algo"), AlgoBcrypt)
	salt := randomBytes(passwordSaltBytes)
	derive, _, err := passwordHasher(algo, in, pw, salt)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	encoded, err := derive()
	took := time.Since(start)
	if err != nil {
		return nil, err
	}
	info, _ := ParsePasswordHash(encoded)
	r := &PasswordHashResult{Encoded: encoded, Info: info, PasswordBytes: len(pw), PasswordReadAs: how,
		TookMS: millis(took), Took: tookText(took)}
	if len(pw) == 0 {
		r.Warnings.add(LevelWarn, "The password is empty. This is its hash, but nothing should accept an empty password.")
	}
	if (enc == "" || enc == EncUTF8) && strings.TrimSpace(raw) != raw {
		r.Warnings.add(LevelInfo, "The password starts or ends with whitespace, and that whitespace is part of what was hashed.")
	}
	r.Warnings = append(r.Warnings, info.warnings...)
	if strings.HasPrefix(algo, "pbkdf2-") {
		r.Warnings.add(LevelInfo, "PBKDF2 is not memory-hard, so GPUs guess it cheaply. OWASP recommends it where FIPS 140 compliance requires it, and Argon2id otherwise.")
	}
	return r, nil
}

// passwordHasher refuses what it can before any slow work, returning the derivation and the bytes it allocates, both meaningless beside an error.
func passwordHasher(algo string, in Input, pw, salt []byte) (func() (string, error), int64, error) {
	phc := func(head string, sum []byte, err error) (string, error) {
		return head + "$" + phcB64.EncodeToString(salt) + "$" + phcB64.EncodeToString(sum), err
	}
	switch algo {
	case AlgoBcrypt:
		cost, err := intField(in, bcryptCostField)
		if err == nil && len(pw) > bcryptMaxPassword {
			chars := ""
			if n := utf8.RuneCount(pw); utf8.Valid(pw) && n != len(pw) {
				chars = fmt.Sprintf(" (%d characters; in UTF-8 some take more than one byte)", n)
			}
			err = fmt.Errorf("bcrypt: the password is %d bytes%s, and bcrypt reads at most 72. "+
				"Go's bcrypt, which this page runs, refuses rather than hash a shortened password. "+
				"Many other libraries silently use only the first 72 bytes, so every password that shares them gets the same hash. "+
				"For long passwords or passphrases use Argon2id or scrypt.", len(pw), chars)
		}
		return func() (string, error) {
			h, err := bcrypt.GenerateFromPassword(pw, cost)
			// Go writes $2a$; $2b$, what current libraries write, differs only past 255 bytes.
			return strings.Replace(string(h), "$2a$", "$2b$", 1), err
		}, 0, err

	case AlgoArgon2id:
		m, errM := intField(in, argon2MField)
		t, errT := intField(in, argon2TField)
		p, errP := intField(in, argon2PField)
		err := cmp.Or(errM, errT, errP)
		if err == nil && m < 8*p {
			err = fmt.Errorf("argon2_m: Argon2 needs at least 8 KiB per lane, so p=%d needs m of at least %d", p, 8*p)
		}
		return func() (string, error) {
			return phc(fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d", argon2.Version, m, t, p),
				argon2.IDKey(pw, salt, uint32(t), uint32(m), uint8(p), passwordKeyBytes), nil)
		}, int64(m) << 10, err

	case AlgoScrypt:
		n, errN := intField(in, scryptNField)
		if errN == nil && n&(n-1) != 0 {
			errN = fmt.Errorf("scrypt_n: N must be a power of two (1024, 2048, … 131072), got %d", n)
		}
		r, errR := intField(in, scryptRField)
		p, errP := intField(in, scryptPField)
		err := cmp.Or(errN, errR, errP)
		if err == nil && 128*n*r > scryptMaxMemory {
			err = fmt.Errorf("scrypt: N=%d with r=%d needs %s of memory (128 × N × r bytes); the limit is %s",
				n, r, bytesText(128*n*r), bytesText(scryptMaxMemory))
		}
		return func() (string, error) {
			sum, err := scrypt.Key(pw, salt, n, r, p, passwordKeyBytes)
			return phc(fmt.Sprintf("$scrypt$ln=%d,r=%d,p=%d", bits.TrailingZeros(uint(n)), r, p), sum, err)
		}, scryptMemory(n, r, p), err

	case AlgoPBKDF2SHA256, AlgoPBKDF2SHA512:
		ph := pbkdf2Hashes[strings.TrimPrefix(algo, "pbkdf2-")]
		iter, err := intField(in, pbkdf2IterField.withDefault(ph.owasp))
		return func() (string, error) {
			sum, err := pbkdf2.Key(ph.new, string(pw), salt, iter, ph.size)
			return phc(fmt.Sprintf("$%s$i=%d,l=%d", algo, iter, ph.size), sum, err)
		}, 0, err
	}
	return nil, 0, fmt.Errorf("algo: want bcrypt, argon2id, scrypt, pbkdf2-sha256 or pbkdf2-sha512, got %q", algo)
}

// scryptMemory is what x/crypto/scrypt allocates: V (128·N·r) once, as the p lanes run in turn, plus B (128·r·p) and XY (256·r).
func scryptMemory(n, r, p int) int64 { return 128 * int64(r) * int64(n+p+2) }

// MemoryCost is roughly what op name allocates: Argon2's or scrypt's memory, else 16 MiB.
func MemoryCost(name string, in Input) int64 {
	var mem int64
	switch name {
	case "password-hash":
		if _, m, err := passwordHasher(choice(in.Get("algo"), AlgoBcrypt), in, nil, nil); err == nil {
			mem = m
		}
	case "password-verify":
		if h, err := ParsePasswordHash(in.Get("hash")); err == nil && h.Unsupported == "" && h.Refused == "" && in.Get("password") != "" {
			mem = h.mem
		}
	}
	return cmp.Or(mem, 16<<20)
}

// Verify states.
const (
	PasswordMatch       = "match"
	PasswordNoMatch     = "no-match"
	PasswordUnchecked   = "unchecked"   // no password given: the hash was only read
	PasswordUnsupported = "unsupported" // a format this page names but cannot verify
	PasswordRefused     = "refused"     // parameters above this page's limits
)

type PasswordVerifyResult struct {
	Info          *PasswordHashInfo `json:"parsed"`
	State         string            `json:"state"`
	Detail        string            `json:"detail"`
	PasswordBytes int               `json:"password_bytes"`
	TookMS        float64           `json:"took_ms,omitempty"`
	Warnings      Warnings          `json:"warnings,omitempty"`

	Took string `json:"-"`
}

func runPasswordVerify(in Input) (any, error) {
	info, err := ParsePasswordHash(in.Get("hash"))
	if err != nil {
		return nil, fmt.Errorf("hash: %w", err)
	}
	raw := in.Get("password")
	pw, _, err := decodeInput(raw, in.Get("password_enc"))
	if err != nil {
		return nil, fmt.Errorf("password: %w", err)
	}
	r := &PasswordVerifyResult{Info: info, PasswordBytes: len(pw)}
	switch {
	case info.Unsupported != "":
		r.State, r.Detail = PasswordUnsupported, info.Unsupported
	case info.Refused != "":
		r.State, r.Detail = PasswordRefused, info.Refused
	case raw == "":
		r.State, r.Detail = PasswordUnchecked, "Read the hash only. Enter a password to check it against this hash."
	default:
		start := time.Now()
		ok, err := info.check(pw)
		took := time.Since(start)
		if err != nil {
			return nil, err
		}
		r.TookMS, r.Took = millis(took), tookText(took)
		r.State, r.Detail = PasswordNoMatch, "The password does not produce this hash. Check for a stray space or newline, letter case, and how the password is encoded."
		if ok {
			r.State, r.Detail = PasswordMatch, "The password produces this hash. The comparison ran in constant time."
		}
		if info.Algorithm == AlgoBcrypt && len(pw) > bcryptMaxPassword {
			r.Warnings.add(LevelWarn, fmt.Sprintf(
				"The password is %d bytes and bcrypt reads only the first 72, so the rest played no part: any password with the same first 72 bytes gets the same answer.", len(pw)))
		}
	}
	r.Warnings = append(r.Warnings, info.warnings...)
	return r, nil
}

// PasswordHashInfo is what a stored password hash says about itself.
type PasswordHashInfo struct {
	// Algorithm is an Algo* id, or a legacy crypt(3) name (md5crypt, sha512crypt, …).
	Algorithm   string `json:"algorithm"`
	Name        string `json:"name"`
	Format      string `json:"format"`
	Variant     string `json:"variant,omitempty"`
	Params      []Row  `json:"params,omitempty"`
	SaltBytes   int    `json:"salt_bytes"`
	HashBytes   int    `json:"hash_bytes"`
	Unsupported string `json:"unsupported,omitempty"` // why a recognised format can't be verified here
	Refused     string `json:"refused,omitempty"`     // which parameter is above this page's limits

	warnings Warnings
	check    func(pw []byte) (bool, error)
	mem      int64 // bytes check allocates (Argon2 and scrypt)
}

// saltWarning: 16 bytes is the floor RFC 9106 and NIST SP 800-132 both set.
func (h *PasswordHashInfo) saltWarning() {
	if h.SaltBytes < 16 {
		h.warnings.add(LevelWarn, fmt.Sprintf("The salt is %d bytes; 16 is the usual minimum.", h.SaltBytes))
	}
}

// part is one $-separated field of a hash string, with its offset in the input.
type part struct {
	s  string
	at int
}

func partAt(p []part, i int) part {
	if i < len(p) {
		return p[i]
	}
	return part{}
}

// ParsePasswordHash reads bcrypt, PHC strings (Argon2, scrypt, PBKDF2) and passlib's and Django's forms,
// and names the crypt(3) formats it can't verify. Errors give offsets counted in s.
func ParsePasswordHash(s string) (*PasswordHashInfo, error) {
	t := strings.TrimLeft(s, " \t\r\n")
	at := len(s) - len(t)
	if t = strings.TrimRight(t, " \t\r\n"); t == "" {
		return nil, errors.New("no hash given")
	}
	var p []part
	for _, f := range strings.Split(t, "$") {
		p = append(p, part{f, at})
		at += len(f) + 1
	}
	switch id := partAt(p, 1).s; {
	case strings.HasPrefix(t, "pbkdf2_sha256$"):
		return parseDjangoPBKDF2(p)
	case !strings.HasPrefix(t, "$"):
	case bcryptVariants[id] != "":
		return parseBcrypt(t, p)
	case strings.HasPrefix(id, "argon2"):
		return parseArgon2(p)
	case id == "scrypt":
		return parseScrypt(p)
	case id == AlgoPBKDF2SHA256 || id == AlgoPBKDF2SHA512:
		return parsePBKDF2(p)
	case legacyCrypt[id].name != "":
		return parseLegacy(p), nil
	}
	hint := ""
	if allHex(t) && slices.Contains([]int{32, 40, 56, 64, 96, 128}, len(t)) {
		hint = fmt.Sprintf(" %d hex characters looks like a plain digest (MD5, SHA-1, SHA-256 …), which is not a password hash: it has no salt and no cost. The Hash page computes those.", len(t))
	}
	return nil, fmt.Errorf("%w%s", errUnknownHash, hint)
}

var errUnknownHash = errors.New("not a password hash format this page knows. It reads bcrypt ($2a$, $2b$, $2y$), Argon2 ($argon2id$, $argon2i$), " +
	"scrypt ($scrypt$) and PBKDF2 ($pbkdf2-sha256$, $pbkdf2-sha512$, Django's pbkdf2_sha256$), " +
	"and names the crypt(3) formats $1$, $apr1$, $5$, $6$, $y$, $7$ and phpass ($P$).")

// ---- bcrypt ----

const bcryptAlphabet = "./" + alnum

// bcryptVariants all verify alike; they differ in which buggy implementation, if any, made the hash.
var bcryptVariants = map[string]string{
	"2":  "The original prefix, rarely seen now. Verified like $2a$.",
	"2a": "The long-standing prefix. Same output as $2b$ for any password bcrypt reads in full.",
	"2b": "OpenBSD's 2014 prefix, after a fix for passwords over 255 bytes. What current libraries write.",
	"2x": "crypt_blowfish's marker for hashes made by its pre-2011 bug with non-ASCII bytes.",
	"2y": "crypt_blowfish's and PHP's prefix for correct hashes. The same algorithm as $2b$.",
}

func parseBcrypt(t string, p []part) (*PasswordHashInfo, error) {
	id := p[1].s
	if len(p) != 4 {
		return nil, fmt.Errorf("bcrypt: want $%s$<cost>$<22 characters of salt, then 31 of hash>, found %d $-separated fields", id, len(p)-1)
	}
	cp, body := p[2], p[3]
	if len(cp.s) != 2 || !allDigits(cp.s) {
		return nil, fmt.Errorf("bcrypt: the cost at offset %d must be two digits, found %q", cp.at, cp.s)
	}
	cost, _ := strconv.Atoi(cp.s)
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return nil, fmt.Errorf("bcrypt: cost %d at offset %d is outside bcrypt's range of 04 to 31", cost, cp.at)
	}
	if i := len(body.s) - len(strings.TrimLeft(body.s, bcryptAlphabet)); i < len(body.s) {
		return nil, fmt.Errorf("bcrypt: %s at offset %d is not in bcrypt's base64 alphabet (./A-Za-z0-9)", charAt(body.s, i), body.at+i)
	}
	if len(body.s) != 53 {
		return nil, fmt.Errorf("bcrypt: after the cost come 53 characters, 22 of salt and 31 of hash; found %d", len(body.s))
	}
	h := &PasswordHashInfo{
		Algorithm: AlgoBcrypt, Name: "bcrypt", Format: "Modular Crypt Format", Variant: "$" + id + "$",
		SaltBytes: 16, HashBytes: 23,
		Params: []Row{
			{Name: "variant", Value: "$" + id + "$", Meaning: bcryptVariants[id]},
			{Name: "cost", Value: cp.s, Meaning: fmt.Sprintf("2^%d = %s rounds of the key setup. Each step doubles the time.", cost, thousands(1<<cost))},
			{Name: "salt", Value: body.s[:22], Meaning: "16 bytes, in bcrypt's own base64"},
		},
	}
	if cost > bcryptMaxCost {
		h.Refused = fmt.Sprintf("Cost %d is above this page's limit of %d. Each step doubles the work, and the limit keeps one request from tying up the server.", cost, bcryptMaxCost)
	}
	if cost < 10 {
		h.warnings.add(LevelWarn, fmt.Sprintf("Cost %d is below OWASP's minimum of 10.", cost))
	}
	if id == "2x" {
		h.warnings.add(LevelWarn, "A $2x$ hash came from crypt_blowfish's pre-2011 bug. This page computes correct bcrypt, which matches it only when the password is plain ASCII.")
	}
	h.check = func(pw []byte) (bool, error) {
		err := bcrypt.CompareHashAndPassword([]byte(t), pw)
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return err == nil, err
	}
	return h, nil
}

// ---- PHC helpers ----

// param is one name=value pair of a PHC parameter list; at is the value's offset.
type param struct {
	k, v string
	at   int
}

func phcParams(pt part, algo string) ([]param, error) {
	if pt.s == "" {
		return nil, fmt.Errorf("%s: no parameters at offset %d", algo, pt.at)
	}
	var out []param
	at := pt.at
	for _, f := range strings.Split(pt.s, ",") {
		k, v, ok := strings.Cut(f, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("%s: %q at offset %d is not name=value", algo, f, at)
		}
		out = append(out, param{k, v, at + len(k) + 1})
		at += len(f) + 1
	}
	return out, nil
}

// passwordInts reads params in order: each must be one of names, with a whole number >= least.
func passwordInts(params []param, algo string, least int, names ...string) (map[string]int, error) {
	vals := map[string]int{}
	for _, x := range params {
		if !slices.Contains(names, x.k) {
			return nil, fmt.Errorf("%s: unknown parameter %q at offset %d", algo, x.k, x.at-len(x.k)-1)
		}
		n, err := x.int(algo)
		if err != nil {
			return nil, err
		}
		if n < least {
			return nil, fmt.Errorf("%s: %s=%d at offset %d; it must be at least %d", algo, x.k, n, x.at, least)
		}
		vals[x.k] = n
	}
	return vals, nil
}

func (x param) int(algo string) (int, error) {
	if len(x.v) > 10 || !allDigits(x.v) {
		return 0, fmt.Errorf("%s: %s=%q at offset %d is not a whole number", algo, x.k, x.v, x.at)
	}
	n, _ := strconv.Atoi(x.v)
	return n, nil
}

// phcDecode reads a salt or hash: standard base64 without padding. A trailing '=' is
// tolerated and '.' read as '+' (passlib's "adapted base64"); neither means anything else here.
func phcDecode(pt part, what string) ([]byte, error) {
	s := strings.TrimRight(pt.s, "=")
	if s == "" {
		return nil, fmt.Errorf("%s is empty (offset %d)", what, pt.at)
	}
	if i := len(s) - len(strings.TrimLeft(s, bcryptAlphabet+"+")); i < len(s) {
		return nil, fmt.Errorf("%s: %s at offset %d is not base64", what, charAt(s, i), pt.at+i)
	}
	b, err := phcB64.DecodeString(strings.ReplaceAll(s, ".", "+"))
	if err != nil {
		return nil, fmt.Errorf("%s at offset %d: %d characters is not a whole number of base64 groups", what, pt.at, len(s))
	}
	if len(b) > maxStoredBytes {
		return nil, fmt.Errorf("%s is %d bytes; this page reads up to %d", what, len(b), maxStoredBytes)
	}
	return b, nil
}

func passwordSaltHash(salt, sum part, algo string) ([]byte, []byte, error) {
	s, errS := phcDecode(salt, algo+" salt")
	h, errH := phcDecode(sum, algo+" hash")
	return s, h, cmp.Or(errS, errH)
}

// ---- Argon2 ----

// owaspArgon2 lists OWASP's equivalent Argon2id minimums as (m KiB, t).
var owaspArgon2 = [][2]int{{47104, 1}, {19456, 2}, {12288, 3}, {9216, 4}, {7168, 5}}

func parseArgon2(p []part) (*PasswordHashInfo, error) {
	id := p[1].s
	name, ok := map[string]string{AlgoArgon2id: "Argon2id", AlgoArgon2i: "Argon2i", AlgoArgon2d: "Argon2d"}[id]
	if !ok {
		return nil, fmt.Errorf("unknown Argon2 variant %q at offset %d: there are argon2id, argon2i and argon2d", id, p[1].at)
	}
	rest, version := p[2:], 0x10 // what a PHC string without v= means
	if len(rest) > 0 && strings.HasPrefix(rest[0].s, "v=") {
		v, err := param{"v", rest[0].s[2:], rest[0].at + 2}.int(id)
		if err != nil {
			return nil, err
		}
		if v != 0x10 && v != 0x13 {
			return nil, fmt.Errorf("%s: unknown version v=%d at offset %d; Argon2 has 16 (1.0) and 19 (1.3)", id, v, rest[0].at+2)
		}
		version, rest = v, rest[1:]
	}
	if len(rest) != 3 {
		return nil, fmt.Errorf("%s: want $%s$v=19$m=…,t=…,p=…$<salt>$<hash>", id, id)
	}
	params, err := phcParams(rest[0], id)
	if err != nil {
		return nil, err
	}
	h := &PasswordHashInfo{Algorithm: id, Name: name, Format: "PHC string"}
	extra := func(x param) bool { return x.k == "keyid" || x.k == "data" }
	for _, x := range params {
		if extra(x) {
			h.Unsupported = fmt.Sprintf("This hash carries %s=, extra input Argon2 mixes in, which this page can't supply.", x.k)
		}
	}
	vals, err := passwordInts(slices.DeleteFunc(params, extra), id, 0, "m", "t", "p")
	if err != nil {
		return nil, err
	}
	for _, k := range []string{"m", "t", "p"} {
		if _, ok := vals[k]; !ok {
			return nil, fmt.Errorf("%s: the parameters at offset %d have no %s=", id, rest[0].at, k)
		}
	}
	m, t, lanes := vals["m"], vals["t"], vals["p"]
	switch {
	case t < 1:
		return nil, fmt.Errorf("%s: t=0; Argon2 makes at least one pass", id)
	case lanes < 1:
		return nil, fmt.Errorf("%s: p=0; Argon2 needs at least one lane", id)
	case m < 8*lanes:
		return nil, fmt.Errorf("%s: m=%d is below Argon2's minimum of 8 KiB per lane (%d for p=%d)", id, m, 8*lanes, lanes)
	}
	salt, sum, err := passwordSaltHash(rest[1], rest[2], id)
	if err != nil {
		return nil, err
	}
	if len(sum) < 4 {
		return nil, fmt.Errorf("%s: the hash is %d bytes; Argon2 outputs at least 4", id, len(sum))
	}
	h.SaltBytes, h.HashBytes, h.mem = len(salt), len(sum), int64(m)<<10
	h.Params = []Row{
		{Name: "v", Value: strconv.Itoa(version), Meaning: map[int]string{0x10: "Argon2 version 1.0", 0x13: "Argon2 version 1.3"}[version]},
		{Name: "m", Value: strconv.Itoa(m), Meaning: "memory in KiB: " + kibText(m)},
		{Name: "t", Value: strconv.Itoa(t), Meaning: "passes over that memory"},
		{Name: "p", Value: strconv.Itoa(lanes), Meaning: "lanes (parallelism)"},
	}

	switch {
	case h.Unsupported != "":
	case id == AlgoArgon2d:
		h.Unsupported = "Go's argon2 package has no Argon2d, so this page can't check it. Argon2d's memory access depends on the password, which is why RFC 9106 recommends Argon2id for passwords."
	case version != 0x13:
		h.Unsupported = "This is Argon2 version 16 (1.0); a string without v= means that version. Go's argon2 package implements only version 19 (1.3)."
	case m > argon2MaxMemory:
		h.Refused = fmt.Sprintf("m=%d KiB (%s) is above this page's limit of %d KiB (%s).", m, kibText(m), argon2MaxMemory, kibText(argon2MaxMemory))
	case t > argon2MaxTime:
		h.Refused = fmt.Sprintf("t=%d is above this page's limit of %d passes.", t, argon2MaxTime)
	case lanes > argon2MaxThreads:
		h.Refused = fmt.Sprintf("p=%d is above this page's limit of %d lanes.", lanes, argon2MaxThreads)
	}
	if id == AlgoArgon2id && !slices.ContainsFunc(owaspArgon2, func(c [2]int) bool { return m >= c[0] && t >= c[1] }) {
		h.warnings.add(LevelWarn, "Below OWASP's minimum for Argon2id: m=19456 (19 MiB) with t=2, or an equivalent such as m=47104 with t=1, or m=12288 with t=3.")
	}
	if id == AlgoArgon2i {
		h.warnings.add(LevelInfo, "Argon2i. RFC 9106 and OWASP recommend Argon2id for password hashing.")
	}
	h.saltWarning()
	key := argon2.Key
	if id == AlgoArgon2id {
		key = argon2.IDKey
	}
	h.check = func(pw []byte) (bool, error) {
		return subtle.ConstantTimeCompare(key(pw, salt, uint32(t), uint32(m), uint8(lanes), uint32(len(sum))), sum) == 1, nil
	}
	return h, nil
}

// ---- scrypt ----

// owaspScrypt lists OWASP's equivalent scrypt minimums as (N, p), all at r=8.
var owaspScrypt = [][2]int{{1 << 17, 1}, {1 << 16, 2}, {1 << 15, 3}, {1 << 14, 5}, {1 << 13, 10}}

func parseScrypt(p []part) (*PasswordHashInfo, error) {
	if len(p) != 5 {
		return nil, errors.New("scrypt: want $scrypt$ln=…,r=…,p=…$<salt>$<hash>")
	}
	params, err := phcParams(p[2], "scrypt")
	if err != nil {
		return nil, err
	}
	vals, err := passwordInts(params, "scrypt", 1, "ln", "r", "p")
	if err != nil {
		return nil, err
	}
	for _, k := range []string{"ln", "r", "p"} {
		if _, ok := vals[k]; !ok {
			return nil, fmt.Errorf("scrypt: the parameters at offset %d have no %s=", p[2].at, k)
		}
	}
	ln, r, par := vals["ln"], vals["r"], vals["p"]
	if ln > 62 {
		return nil, fmt.Errorf("scrypt: ln=%d is not a usable cost; N = 2^ln", ln)
	}
	salt, sum, err := passwordSaltHash(p[3], p[4], "scrypt")
	if err != nil {
		return nil, err
	}
	n := 1 << ln
	h := &PasswordHashInfo{Algorithm: AlgoScrypt, Name: "scrypt", Format: "passlib / PHC string",
		SaltBytes: len(salt), HashBytes: len(sum)}
	mem := "128 × N × r bytes"
	if ln <= scryptMaxLogN+4 && r <= 1024 {
		mem = fmt.Sprintf("memory is 128 × N × r bytes: %s", bytesText(128*n*r))
	}
	h.Params = []Row{
		{Name: "ln", Value: strconv.Itoa(ln), Meaning: fmt.Sprintf("N = 2^%d = %s, the cost; %s", ln, thousands(n), mem)},
		{Name: "r", Value: strconv.Itoa(r), Meaning: "block size"},
		{Name: "p", Value: strconv.Itoa(par), Meaning: "parallelism: how many times the memory-hard step runs"},
	}
	switch {
	case ln > scryptMaxLogN:
		h.Refused = fmt.Sprintf("N=2^%d is above this page's limit of 2^%d.", ln, scryptMaxLogN)
	case r > scryptMaxR:
		h.Refused = fmt.Sprintf("r=%d is above this page's limit of %d.", r, scryptMaxR)
	case par > scryptMaxP:
		h.Refused = fmt.Sprintf("p=%d is above this page's limit of %d.", par, scryptMaxP)
	case 128*n*r > scryptMaxMemory:
		h.Refused = fmt.Sprintf("N=2^%d with r=%d needs %s of memory; this page's limit is %s.", ln, r, bytesText(128*n*r), bytesText(scryptMaxMemory))
	default:
		h.mem = scryptMemory(n, r, par) // within the caps only: past them 128·N·r can overflow
	}
	if !meetsOWASPScrypt(n, r, par) {
		h.warnings.add(LevelWarn, "Below OWASP's minimum for scrypt: N=2^17 with r=8 and p=1, or an equivalent such as N=2^16 with p=2, or N=2^15 with p=3.")
	}
	h.saltWarning()
	h.check = func(pw []byte) (bool, error) {
		got, err := scrypt.Key(pw, salt, n, r, par, len(sum))
		return subtle.ConstantTimeCompare(got, sum) == 1, err
	}
	return h, nil
}

// meetsOWASPScrypt: N·r and N·r·p reach some OWASP line's; past the first line's memory any p does, and the early true keeps n·r·p from overflowing.
func meetsOWASPScrypt(n, r, p int) bool {
	return n >= 1<<20 || r >= 1<<20 || n*r >= 1<<17*8 || slices.ContainsFunc(owaspScrypt, func(c [2]int) bool {
		return n*r >= c[0]*8 && n*r*p >= c[0]*8*c[1]
	})
}

// ---- PBKDF2 ----

func parsePBKDF2(p []part) (*PasswordHashInfo, error) {
	id := p[1].s
	if len(p) != 5 {
		return nil, fmt.Errorf("%s: want $%s$i=…,l=…$<salt>$<hash>", id, id)
	}
	vals, format := map[string]int{}, "PHC string"
	if allDigits(p[2].s) {
		// passlib writes the bare iteration count and its adapted base64.
		n, err := param{"rounds", p[2].s, p[2].at}.int(id)
		if err != nil {
			return nil, err
		}
		vals["i"], format = n, "passlib"
	} else {
		params, err := phcParams(p[2], id)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(p[2].s, "i=") && !strings.Contains(p[2].s, ",i=") {
			return nil, fmt.Errorf("%s: the parameters at offset %d have no i= (iterations)", id, p[2].at)
		}
		if vals, err = passwordInts(params, id, 0, "i", "l"); err != nil {
			return nil, err
		}
	}
	salt, sum, err := passwordSaltHash(p[3], p[4], id)
	if err != nil {
		return nil, err
	}
	if l := vals["l"]; l != 0 && l != len(sum) {
		return nil, fmt.Errorf("%s: l=%d, but the hash is %d bytes", id, l, len(sum))
	}
	return pbkdf2Info(pbkdf2Hashes[strings.TrimPrefix(id, "pbkdf2-")], format, vals["i"], salt, sum)
}

// parseDjangoPBKDF2 reads pbkdf2_sha256$<iterations>$<salt>$<hash>: the salt used as text, the hash padded base64.
func parseDjangoPBKDF2(p []part) (*PasswordHashInfo, error) {
	if len(p) != 4 {
		return nil, errors.New("pbkdf2_sha256: want Django's pbkdf2_sha256$<iterations>$<salt>$<hash>")
	}
	iter, err := param{"iterations", p[1].s, p[1].at}.int("pbkdf2_sha256")
	if err != nil {
		return nil, err
	}
	if p[2].s == "" {
		return nil, fmt.Errorf("pbkdf2_sha256: the salt at offset %d is empty", p[2].at)
	}
	sum, err := phcDecode(p[3], "pbkdf2_sha256 hash")
	if err != nil {
		return nil, err
	}
	return pbkdf2Info(pbkdf2Hashes["sha256"], "Django", iter, []byte(p[2].s), sum)
}

func pbkdf2Info(ph pbkdf2Hash, format string, iter int, salt, sum []byte) (*PasswordHashInfo, error) {
	if iter < 1 {
		return nil, errors.New("pbkdf2: the iteration count is 0; PBKDF2 needs at least 1")
	}
	h := &PasswordHashInfo{Algorithm: "pbkdf2-" + ph.id, Name: ph.name, Format: format,
		SaltBytes: len(salt), HashBytes: len(sum)}
	blocks := (len(sum) + ph.size - 1) / ph.size
	h.Params = []Row{
		{Name: "i", Value: strconv.Itoa(iter), Meaning: fmt.Sprintf("%s iterations of HMAC-%s", thousands(iter), strings.ToUpper(ph.id))},
		{Name: "l", Value: strconv.Itoa(len(sum)), Meaning: "output length in bytes"},
	}
	if iter > pbkdf2MaxIter/blocks {
		more := ""
		if blocks > 1 {
			more = fmt.Sprintf(" times %d, because the output is %d digests long,", blocks, blocks)
		}
		h.Refused = fmt.Sprintf("%s iterations%s is above this page's limit of %s.", thousands(iter), more, thousands(pbkdf2MaxIter))
	}
	if iter < ph.owasp {
		h.warnings.add(LevelWarn, fmt.Sprintf("%s iterations is below OWASP's minimum of %s for %s.", thousands(iter), thousands(ph.owasp), ph.name))
	}
	h.saltWarning()
	h.check = func(pw []byte) (bool, error) {
		got, err := pbkdf2.Key(ph.new, string(pw), salt, iter, len(sum))
		return subtle.ConstantTimeCompare(got, sum) == 1, err
	}
	return h, nil
}

// ---- crypt(3) formats named but not verified ----

// cryptAlphabet is crypt(3)'s base64 order, which phpass also counts rounds in.
const cryptAlphabet = "./0123456789" + letters

var legacyCrypt = map[string]struct{ algo, name, note string }{
	"1":    {"md5crypt", "md5crypt", "MD5 with a fixed 1,000 rounds: fast to guess on a GPU. Rehash these with Argon2id or bcrypt."},
	"apr1": {"apr1", "Apache MD5 (apr1)", "MD5 with a fixed 1,000 rounds, as htpasswd -m writes it: fast to guess on a GPU. htpasswd -B writes bcrypt."},
	"5":    {"sha256crypt", "SHA-256 crypt", ""},
	"6":    {"sha512crypt", "SHA-512 crypt", ""},
	"y":    {"yescrypt", "yescrypt", ""},
	"7":    {"scrypt-crypt", "scrypt ($7$ encoding)", ""},
	"P":    {"phpass", "phpass (WordPress, phpBB)", "MD5-based: fast to guess on a GPU."},
	"H":    {"phpass", "phpass (phpBB)", "MD5-based: fast to guess on a GPU."},
}

func parseLegacy(p []part) *PasswordHashInfo {
	id := p[1].s
	lc := legacyCrypt[id]
	h := &PasswordHashInfo{Algorithm: lc.algo, Name: lc.name, Format: "crypt(3)", Variant: "$" + id + "$",
		Unsupported: lc.name + " is a legacy crypt(3) format. This page recognises it but doesn't verify it: neither Go's standard library nor x/crypto implements it."}
	switch id {
	case "1", "apr1", "5", "6":
		rest, rounds, meaning := p[2:], "1000", "fixed"
		if id == "5" || id == "6" {
			rounds, meaning = "5000", "the default, as the string has no rounds="
			if r, ok := strings.CutPrefix(partAt(rest, 0).s, "rounds="); ok {
				rounds, meaning, rest = r, "from rounds=", rest[1:]
			}
		}
		salt, sum := partAt(rest, 0).s, partAt(rest, 1).s
		h.SaltBytes, h.HashBytes = len(salt), len(sum)*6/8
		h.Params = []Row{{Name: "rounds", Value: rounds, Meaning: meaning}, {Name: "salt", Value: salt, Meaning: "used as the characters themselves"}}
	case "P", "H":
		// $P$, one character for log2(rounds), 8 of salt, 22 of hash.
		if body := partAt(p, 2).s; len(body) >= 9 {
			if n := strings.IndexByte(cryptAlphabet, body[0]); n >= 7 && n <= 30 {
				h.Params = []Row{{Name: "rounds", Value: thousands(1 << n), Meaning: fmt.Sprintf("2^%d, from the %q after the prefix", n, body[0])}}
			}
			h.SaltBytes, h.HashBytes = 8, len(body[9:])*6/8
		}
		h.Format = "phpass portable hash"
		h.Unsupported = "phpass is the portable MD5-based hash older WordPress and phpBB installs store. This page recognises it but doesn't verify it."
	case "y", "7":
		h.Params = []Row{{Name: "params", Value: partAt(p, 2).s, Meaning: "encoded parameters"}}
		h.Unsupported = "yescrypt is a crypt(3) format, the /etc/shadow default on many current Linux distributions. This page recognises it but can't verify it: neither Go's standard library nor x/crypto implements it."
		if id == "7" {
			h.Unsupported = "This is scrypt in the $7$ crypt(3) encoding. This page verifies scrypt in the $scrypt$ (passlib) form only."
		}
	}
	if lc.note != "" {
		h.warnings.add(LevelWarn, lc.note)
	}
	return h
}

func kibText(kib int) string { return bytesText(kib << 10) }
