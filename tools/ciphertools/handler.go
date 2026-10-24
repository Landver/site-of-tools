//go:build !js

// The package's one server-only file: the tag keeps Echo, platform and the Mongo driver out of the wasm binary.

package ciphertools

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"

	"github.com/Landver/site-of-tools/platform"
)

// page is one sub-nav entry, in nav order, and the GET route serving its shell "cipher/<Key>".
type page struct {
	Key, Path, Label, Tip, Title, Desc string
}

var pages = []page{
	{Key: "jwt", Path: "/", Label: "JWT", Tip: "Decode, verify and sign JSON Web Tokens",
		Title: "JWT decoder, verifier and signer — Cipher Tools",
		Desc:  "Decode a JWT, verify its signature with a secret, PEM or JWKS, and sign new ones: HS, RS, PS, ES and EdDSA. Runs in your browser, so the token never leaves the page. Loud about unverified tokens, alg none and algorithm confusion."},
	{Key: "hash", Path: "/hash", Label: "Hash", Tip: "Hash text or a file, check a checksum",
		Title: "Hash calculator and checksum checker: MD5, SHA-256, SHA-3, BLAKE2 — Cipher Tools",
		Desc:  "Hash text or a file with MD5, SHA-1, SHA-2, SHA-3, BLAKE2, Keccak-256, CRC32 and Adler-32 at once, as hex and base64. Paste a checksum to see which algorithm it matches. Flags trailing newlines, CRLF and BOMs. Runs in your browser."},
	{Key: "hmac", Path: "/hmac", Label: "HMAC", Tip: "Compute an HMAC, check a webhook signature",
		Title: "HMAC generator and webhook signature checker — Cipher Tools",
		Desc:  "Compute HMAC-SHA256, SHA-512, SHA-1, MD5 and SHA-3 at once with a key as text, hex or base64, and verify a webhook signature (GitHub, Stripe, Slack) in constant time. Runs in your browser, so the key never leaves the page."},
	{Key: "password", Path: "/password", Label: "Passwords", Tip: "Hash and check passwords: bcrypt, Argon2id, scrypt, PBKDF2",
		Title: "bcrypt, Argon2, scrypt and PBKDF2 password hash generator and checker — Cipher Tools",
		Desc:  "Hash a password with bcrypt, Argon2id, scrypt or PBKDF2, or paste a stored hash to read its algorithm, cost and salt and check a password against it. Warns about bcrypt's 72-byte limit and weak parameters. Runs in your browser."},
	{Key: "encrypt", Path: "/encrypt", Label: "Encrypt", Tip: "Encrypt and decrypt with AES-GCM, ChaCha20-Poly1305 or AES-CBC",
		Title: "AES-GCM, ChaCha20-Poly1305 and AES-CBC encryption and decryption — Cipher Tools",
		Desc:  "Encrypt or decrypt with AES-GCM, ChaCha20-Poly1305 or AES-CBC using a hex or base64 key, a random nonce and optional AAD. The output layout (nonce, ciphertext, tag) is stated so other code can read it. Runs in your browser, so the key never leaves the page."},
	{Key: "keys", Path: "/keys", Label: "Keys", Tip: "Generate and convert keys: PEM, JWK, OpenSSH",
		Title: "RSA, ECDSA and Ed25519 key generator, PEM to JWK and OpenSSH converter — Cipher Tools",
		Desc:  "Generate a test RSA, ECDSA or Ed25519 key pair, or paste a key to convert it between PEM (PKCS#8, PKCS#1, SPKI), JWK and OpenSSH. Shows the SPKI and OpenSSH SHA256 fingerprints and the RFC 7638 JWK thumbprint. Runs in your browser."},
	{Key: "cert", Path: "/cert", Label: "Certs", Tip: "Decode certificates, chains and CSRs",
		Title: "X.509 certificate decoder, chain order checker and CSR reader — Cipher Tools",
		Desc:  "Decode a certificate, chain or CSR from PEM or DER: SANs, validity, issuer, key, usages and SHA-256 fingerprints. Checks chain order and each signature, flags expiry, SHA-1 and CN-only certificates, and tests whether a key matches. Runs in your browser."},
	{Key: "totp", Path: "/totp", Label: "TOTP", Tip: "TOTP and HOTP codes, otpauth:// URIs",
		Title: "TOTP and HOTP code generator, otpauth:// URI reader and builder — Cipher Tools",
		Desc:  "Get the previous, current and next TOTP or HOTP code from a base32 secret or an otpauth:// URI, with a countdown. Check a code within one step either side, and build an otpauth:// URI. SHA1, SHA256 and SHA512. Runs in your browser."},
	{Key: "random", Path: "/random", Label: "Random", Tip: "Random tokens, passwords and UUIDs",
		Title: "Random token, password and UUID v4 / v7 generator — Cipher Tools",
		Desc:  "Generate random tokens as hex, base64url or letters and digits, passwords with the character sets you pick and their exact entropy, and UUID v4 or v7 in bulk. Cryptographic randomness with no modulo bias, made in your browser."},
	{Key: "encode", Path: "/encode", Label: "Encode", Tip: "Bytes as text, hex, base64 and base32; Basic auth",
		Title: "Base64, hex and base32 converter, Basic auth header — Cipher Tools",
		Desc:  "Convert bytes between UTF-8 text, hex, base64, base64url and base32, with the base64 variant named and bad characters pointed at by offset. Build and decode HTTP Basic auth headers. Runs in your browser."},
	{Key: "identify", Path: "/identify", Label: "Identify", Tip: "What is this string? Hashes, tokens, keys, encodings",
		Title: "Hash, token, key and encoding identifier with hashcat modes — Cipher Tools",
		Desc:  "Paste a string to see what it could be: hash types with hashcat modes, JWT, JWE, PEM keys and certificates, SSH keys, bcrypt and Argon2 hashes, UUIDs, otpauth:// URIs, base64, hex or base32. Ranked candidates, each linked to the page that reads it."},
	{Key: "dpop", Path: "/dpop", Label: "DPoP", Tip: "RFC 9449 DPoP proof JWT generator and verifier",
		Title: "RFC 9449 DPoP proof generator and verifier — Cipher Tools",
		Desc:  "Generate and verify OAuth 2.0 / 2.1 RFC 9449 DPoP proof JWTs: inspect embedded public JWKs, compute RFC 7638 jkt thumbprints, verify ath access token hashes, and test HTTP method and URI bindings. Cryptography runs in your browser."},
	{Key: "pkce", Path: "/pkce", Label: "PKCE", Tip: "RFC 7636 PKCE code_verifier and code_challenge (S256)",
		Title: "PKCE code_verifier and code_challenge generator and verifier — Cipher Tools",
		Desc:  "Generate cryptographic PKCE code_verifier and S256 code_challenge for OAuth 2.1 and OpenID Connect. Verify challenges in your browser with zero network transmission."},
}

const (
	heavyBudget = 256 << 20
	maxBody     = 8 << 20 // every POST, uploads included; a file hashed in the browser never travels
)

type Limits struct {
	Pure, Heavy platform.Limiter
	Engine      platform.Limiter // pulls of the multi-MB wasm engine, which a browser keeps
	HeavyCap    *platform.Cap    // a byte budget; each Heavy op holds HeavyWeight of it
}

func NewLimits() *Limits {
	return &Limits{
		Pure:     platform.NewLimiter(10, 50),
		Heavy:    platform.NewLimiter(1, 5),
		Engine:   platform.NewLimiter(1, 10),
		HeavyCap: platform.NewCap(heavyBudget),
	}
}

// HeavyWeight is MemoryCost within [1 MiB, the budget], so no input is refused forever.
func HeavyWeight(name string, in Input) int64 {
	return min(max(MemoryCost(name, in), 1<<20), heavyBudget)
}

type handler struct {
	base string
	lim  *Limits
}

// Register serves a GET shell per page and a POST per op, answering JSON or, with JavaScript off, the page.
// Ops read the body only: a secret in a URL lands in history, Referer and logs. lim nil means fresh limits.
func Register(e *echo.Echo, base string, static fs.FS, lim *Limits) {
	if lim == nil {
		lim = NewLimits()
	}
	h := &handler{base: base, lim: lim}
	e.Use(immutableEngine)
	e.GET(enginePath, (&engine{static: static}).serve, platform.RateLimit(lim.Engine, nil, limited))
	for _, p := range pages {
		e.GET(p.Path, func(c *echo.Context) error { return c.Render(http.StatusOK, "cipher/"+p.Key, h.vm(p)) })
	}
	rate := map[bool]echo.MiddlewareFunc{false: platform.RateLimit(lim.Pure, nil, limited), true: platform.RateLimit(lim.Heavy, nil, limited)}
	for _, op := range Ops() {
		e.POST(op.Path, h.op(op), middleware.BodyLimit(maxBody), rate[op.Heavy])
	}
}

// immutableEngine lets browsers keep the engine: Cloudflare skips .wasm and embeds have no Last-Modified.
func immutableEngine(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		r := c.Request()
		if (strings.HasPrefix(r.URL.Path, "/static/wasm/") || strings.HasPrefix(r.URL.Path, "/static/js/cipher")) &&
			r.URL.Query().Get("v") != "" {
			c.Response().Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		return next(c)
	}
}

// enginePath is served here, not by /static: Echo prefers the exact route to NewApp's wildcard, and
// platform's gzip middleware skips it (platform/app.go), so the bytes written are the bytes sent.
const enginePath = "/static/wasm/cipher.wasm"

const engineFile = "wasm/cipher.wasm"

// engine gzips the ~13 MB engine once, not per request (~0.25 s CPU each); size+mtime keying catches a rebuild.
type engine struct {
	static fs.FS
	mu     sync.Mutex
	key    string
	gz     []byte
}

func (en *engine) serve(c *echo.Context) error {
	info, err := fs.Stat(en.static, engineFile)
	if err != nil {
		return echo.ErrNotFound
	}
	c.Response().Header().Add(echo.HeaderVary, echo.HeaderAcceptEncoding)
	gz := strings.Contains(c.Request().Header.Get(echo.HeaderAcceptEncoding), "gzip")
	body, err := en.read(info, gz)
	if err != nil {
		return err
	}
	if gz {
		c.Response().Header().Set(echo.HeaderContentEncoding, "gzip")
	}
	return c.Blob(http.StatusOK, "application/wasm", body)
}

func (en *engine) read(info fs.FileInfo, gz bool) ([]byte, error) {
	if !gz {
		return fs.ReadFile(en.static, engineFile)
	}
	key := fmt.Sprint(info.Size(), info.ModTime().UnixNano())
	en.mu.Lock()
	defer en.mu.Unlock()
	if key == en.key {
		return en.gz, nil
	}
	raw, err := fs.ReadFile(en.static, engineFile)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&b, gzip.BestCompression)
	zw.Write(raw)
	zw.Close() // writes to a bytes.Buffer can't fail
	en.key, en.gz = key, b.Bytes()
	return en.gz, nil
}

func (h *handler) vm(p page) map[string]any {
	// Op is always set: templates compare it with eq, and eq on a missing key is an error, not false.
	return map[string]any{"Active": p.Key, "Title": p.Title, "Desc": p.Desc, "Heading": p.Title, "Pages": pages,
		"Base": h.base, "Form": url.Values{}, "Op": "", "Algs": SignAlgs}
}

func (h *handler) op(op Op) echo.HandlerFunc {
	p := pages[slices.IndexFunc(pages, func(p page) bool { return p.Key == op.Page })]
	return func(c *echo.Context) error {
		c.Response().Header().Set("Cache-Control", "no-store") // results can be secrets: a generated key, a signed token
		in, err := readInput(c)
		var res any
		if err == nil {
			res, err = h.run(c.RealIP(), op, in)
		}
		vm := h.vm(p)
		vm["Form"], vm["Op"] = in.Fields, op.Name
		if err == nil {
			vm["Result"] = res
			return platform.Reply(c, http.StatusOK, res, vm, "cipher/"+p.Key, "cipher/"+p.Key)
		}
		vm["Error"] = err.Error()
		code := http.StatusBadRequest
		if errors.Is(err, platform.ErrBusy) {
			code = http.StatusServiceUnavailable
		}
		return platform.Reply(c, code, map[string]string{"error": err.Error()}, vm, "cipher/"+p.Key, "cipher/"+p.Key)
	}
}

func (h *handler) run(client string, op Op, in Input) (any, error) {
	if op.Heavy {
		w := HeavyWeight(op.Name, in)
		if !h.lim.HeavyCap.TryAcquire(client, w) {
			return nil, platform.ErrBusy
		}
		defer h.lim.HeavyCap.Release(client, w)
	}
	return Run(op, in)
}

// readInput takes a form (urlencoded or multipart) or a flat JSON object, so both curl -d and curl --json work.
func readInput(c *echo.Context) (Input, error) {
	in := Input{Fields: url.Values{}, Files: map[string][]byte{}}
	r := c.Request()
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var obj map[string]any
		dec := json.NewDecoder(r.Body)
		dec.UseNumber()
		if err := dec.Decode(&obj); err != nil {
			return in, fmt.Errorf("body: %w", jsonError(err))
		}
		return InputFromJSON(obj)
	}
	if err := r.ParseMultipartForm(maxBody); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		return in, fmt.Errorf("body: %w", err)
	}
	maps.Copy(in.Fields, r.PostForm) // not Form, which merges in the query string
	if r.MultipartForm == nil {
		return in, nil
	}
	for k, fhs := range r.MultipartForm.File {
		f, err := fhs[0].Open()
		if err != nil {
			return in, err
		}
		in.Files[k], err = io.ReadAll(io.LimitReader(f, maxBody))
		f.Close()
		if err != nil {
			return in, err
		}
	}
	return in, nil
}

func limited(c *echo.Context) error {
	return c.JSON(http.StatusTooManyRequests, map[string]string{
		"error": "Too many requests from your address. The pages run in your browser and need none of these; this limit is for the API.",
	})
}

// SitemapPages lists this tool's indexable URLs, for platform.RegisterSEO.
func SitemapPages() ([]platform.Page, error) {
	out := make([]platform.Page, len(pages))
	for i, p := range pages {
		out[i] = platform.Page{Path: p.Path}
	}
	return out, nil
}
