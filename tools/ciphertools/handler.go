//go:build !js

// The one file in this package that is server-only. The build tag keeps Echo,
// platform and everything they pull in (the Mongo driver among them) out of the
// wasm binary, which only ever needs the ops and the templates.

package ciphertools

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"

	"github.com/Landver/site-of-tools/platform"
)

// page is one sub-nav entry: a GET route serving the page shell. Its forms post
// to ops (op.go), which is where the work happens.
type page struct {
	Key, Path, Template, Title, Desc string
}

var pages = []page{
	{Key: "jwt", Path: "/", Template: "cipher/jwt",
		Title: "JWT decoder, verifier and signer — Cipher Tools",
		Desc:  "Decode a JWT, verify its signature with a secret, PEM or JWKS, and sign new ones: HS, RS, PS, ES and EdDSA. Runs in your browser, so the token never leaves the page. Loud about unverified tokens, alg none and algorithm confusion."},
	{Key: "hash", Path: "/hash", Template: "cipher/hash",
		Title: "Hash calculator and checksum checker: MD5, SHA-256, SHA-3, BLAKE2 — Cipher Tools",
		Desc:  "Hash text or a file with MD5, SHA-1, SHA-2, SHA-3, BLAKE2, Keccak-256, CRC32 and Adler-32 at once, as hex and base64. Paste a checksum to see which algorithm it matches. Flags trailing newlines, CRLF and BOMs. Runs in your browser."},
	{Key: "hmac", Path: "/hmac", Template: "cipher/hmac",
		Title: "HMAC generator and webhook signature checker — Cipher Tools",
		Desc:  "Compute HMAC-SHA256, SHA-512, SHA-1, MD5 and SHA-3 at once with a key as text, hex or base64, and verify a webhook signature (GitHub, Stripe, Slack) in constant time. Runs in your browser, so the key never leaves the page."},
	{Key: "password", Path: "/password", Template: "cipher/password",
		Title: "bcrypt, Argon2, scrypt and PBKDF2 password hash generator and checker — Cipher Tools",
		Desc:  "Hash a password with bcrypt, Argon2id, scrypt or PBKDF2, or paste a stored hash to read its algorithm, cost and salt and check a password against it. Warns about bcrypt's 72-byte limit and weak parameters. Runs in your browser."},
	{Key: "encrypt", Path: "/encrypt", Template: "cipher/encrypt",
		Title: "AES-GCM, ChaCha20-Poly1305 and AES-CBC encryption and decryption — Cipher Tools",
		Desc:  "Encrypt or decrypt with AES-GCM, ChaCha20-Poly1305 or AES-CBC using a hex or base64 key, a random nonce and optional AAD. The output layout (nonce, ciphertext, tag) is stated so other code can read it. Runs in your browser, so the key never leaves the page."},
	{Key: "keys", Path: "/keys", Template: "cipher/keys",
		Title: "RSA, ECDSA and Ed25519 key generator, PEM to JWK and OpenSSH converter — Cipher Tools",
		Desc:  "Generate a test RSA, ECDSA or Ed25519 key pair, or paste a key to convert it between PEM (PKCS#8, PKCS#1, SPKI), JWK and OpenSSH. Shows the SPKI and OpenSSH SHA256 fingerprints and the RFC 7638 JWK thumbprint. Runs in your browser."},
	{Key: "cert", Path: "/cert", Template: "cipher/cert",
		Title: "X.509 certificate decoder, chain order checker and CSR reader — Cipher Tools",
		Desc:  "Decode a certificate, chain or CSR from PEM or DER: SANs, validity, issuer, key, usages and SHA-256 fingerprints. Checks chain order and each signature, flags expiry, SHA-1 and CN-only certificates, and tests whether a key matches. Runs in your browser."},
	{Key: "totp", Path: "/totp", Template: "cipher/totp",
		Title: "TOTP and HOTP code generator, otpauth:// URI reader and builder — Cipher Tools",
		Desc:  "Get the previous, current and next TOTP or HOTP code from a base32 secret or an otpauth:// URI, with a countdown. Check a code within one step either side, and build an otpauth:// URI. SHA1, SHA256 and SHA512. Runs in your browser."},
	{Key: "random", Path: "/random", Template: "cipher/random",
		Title: "Random token, password and UUID v4 / v7 generator — Cipher Tools",
		Desc:  "Generate random tokens as hex, base64url or letters and digits, passwords with the character sets you pick and their exact entropy, and UUID v4 or v7 in bulk. Cryptographic randomness with no modulo bias, made in your browser."},
	{Key: "encode", Path: "/encode", Template: "cipher/encode",
		Title: "Base64, hex and base32 converter, Basic auth header — Cipher Tools",
		Desc:  "Convert bytes between UTF-8 text, hex, base64, base64url and base32, with the base64 variant named and bad characters pointed at by offset. Build and decode HTTP Basic auth headers. Runs in your browser."},
	{Key: "identify", Path: "/identify", Template: "cipher/identify",
		Title: "Hash, token, key and encoding identifier with hashcat modes — Cipher Tools",
		Desc:  "Paste a string to see what it could be: hash types with hashcat modes, JWT, JWE, PEM keys and certificates, SSH keys, bcrypt and Argon2 hashes, UUIDs, otpauth:// URIs, base64, hex or base32. Ranked candidates, each linked to the page that reads it."},
}

// maxBody bounds every POST, uploads included. The browser engine has no such
// limit: a file hashed there never travels.
const maxBody = 8 << 20

// Limits are this tool's budgets, built once and shared by every door. Ops are
// pure CPU with no upstream, so the ordinary ones are generous; Heavy ops
// (password hashing, RSA key generation, signing) are what a stranger would
// use to burn this box's CPU and memory, so they are not.
type Limits struct {
	Pure, Heavy platform.Limiter
	// Engine bounds how fast one address can pull the multi-MB wasm engine; a
	// page load fetches it once and the browser keeps it.
	Engine platform.Limiter
	// HeavyCap is a byte budget for Heavy ops in flight, each holding
	// HeavyWeight of it while it runs.
	HeavyCap *platform.Cap
}

const heavyBudget = 256 << 20

// NewLimits returns fresh budgets: Pure 10/s (burst 50), Heavy 1/s (burst 5),
// Engine 1/s (burst 10); 256 MiB of Heavy ops in flight.
func NewLimits() *Limits {
	return &Limits{
		Pure:     platform.NewLimiter(10, 50),
		Heavy:    platform.NewLimiter(1, 5),
		Engine:   platform.NewLimiter(1, 10),
		HeavyCap: platform.NewCap(heavyBudget),
	}
}

// HeavyWeight is what a Heavy op holds of HeavyCap: its MemoryCost, at least
// 1 MiB, and never more than the whole budget, so no input is refused forever.
func HeavyWeight(name string, in Input) int64 {
	return min(max(MemoryCost(name, in), 1<<20), heavyBudget)
}

var errBusy = errors.New(platform.BusyMessage)

type handler struct {
	base string
	lim  *Limits
}

// Register wires cipher.corpberry.com.
//
//	GET  <page.Path>   page shells, one per sub-nav entry
//	POST <op.Path>     every op: JSON for an API caller, the whole page for a
//	                   browser with JavaScript off
//
// Ops read the POST body only, never the query string. A secret in a URL lands
// in history, in Referer headers and in the request log; refusing to read one
// there is what keeps anybody from building that habit.
//
// static is the shared static FS the app serves /static from; the engine is read
// from it once and served pre-compressed (engine below). lim nil means fresh
// limits.
func Register(e *echo.Echo, base string, static fs.FS, lim *Limits) {
	if lim == nil {
		lim = NewLimits()
	}
	h := &handler{base: base, lim: lim}
	e.Use(immutableEngine)
	en := &engine{static: static}
	e.GET(enginePath, en.serve, platform.RateLimit(lim.Engine, nil, limited))
	pure := platform.RateLimit(lim.Pure, nil, limited)
	heavy := platform.RateLimit(lim.Heavy, nil, limited)
	limit := middleware.BodyLimit(maxBody)

	for _, p := range pages {
		e.GET(p.Path, h.page(p))
	}
	for _, op := range Ops() {
		rl := pure
		if op.Heavy {
			rl = heavy
		}
		e.POST(op.Path, h.op(op), limit, rl)
	}
}

// immutableEngine lets browsers keep the engine. It is ~10 MB (~2.5 MB
// gzipped), Cloudflare does not cache .wasm by default, and embedded files carry
// no Last-Modified, so without this every page view downloaded it again. Only
// content-hashed URLs (?v=, from platform.AssetVersioner) qualify: their bytes
// can never change under the same URL, so "immutable" is simply true.
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

// enginePath is the one static file this package serves itself. Echo's router
// prefers this exact route to the /static* wildcard NewApp registers, and
// platform's gzip middleware skips it (platform/app.go), so the bytes written
// here are the bytes sent.
const enginePath = "/static/wasm/cipher.wasm"

// engine serves the wasm engine gzipped once, not per request. The file is
// ~12 MB; the shared gzip middleware compressed it on every fetch, ~0.25 s of
// CPU each time, and Cloudflare doesn't cache .wasm without a rule, so the one
// URL every visitor downloads was also the cheapest way to keep a core busy.
//
// The cache is keyed on size and modification time: embedded files never
// change, and in dev (disk FS) a `make wasm` rebuild is picked up on the next
// request instead of serving the old engine until restart.
type engine struct {
	static fs.FS
	mu     sync.Mutex
	key    string
	gz     []byte
}

const engineFile = "wasm/cipher.wasm"

func (en *engine) serve(c *echo.Context) error {
	info, err := fs.Stat(en.static, engineFile)
	if err != nil {
		return echo.ErrNotFound
	}
	c.Response().Header().Add(echo.HeaderVary, echo.HeaderAcceptEncoding)
	if !strings.Contains(c.Request().Header.Get(echo.HeaderAcceptEncoding), "gzip") {
		raw, err := fs.ReadFile(en.static, engineFile)
		if err != nil {
			return err
		}
		return c.Blob(http.StatusOK, "application/wasm", raw)
	}
	gz, err := en.compressed(info)
	if err != nil {
		return err
	}
	c.Response().Header().Set(echo.HeaderContentEncoding, "gzip")
	return c.Blob(http.StatusOK, "application/wasm", gz)
}

func (en *engine) compressed(info fs.FileInfo) ([]byte, error) {
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
	if err := zw.Close(); err != nil {
		return nil, err
	}
	en.key, en.gz = key, b.Bytes()
	return en.gz, nil
}

func findPage(key string) page {
	for _, p := range pages {
		if p.Key == key {
			return p
		}
	}
	panic("ciphertools: op names unknown page " + key)
}

func (h *handler) vm(p page) map[string]any {
	return map[string]any{
		"Active": p.Key, "Title": p.Title, "Desc": p.Desc, "Heading": p.Title,
		// Op is always set, even to "": templates compare it with eq, and eq
		// on a missing map key is an execution error, not false.
		"Base": h.base, "Form": url.Values{}, "Op": "", "Algs": SignAlgs,
	}
}

func (h *handler) page(p page) echo.HandlerFunc {
	return func(c *echo.Context) error {
		return c.Render(http.StatusOK, p.Template, h.vm(p))
	}
}

func (h *handler) op(op Op) echo.HandlerFunc {
	p := findPage(op.Page)
	return func(c *echo.Context) error {
		// Results can be secrets (a generated key, a signed token); no cache
		// between here and the visitor may keep one.
		c.Response().Header().Set("Cache-Control", "no-store")

		in, err := readInput(c)
		var res any
		if err == nil {
			res, err = h.run(op, in)
		}
		code := http.StatusOK
		switch {
		case errors.Is(err, errBusy):
			code = http.StatusServiceUnavailable
		case err != nil:
			code = http.StatusBadRequest
		}
		if platform.WantsJSON(c) {
			if err != nil {
				return c.JSON(code, map[string]string{"error": err.Error()})
			}
			return c.JSON(http.StatusOK, res)
		}
		// A browser posting the form itself: JavaScript is off, so the page
		// renders server-side with the result in place.
		vm := h.vm(p)
		vm["Form"], vm["Op"] = in.Fields, op.Name
		if err != nil {
			vm["Error"] = err.Error()
		} else {
			vm["Result"] = res
		}
		return c.Render(code, p.Template, vm)
	}
}

// run holds a Heavy op's share of HeavyCap while it runs, after its input is
// parsed, since the weight depends on it.
func (h *handler) run(op Op, in Input) (any, error) {
	if !op.Heavy {
		return Run(op, in)
	}
	w := HeavyWeight(op.Name, in)
	if !h.lim.HeavyCap.TryAcquire(w) {
		return nil, errBusy
	}
	defer h.lim.HeavyCap.Release(w)
	return Run(op, in)
}

// readInput accepts a form (urlencoded or multipart) or a flat JSON object of
// strings, so both `curl -d key=value` and `curl --json '{...}'` work.
func readInput(c *echo.Context) (Input, error) {
	in := Input{Fields: url.Values{}, Files: map[string][]byte{}}
	r := c.Request()
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var obj map[string]any
		if err := json.NewDecoder(r.Body).Decode(&obj); err != nil {
			return in, fmt.Errorf("body: %w", jsonError(err))
		}
		return InputFromJSON(obj)
	}
	if err := r.ParseMultipartForm(maxBody); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		return in, fmt.Errorf("body: %w", err)
	}
	// PostForm, not Form: Form merges in the query string.
	for k, v := range r.PostForm {
		in.Fields[k] = v
	}
	if r.MultipartForm != nil {
		for k, fhs := range r.MultipartForm.File {
			if len(fhs) == 0 {
				continue
			}
			f, err := fhs[0].Open()
			if err != nil {
				return in, err
			}
			b, err := io.ReadAll(io.LimitReader(f, maxBody))
			f.Close()
			if err != nil {
				return in, err
			}
			in.Files[k] = b
		}
	}
	return in, nil
}

func limited(c *echo.Context) error {
	return c.JSON(http.StatusTooManyRequests, map[string]string{
		"error": "Too many requests from your address. The pages run in your browser and need none of these; this limit is for the API.",
	})
}

// SitemapPages: this tool's indexable URLs, for platform.RegisterSEO.
func SitemapPages() ([]platform.Page, error) {
	out := make([]platform.Page, 0, len(pages))
	for _, p := range pages {
		out = append(out, platform.Page{Path: p.Path})
	}
	return out, nil
}
