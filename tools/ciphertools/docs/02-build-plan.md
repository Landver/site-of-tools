# Build plan — cipher.corpberry.com

## Decision: where the crypto runs

**The browser.** Decided by the owner on 2026-09-28, against a lean for
server-side Go. The [landscape](00-landscape.md) is why: every tool in this
category that people trust runs locally and says so, and the server-side ones are
the ones reviewers call untrustworthy. A JWT or an HMAC secret is a credential. A
page that posts it to someone's server is asking a lot of trust.

**How, without breaking the repo's rules:** the domain package is compiled to
WebAssembly (`GOOS=js GOARCH=wasm`, stock Go toolchain, no Node). The same Go code
that answers the JSON API runs inside the visitor's tab:

```
browser tab                                   server (same binary as ever)
───────────                                   ────────────────────────────
form submit / keystroke                       GET  /hash   → page shell (html)
   │ (cipher.js intercepts, never posts)      POST /hash   → JSON API, or the whole
   ▼                                                         page when JS is off
Web Worker  ── cipher-worker.js                  │
   │  Go wasm: ciphertools.Render(op, form)      ▼
   │  = Ops[op].Run + html/template fragment  ciphertools.Ops[op].Run  (same code)
   ▼
#result.innerHTML = the fragment
```

- **One source of truth.** `Ops` (the registry in `op.go`) is the whole feature:
  a form in, a result struct out. The server's handler and the wasm entrypoint
  are both a few lines around it. The result fragments are the same
  `templates/*.html` in both places, executed by the same `html/template`, so a
  page can't render differently in the browser than it does in a test.
- **A worker, not the main thread.** bcrypt at cost 12, Argon2 and RSA-4096
  key generation take seconds. `syscall/js` calls are synchronous, so the engine
  runs inside a Web Worker and the page never freezes.
- **No silent fallback.** If the engine fails to load, the page says so and
  sends **nothing**. Posting the input to the server "to be helpful" would break
  the one promise the page makes. With JavaScript off, a `<noscript>` note says
  that submitting *will* send the input to the server, where it's processed in
  memory and never logged or stored. That's a choice the visitor makes knowingly.
- **The JSON API stays.** `curl -d token=… https://cipher.corpberry.com/jwt/decode`
  is server-side by definition, and that's the caller's own choice. Secrets go in
  the POST body only. The request log records the URI and never the body, and no
  op accepts a secret in the query string.
- **Live as you type.** Once the engine is local, a keystroke costs nothing, so the
  cheap pages (JWT decode, hash, encode, identify) update on input. The expensive
  ones (password hashing, key generation) wait for a click.

### Build artifacts

`shared/static/wasm/cipher.wasm` and `shared/static/wasm/wasm_exec.js` are
generated, gitignored, and embedded through `shared.Static`. That's exactly the
`styles.css` pattern. `wasm_exec.js` is copied from `$(go env GOROOT)/lib/wasm/`
at build time, never committed, because it must match the compiler that built
the `.wasm`. It's built by `make wasm` (a prerequisite of `build` and `dev`), by
the Dockerfile before `go build`, and checked by CI and the pre-push hook.

`handler.go` carries `//go:build !js`, so the wasm binary never links Echo, Mongo
or `platform/`. Everything else in the package is pure Go and builds for both
targets.

## Pages (sub-nav order)

| Route | Page | Ops (POST) | Live? |
|---|---|---|---|
| `/` | JWT decode / verify / sign | `/jwt/decode`, `/jwt/sign` | decode |
| `/hash` | Hash text or a file, compare | `/hash` | yes |
| `/hmac` | HMAC + verify | `/hmac` | yes |
| `/password` | bcrypt / Argon2id / scrypt / PBKDF2 | `/password/hash`, `/password/verify` | no |
| `/encrypt` | AES-GCM, ChaCha20-Poly1305, AES-CBC | `/encrypt` | no |
| `/keys` | Generate + inspect/convert keys | `/keys/generate`, `/keys/inspect` | inspect |
| `/cert` | X.509 / CSR / chain decode | `/cert` | yes |
| `/totp` | TOTP/HOTP codes, `otpauth://` | `/totp` | yes |
| `/random` | Tokens, passwords, UUIDs | `/random` | no |
| `/encode` | Bytes between text/hex/base64/base32, Basic auth | `/encode` | yes |
| `/identify` | What is this string? | `/identify` | yes |

## Floors

Built one floor at a time; each one lands green and committed before the next
starts.

1. **Foundation + JWT.** Op registry, handler, wasm entrypoint, worker glue,
   build plumbing (Makefile, Dockerfile, CI, hook, air), `main.go` wiring, the JWT page.
2. **Hash, HMAC, Encode.**
3. **Password, Random.**
4. **Keys, Certificates.**
5. **TOTP, Encrypt, Identify.**
6. **Review pass**, then the fixes it finds.

## Outside the repo

A new subdomain needs a Cloudflare DNS record and an nginx `server {}` block on
the host ([DEPLOYMENT §3](../../../docs/DEPLOYMENT.md)). Both are manual and
the owner's to add.
