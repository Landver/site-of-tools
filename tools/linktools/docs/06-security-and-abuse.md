# Security and abuse — the cross-cutting threat model

**Read this before writing `trace.go`.** Two features here are
security-load-bearing in a way nothing else in the repo is: Trace makes this box
fetch a URL a stranger chose, and Short hands out redirects on the domain that
hosts everything else.

---

## 1. Threat table

| # | Threat | Surface | Control |
|---|---|---|---|
| 1 | SSRF | `/trace`, `/preview` | `Dialer.Control` gate + `Proxy: nil` + `DisableKeepAlives`, §2 |
| 2 | DNS rebinding | `/trace` multi-hop | The gate runs on the literal address the kernel is about to connect to, §2 |
| 3 | Client-side SSRF / router CSRF | `/s/:code` | IP-literal + port rejection at create, [04 §6](04-short-links.md#6-redirect-safety) |
| 4 | Open redirect | `/s/:code` | Scheme allowlist at create **and** resolve |
| 5 | Phishing relay → domain blocklisted | alias creation | API key, fail-closed, + `X-Robots-Tag: noindex` |
| 6 | Alias enumeration | `/s/:code`, `GET /short` | `crypto/rand` codes **and** a key-gated console |
| 7 | **Pasted URLs persisted in logs** | every page | §5 — *unresolved, blocks Phase 0* |
| 8 | Decode-ladder exhaustion | `/` | Depth and size caps, §7 |
| 9 | Reflected hostile URL | every page | Never render input into `href`; CSP, §8 |
| 10 | Bandwidth / header amplification | `/trace`, `/preview` | Hop, body **and header** caps, §3 |
| 11 | Mongo load amplification | `/s/:code` | Resolve cache + global breaker, [04 §7](04-short-links.md#7-abuse-controls-summarised) |
| 12 | Mongo operator injection | `POST /short` | Typed struct, regex before filter, [04 §3](04-short-links.md#custom-slugs) |
| 13 | **Attribution: abuse complaints land on this Hetzner account** | `/trace` | §2's port allowlist, hard; and see the precedent below |
| 14 | **Self-trace recursion / Cloudflare bypass** | `/trace` | Refuse own vhosts and own interface addresses, §2 |
| 15 | Per-IP limits meaningless over IPv6 | every limited route | Key on the `/64`, §4 |

**On #13, this project has already ruled on this once.** The `iptools` live port
scanner was shelved because of Hetzner ban risk (`docs/reports/`). Every
`/trace` fetch carries the box's Hetzner IP as the source, so abuse complaints
for attacker-driven traffic land on the account that also fronts third-party
client sites behind the same nginx. The first draft of §2 quietly reopened a
narrow version of this by allowing "common dev ports if a case appears". That
door stays closed.

---

## 2. SSRF: the one that matters

### Use `Dialer.Control`, not a hand-rolled resolve-then-dial

The first draft sketched replacing `DialContext`, calling `LookupNetIP` by hand,
and dialling "the specific address that was checked". `dnstools` already does
better, with `net.Dialer.Control` (`email.go:781`), which runs **after
resolution, on the literal address the kernel is about to connect to**. It is
strictly better: there is no TOCTOU window to reason about at all, it composes
with Happy Eyeballs and multi-address fallback, and it needs no re-dial code.

The sketch was also buggy in three ways worth not repeating: it discarded the
`SplitHostPort` error, ignored the `LookupNetIP` error, and its "reject unless
every returned address is public" rule fails closed on legitimate hosts that
publish one unroutable address.

### Lift the gate from botcheck, and promote it to `platform`

The routable-address check has now been written **four times** in this repo:
`dnstools/email.go:799`, `dnstools/spread.go:514`, `iptools/handler.go:234`, and
`botcheck/botcheck.go:746`. Only the last is complete.

`email.go`'s version does **not** satisfy this doc's own requirements:

```go
if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
```

`100.64.0.0/10` (CGNAT) is global unicast and not private, so it passes.
`spread.go` and `iptools` use a weaker `net.IP` variant with no `Unmap` and no
`IsGlobalUnicast`. **`botcheck.publiclyRoutable` is the one to promote**: it adds
`cgnatRange` and `IsMulticast` on top of `Unmap`.

It belongs in `platform` **now**, before `trace.go` is written — four copies
already retires the "if it gets lifted twice" rule. Extend the promoted version
with what none of them cover:

- `0.0.0.0/8`, `192.0.0.0/24`, `198.18.0.0/15` (benchmarking), `240.0.0.0/4`
- IPv6 transition prefixes that embed IPv4: `64:ff9b::/96` (NAT64),
  `2002::/16` (6to4), `2001::/32` (Teredo)
- `::1`, `fc00::/7`, link-local, unspecified, multicast — already covered by the
  botcheck version's `Unmap` + stdlib predicates

### Three bypasses a dialer gate alone does not close

**(a) `Proxy: http.ProxyFromEnvironment`.** It is carried in the very transport
this doc says to lift (`dnstools/email.go:777`). With `HTTP_PROXY`/`HTTPS_PROXY`
set, `DialContext` is called with the **proxy's** address, so the gate validates
the proxy and the target hostname is handed to the proxy in the CONNECT request.
The gate is completely bypassed. Not theoretical: `docker-compose.yml` loads
`.env` and `.env.prod` wholesale via `env_file`, both are per-host and
gitignored, so a proxy variable added by ops is invisible to anyone reading the
repo — and Go caches the env read in a `sync.Once`, fixing it at first use.
**Set `Proxy: nil` explicitly, with a comment saying why.** Worth a follow-up to
do the same in `email.go`.

**(b) Connection reuse means no dial, and a dialer hook only fires on a dial.**
`http.Transport` serves from the idle pool when the authority matches, and
HTTP/2 can reuse a connection for a second authority the peer certificate
covers. An attacker registers `pub.evil.com` (public A) and `int.evil.com`
(A → `10.0.0.5`) under one certificate, then submits a chain
`pub.evil.com` → `int.evil.com`. Hop 2 may be answered off the pooled
connection with **no dial**, so neither the IP gate nor the port check runs. The
bytes still go to the attacker's own server, so there is no data-plane SSRF —
but the property this doc claims is false, and the rendered result actively
misleads the person checking a suspicious link. **Set `DisableKeepAlives: true`**
(trace is one request per hop at 1/s; pooling buys nothing) **and enforce
scheme/host/port in `trace.go` above the transport as well.** State the rule as:
*the gate runs in two places because a dialer hook only fires when a dial
happens.*

**(c) Public-but-privileged destinations.** The premise "this box can reach a
Mongo server on a private address" is wrong — `DEPLOYMENT §9` describes a remote
dependency reached over the wire by a Cloudflare-proxied DNS name, "only from
hosts on its allowed network path". That is a **source-IP-allowlisted** server
on a public address. So `http://<mongo-host>:27017/` passes the routable gate
and is dialled **from the one source IP the DB firewall trusts**. Mongo will not
speak HTTP, but you get a reachability and auth-surface oracle and a
confused-deputy bypass of the firewall.

The only control standing against that is the port allowlist, so it is a
**first-class control, not an anti-scanning nicety: 80 and 443, no exceptions,
no dev-port escape hatch.** Additionally deny the configured Mongo host, the
box's own interface addresses (enumerated once at startup via
`net.Interfaces()`), and **every configured vhost** — `cfg.VHost` already
enumerates them, and without it `/trace?u=https://link.corpberry.com/trace?u=…`
traces itself recursively (the hop cap is per-request, not per-tree) and reaches
the origin nginx from a source that is not the visitor, putting Cloudflare's WAF
and rate limiting in front of visitors but not in front of this path.

### The manual redirect walk

`CheckRedirect` returns `http.ErrUseLastResponse`; the chain is walked one
request at a time so each hop is a fresh gated dial. Cap at 10 hops. Beyond
that, five rules the first draft omitted:

1. **Resolve `Location` as a relative reference** against the current URL. A
   bare `//evil.tld/` is protocol-relative and `url.Parse` gives it an empty
   scheme, which a naive "non-http/https ends the chain" check mishandles.
2. **Never forward `Referer`.** Go's own client sets it on redirects it follows;
   a hand-rolled walk that copies headers forward sends the pasted URL — tokens
   and all — to every subsequent attacker-chosen host. A worse leak than §5's.
3. **Drop `Authorization` on the first cross-host hop**, and never derive it
   from URL userinfo in the first place.
4. **No cookie jar. Ever.**
5. **Flag an https → http downgrade** as a finding rather than stepping through
   it silently.

Build `req.Header` fresh per hop from a fixed allowlist (`User-Agent`,
`Accept`), never carried forward.

---

## 3. Bounding the fetch

| Bound | Value | Why |
|---|---|---|
| Hops | 10 | Above every legitimate chain |
| Per-hop timeout | 5s | |
| Total wall clock | 15s via `context.WithTimeout` | A chain of slow hops is a slowloris |
| `MaxResponseHeaderBytes` | 64 KiB | **Go's default is 10 MB.** 10 hops × 10 MB × burst 5 × N source IPs is a free amplifier |
| `ResponseHeaderTimeout` | 5s | |
| Body, trace | 0 bytes read, or 64 KB when meta-refresh detection is on | Trace needs headers |
| Body, preview | 512 KB via `io.LimitReader` | `<head>` is near the front |
| `Location` length | 2048 | |
| TLS | verified; `InsecureSkipVerify` never set | A TLS failure is a **finding**, never a retry over http |

Use `GET`, not `HEAD` — too many servers answer `HEAD` differently or not at all
— and close the body unread when only the status line matters.

---

## 4. Rate limits

`dnstools` established the in-process per-IP limiter; reuse it, with one fix.

| Route | Limit |
|---|---|
| `/`, `/clean` | 10/s, burst 50 — pure CPU, generous on purpose |
| `/trace`, `/preview` | 1/s, burst 5 |
| `POST /short`, `GET /short` | 1/s, burst 5 |
| `/s/:code` | no per-IP limit; cache + global breaker instead ([04 §7](04-short-links.md#7-abuse-controls-summarised)) |

**Per-IP limiting over IPv6 is not a limit.** `dnstools/handler.go:330` keys on
bare `c.RealIP()`. A client with a routine `/64` has 2⁶⁴ source addresses, so
"1/s burst 5" is effectively unbounded — and each unique key allocates a bucket
held for `rateLimitExpiry`, making it a memory-growth path too. Normalise before
the store: full address for IPv4, **`/64` prefix for IPv6**. This is a
`platform` helper, since `dnstools` has the same hole today.

---

## 5. The request log will eat pasted URLs

**Unresolved. Blocks Phase 0.**

`platform/requestlog.go` persists the request URI for every non-static request
(`ShouldRecord` skips only `/static/`), TTL **30 days** — not 90; 90 is
`iptools`' lookup history, a different collection. On this host the URI *is* the
user's input:

```
GET /?u=https%3A%2F%2Fapp.example.com%2Freset%3Ftoken%3DSECRET
```

**Redacting inside `RequestLog.Record` does not fix it.** `platform/app.go`'s
`requestLogger` emits `slog.String("uri", v.URI)` to stdout **before** it calls
`reqlog.Record(...)`, in the same `LogValuesFunc`. Docker captures stdout to
disk on the host, indefinitely, with no TTL at all. The correct change is
**redact `v.URI` once at the top of `LogValuesFunc` into a local, and use that
local for both the slog attrs and the `RequestEntry`** — two lines, in a
different place than first described.

Sinks that remain regardless: nginx access logs, Cloudflare, `hx-push-url`
putting it in browser history, and `Referer` to any upstream (closed by §2's
rule 2). A TTL is also not deletion from backups, and `UserAgent` is stored
alongside, sharpening the requester fingerprint.

Options:

1. **Redact in `LogValuesFunc`** — small, central, fixes Mongo *and* stdout.
2. **Accept input by `POST`** on Inspect — fixes all sinks, costs the
   shareable-result-URL property every other tool here has.
3. **Client-side only** — costs the JSON API and duplicates the parser.
4. Say nothing. Not an option.

**Lean: (1) plus an honest note on the page. ~70%.**

The counter-argument deserves stating, because it is stronger than the first
draft allowed: **every competing parser is client-side-only and markets that as
the feature.** jsonutilities says "your query strings and URLs never leave your
device"; calcbe says its share URL never includes what you pasted. Option (3) is
not a compromise, it is the incumbent architecture, and the category's users
have been taught to expect it.

We are deliberately trading that property for a curl-able JSON API, which
[00 §3](00-landscape.md#3-whats-actually-unoccupied) rates the clearest
unoccupied gap in the survey. That is a defensible trade **only if the page says
which trade it made**.

This is a `platform/` change affecting all four subdomains, so it wants the
owner's sign-off rather than being smuggled in with a feature.

---

## 6. Never store what was traced — which is not currently true

Trace results are not persisted: no cache, no history. A traced-URL corpus is a
record of what people are suspicious of.

**But `request_logs` already is that corpus.** `GET /trace?u=<url>` produces a
row holding the traced URL, `RemoteIP` and `CreatedAt` — requester, target,
timestamp — whether or not `trace.go` writes anything. So §5's redaction is a
hard prerequisite for shipping `/trace`, not only for the Inspect page, and
[03 §5](03-architecture.md#5-storage)'s "deliberately no inspection history" is
true only after it lands.

---

## 7. Decode-ladder exhaustion

Base64 of base64 of base64 is trivial to construct and each rung can be larger
than the last. Cap depth at 5, cap each rung at 64 KB, and **stop with a note**
rather than truncating silently. Fuzz it
([07 §7](07-testing.md#7-fuzzing)) — it is the most fuzz-shaped function here.

---

## 8. Rendering hostile URLs

The Inspect page's job is displaying URLs that may be actively malicious. The
same rules apply to the short-link console, where `note` and `target` are
attacker-influenced.

- **Render input as text, never into an `href`.** `html/template` does neuter
  `javascript:` in URL context, but relying on that alone means one refactor
  into an attribute context away from a stored-XSS-shaped bug.
- Link only when the scheme passed the allowlist, with
  `rel="noopener noreferrer nofollow"` and `referrerpolicy="no-referrer"`.
- **Never echo a password** from userinfo. `Inspection.HasPass` is a bool for
  exactly this reason.
- When a host's Unicode and punycode forms differ, or one label mixes scripts,
  **show both and flag it.** A tool that renders only the pretty form is
  assisting the homoglyph attack.
- **Add a `Content-Security-Policy` for the whole subdomain.** The plan
  otherwise specifies none anywhere, and it is the one control that would
  contain both this and any future `href` slip.

---

## 9. Claims that need qualifying

Places the first draft asserted a property it did not establish:

- **`c.RealIP()` trust.** §4's limiter and `created_ip`'s forensic value both
  inherit DEPLOYMENT §4's invariant that nginx overwrites `CF-Connecting-IP`.
  That invariant is **unverifiable from this repo**: `deploy/nginx/` does not
  exist (configs live on the host), and `dnstools/docs/02-build-fit.md` already
  asks every new subdomain to reconfirm it. This tool adds a forensics-bearing
  consumer, so confirm it before treating `created_ip` as evidence.
  **This is a delivery-plan gate.**
- **`Refresh:` as an HTTP header**, not only `<meta>`, is widely honoured.
  Reporting "chain finished" on a 200 carrying `Refresh: 0;url=…` is a wrong
  answer in the security-relevant direction. Detect and name it.
- Assorted smaller ones, fixed in place: `subtle.ConstantTimeCompare` leaking
  key length, `json:"-"` not protecting an HTML template, `Referrer-Policy`'s
  actual effect, 404-vs-410 as an existence oracle, and the entropy claim
  covering generated codes only. All now handled in
  [`04`](04-short-links.md).

---

## 10. Operational controls

One line each, all currently missing:

- **`X-Robots-Tag: noindex` on `/s/:code`.** Googlebot follows short links and
  will otherwise associate `corpberry.com` with whatever they point at — threat
  #5 arriving by a route the API key does not cover.
- ~~**A kill switch**~~ — `DELETE /short/:code` now exists, key-gated, soft-delete
  only, and it takes effect immediately because the store invalidates the cached
  entry on write. Until it was wired, `LinkStore.Revoke` had **no caller at all**,
  so nothing on this list was reachable by any route. Revoking *everything* a
  leaked key created still needs a per-key identifier on `Link`, which is not
  there yet.
- **A per-key total-link cap**, so a leak is bounded before anyone notices.
- **A stated response body and `Content-Type` for the 302.**

---

## 11. What the pages should say out loud

Following `dnstools`' precedent of naming its own limits:

- Inspect: "Nothing here is fetched — the URL is parsed, not visited. It does
  appear in standard web-server logs, like any other URL, so don't paste
  secrets. Tools that never send the URL anywhere exist and are linked below."
- Clean: "Rules are curated, not exhaustive. Here is the table, and here is what
  was removed."
- Trace: "We can't follow JavaScript redirects, and some targets refuse
  automated requests. When that happens we say so instead of calling the chain
  finished."
- Short: "Creating links needs a key. This is not a public shortener."
