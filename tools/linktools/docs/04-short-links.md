# Short links — the one stateful, abusable feature

Everything else in this suite is a pure function. This page writes to a
database, hands out URLs on a domain that also hosts a portfolio, and redirects
strangers to destinations a caller chose. Every one of those is a way to get
`corpberry.com` blocklisted.

---

## 1. Threat first, feature second

A public URL shortener becomes a phishing relay. Not "might" — it is
continuously scanned for, and open ones get found in days. When one is used for
phishing, Google Safe Browsing and the Microsoft and Cloudflare equivalents do
not blocklist the offending path. **They blocklist the domain**: the portfolio,
the blog and all four tools, in every Chrome and Firefox install on earth, with
an appeal measured in weeks.

The feature is built closed and stays closed.

## 2. Where the redirect lives

**Settled, ~80%: `/s/<code>`,** with the base URL config-driven so a short
domain stays a one-line move.

| Shape | Example | Cost |
|---|---|---|
| **(a) Prefixed path** ✅ | `link.corpberry.com/s/aB3xY9k` | 2 extra chars. Alias and page namespaces can never collide |
| (b) Bare root path | `link.corpberry.com/aB3xY9k` | Every future page name permanently steals an alias, and shipping a `/qr` page silently breaks an existing `qr` alias |
| (c) Separate short domain | `crpb.ry/aB3xY9k` | Genuinely short. A domain, a DNS record, an nginx block, a vhost entry |

(b)'s failure mode is silent and retroactive — it breaks links that already
exist in other people's notes, the one thing a shortener must never do — and two
characters is not worth that. (c) is right *if* length matters, and
`NewShortener` taking its base URL as a parameter means the domain can be bought
later without touching code.

> **Revisit only if** the extension's output goes anywhere character-counted
> (SMS, print). Then buy the domain up front.

## 3. Codes

- **Alphabet: base58** (digits and letters minus `0`, `O`, `I`, `l`). These get
  read aloud and typed by hand.
- **Length: 7.** 58⁷ ≈ 2.2 × 10¹².
- **Source: `crypto/rand`, not `math/rand`, not a hash of the target.**
  Sequential codes are enumerable. A hash is worse than it looks: it makes the
  resolver an oracle for "has anyone shortened this exact URL".
- **Collisions: let the unique index do it.** Insert; on a duplicate-key error
  generate a new code and retry, up to five times. Never check-then-insert —
  that is a race.

Note the scope of the entropy claim: it covers **generated codes only**. Custom
slugs share the `/s/` namespace and are dictionary-shaped.

### Custom slugs

- `^[a-z0-9][a-z0-9-]{1,63}$`, lowercase only, so `/s/Foo` and `/s/foo` can't be
  different links.
- Checked against the reserved list in [03 §3](03-architecture.md#reserved-paths).
- Rejected if exactly 7 base58 characters, so a slug can never occupy the
  generated-code space.
- Taken slug → `409`, never a silent suffix.
- **Validated against the regex before reaching any Mongo filter**, and the
  request body decodes into a typed struct with `string` fields only. A `slug`
  arriving as `{"$ne": null}` into a `bson.M` filter is operator injection; one
  line to prevent, expensive to retrofit.

## 4. Storage

Collection `links`, repository in `store.go` below `short.go` per rule #5,
nil-safe so an absent `MONGODB_URI` means creation is off and the app still
boots.

```go
type Link struct {
	Code      string     `bson:"code"        json:"code"`
	Target    string     `bson:"target"      json:"target"`
	Original  string     `bson:"original,omitempty" json:"original,omitempty"` // pre-clean
	Note      string     `bson:"note,omitempty"     json:"note,omitempty"`     // capped at 256 B
	CreatedAt time.Time  `bson:"created_at"  json:"created_at"`
	CreatedIP string     `bson:"created_ip,omitempty" json:"-"` // forensics only
	ExpiresAt *time.Time `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
	RevokedAt *time.Time `bson:"revoked_at,omitempty" json:"revoked_at,omitempty"`
	Cleaned   []string   `bson:"-"           json:"cleaned,omitempty"` // §9, never stored
	Hits      int64      `bson:"hits"        json:"hits"`
	LastHitAt *time.Time `bson:"last_hit_at,omitempty" json:"last_hit_at,omitempty"`
}
```

`Cleaned` is `bson:"-"` on purpose: it is the §9 response's explanation of what
`clean: true` removed on *this* request, not state the alias carries. The alias's
durable record of the pre-clean URL is `Original`, and persisting the parameter
names as well would only duplicate what diffing `Original` against `Target`
already yields — with the added failure mode that a later rule-table change
makes the stored list disagree with the two URLs beside it.

### Indexes

**`{code: 1}`, unique.** Not covered by `platform.EnsureTTLIndex`; needs its own
`Indexes().CreateOne(...)` with `options.Index().SetUnique(true)`. **Its error
must not be swallowed** the way the TTL one is at `iptools/history.go:51`: a
missing TTL index only forfeits pruning, a missing unique index forfeits §3's
correctness.

**Expiry.** `platform.EnsureTTLIndex(ctx, coll, "expires_at", linkRetention)`,
where `linkRetention` is ten years.

An earlier draft of this document recommended passing `0` — `expireAfterSeconds: 0`,
the expire-at-a-date idiom — and that recommendation was **wrong**. It makes Mongo
*delete* the document about a minute after `expires_at`, which frees the unique
code and lets a later create re-register the same custom slug pointing somewhere
else. That is alias takeover, and it contradicts
[Do not hard-delete](#do-not-hard-delete) three paragraphs further down.

So the index is garbage collection only, on a horizon long enough that the row —
and therefore the unique-index entry that reserves the code — outlives any
practical reuse window. Expiry itself is enforced in code, below.

### Expiry is enforced in code, not by the index

Mongo's TTL monitor sweeps roughly every 60 seconds and lags under load. A
resolver that treats document-absence as expiry keeps serving a revoked link for
a minute or more, silently.

**`Resolve` compares `ExpiresAt` and `RevokedAt` against `time.Now()` itself and
refuses regardless of whether the document is still present.** The index is
garbage collection, never the enforcement point.

### Do not hard-delete

A TTL hard-delete frees the slug, which is alias takeover: `q4-report` expires,
is re-registered pointing elsewhere, and every copy of the old link in other
people's notes now goes to the new target. §8's own principle — "a short link
that quietly changes destination is indistinguishable from an attack" — applies
to expiry as much as to deletion.

So: keep the document, set `RevokedAt`, filter at resolve, and let a much longer
(or no) TTL handle eventual cleanup. **Reclaiming a slug is an explicit operator
action, never a background thread.**

### Hit counting

`$inc` fired into a goroutine with **`context.Background()` plus its own
timeout** — never `c.Request().Context()`, which is cancelled the instant the
redirect response completes, so the write would be aborted rather than merely
slow. `iptools.History.Record` is the shape to copy. The redirect must issue
before the write is acknowledged.

## 5. Authentication, and why the write path is closed

```
POST /short      X-Api-Key: <key>
GET  /short      X-Api-Key: <key>      (see §8)
```

- The key comes from `LINK_API_KEY`. **Empty means creation is disabled**, not
  open — the same contract as an empty `MONGODB_URI`.
- **Compare SHA-256 digests of both sides**, not the raw strings.
  `crypto/subtle.ConstantTimeCompare` returns 0 immediately on a length
  mismatch, so comparing raw keys leaks the key length. Hashing first makes both
  operands fixed-length.
- `401` on a missing or wrong key, with no hint which.
- The **redirect path stays public and unauthenticated.** Obviously.
- No public sign-up, no anonymous creation, not behind a CAPTCHA, not ever. The
  CAPTCHA version is still an open shortener with a speed bump.

## 6. Redirect safety

### Scheme, checked twice

1. **At create:** parse, require `http` or `https`. Reject `javascript:`,
   `data:`, `file:`, `intent:`, everything else.
2. **At resolve:** check the stored target's scheme *again*. A row written by an
   earlier buggy version, or by anyone who ever gets write access to the
   database, must not turn the redirect handler into a `javascript:` dispenser.

### Address, checked at create

The first draft declined IP screening on the grounds it would mean resolving
hostnames. What it declined was *resolution*; rejecting **literals** is free and
must ship.

Without it, `/s/aB3xY9k` → `http://192.168.1.1/setup.cgi?…` or
`http://127.0.0.1:9200/_cluster/settings` is a client-side SSRF and router-CSRF
launcher: the victim's own browser, on their own LAN, makes the request with
their cookies, and a scheme-only allowlist waves it through. So at create time,
reject any target whose host parses as an IP literal failing the routable check
in [06 §2](06-security-and-abuse.md#2-ssrf-the-one-that-matters), plus
`localhost` and `*.localhost`, plus any port outside 80/443.

Resolving hostnames is still declined, for the reason originally given.

### On the response

- **`302`, not `301`.** A 301 is cached by browsers effectively forever; an
  alias that can never be repointed or retired is a liability.
- **`Cache-Control: no-store`** and **`X-Robots-Tag: noindex`** — Googlebot
  follows short links and will otherwise associate `corpberry.com` with whatever
  they point at, which is §1's blocklisting threat arriving by a route the API
  key does not cover.
- **`Referrer-Policy: no-referrer`.** Belt and braces only: on a top-level
  navigation from a pasted link there is no referrer to strip, and when it is
  linked from a page the originating document's policy governs. Worth keeping;
  the alias is not reliably hidden from the destination.
- **Echo v5's `c.Redirect` calls `WriteHeader` in the same call**, so every one
  of those headers must be set on `c.Response().Header()` **before** it, or they
  never reach the wire.

## 7. Abuse controls, summarised

| Control | Value | Why |
|---|---|---|
| API key on create **and console** | required, fail-closed | The one that matters |
| Rate limit on create | 1/s, burst 5, per IP | Behind the key already |
| Rate limit on resolve | none per-IP, but see below | A redirect must be fast and public |
| Scheme allowlist | create **and** resolve | §6 |
| IP-literal / port rejection | create | §6 |
| Target length cap | 2048 bytes | Above every real browser limit |
| `note` length cap | 256 bytes | It is rendered on the console |
| Code entropy | 7 × base58 from `crypto/rand` | Generated codes only |
| Reserved slugs | [03 §3](03-architecture.md#reserved-paths) | Namespace safety |

**The uncapped resolve path is a load amplifier**, not just a fast route: each
hit is a Mongo find plus an `$inc` against the same server backing
`request_logs` and `iptools` history. Hammering `/s/aaaaaaa` — nonexistent is
fine, the lookup still happens — degrades every other tool on the box. Add an
in-process code→target cache (~60s, negative entries included) so repeated hits
cost nothing, batch the `$inc`, and keep one coarse global limiter as a circuit
breaker. Fast *and* bounded.

**404 vs 410:** use one status for both "expired" and "never existed".
Distinguishing them is an existence oracle over the guessable custom-slug
namespace.

**Considered and declined:** screening targets against `iptools.BlockList`. That
corpus is IP- and netblock-shaped, so using it would mean resolving the target's
hostname — a DNS lookup on a caller-chosen name, to defend against a threat the
API key already closes.

## 8. The console

`GET /short` is **key-gated**: the create form, and recent aliases with target,
note, hits, age and expiry, each with a revoke button.

The key travels as a **header**, never a query parameter — a parameter would
land in the server log, the browser history and any referrer. That is also why
the list arrives by htmx rather than in the initial render: a page navigation
cannot carry a custom header, so a server-rendered list could not have been
gated this way at all.

Without the key: the create form and nothing else. A public list hands over the
entire corpus with no guessing, defeating §3's entropy argument outright, and
turns `hits`/`last_hit_at` into a read-receipt oracle showing whether and when a
recipient clicked.

`created_ip` is `json:"-"` so it cannot leak through the API. **A struct tag
means nothing to a template** — the HTML view model must omit it explicitly. The
console applies the same rendering rules as Inspect
([06 §8](06-security-and-abuse.md#8-rendering-hostile-urls)), since `note` and
`target` are attacker-influenced strings.

Revoking an alias is `DELETE /short/:code`, key-gated like every other write.
Soft-delete only: `RevokedAt` is set, the document stays, and the code is never
reissued — freeing it would let a re-registered custom slug silently change
where every existing copy of that link goes. `Resolve` refuses a revoked link
from the moment of the write, because the store invalidates its cache entry
rather than waiting out a TTL.

## 9. API contract

```
POST /short                                     201
X-Api-Key: …
Content-Type: application/json

{"url": "https://example.com/very/long?utm_source=x",
 "slug": "optional",
 "ttl":  "720h",           // optional Go duration; omitted = permanent
 "clean": true,            // optional: strip trackers before storing
 "note": "optional"}

→ {"code":"aB3xY9k",
   "short":"https://link.corpberry.com/s/aB3xY9k",
   "target":"https://example.com/very/long",
   "original":"https://example.com/very/long?utm_source=x",
   "cleaned":["utm_source"],
   "expires_at":null,
   "hits":0,
   "created_at":"2026-09-25T10:04:00Z"}
```

`"clean": true` is what makes this suite cohere rather than being four tools
sharing a domain: shortening is the natural moment to strip the tracking, and
the response names what went, so it is never a silent mutation.

**The order is fixed and matters:** parse → validate → clean → **re-parse and
re-validate the cleaned result** → store. Cleaning rules only ever *delete query
parameters*; they never rewrite scheme, host, port or path. Both halves are
load-bearing, because rule tables in this genre conventionally unwrap redirect
parameters (`?url=`, `?redirect=`) — and the moment a rule can change the host,
a validation that ran before cleaning is void. A16's wrapper unwrapping is
therefore a *display* feature on Inspect and an explicit opt-in on Clean, never
part of `clean: true` on the create path.

`Original` is stored alongside the cleaned target so a rule bug is recoverable
and auditable.

Errors: `400` bad or non-http(s) URL, or an IP literal · `401` bad key ·
`409` slug taken · `429` rate limited · `503` storage off. All
content-negotiated.
