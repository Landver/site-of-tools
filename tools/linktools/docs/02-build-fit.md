# Build fit — the menu filtered through this stack

Constraints in scope, from `CLAUDE.md` and
[`ARCHITECTURE §1–2`](../../../docs/ARCHITECTURE.md): one Go binary
(`CGO_ENABLED=0`, distroless, ~16 MB), Echo v5 + htmx + Tailwind standalone,
**no Node ever**, Mongo optional and nil-safe, one Hetzner box behind Cloudflare
and nginx, no budget for paid data.

Headline: **most of this suite is `net/url` and a rule table**, and Tier 0 adds
**zero new modules** — thirteen of twenty features need no network, no state and
no dependency. Unlike `dnstools`, which needed a UDP egress test before a
line could be written, Tier 0 here has no blocking technical unknown at all. It
does have one blocking *policy* unknown — see [§6](#6-the-blocker-before-phase-0).

---

## 0. Why its own subdomain

`dnstools` argued this explicitly and this plan should too. URL tooling could
live as tabs inside `ip.corpberry.com`, which would cost nothing: no DNS record,
no nginx block, no fourth SEO surface, no fourth README to keep current.

**Own subdomain anyway. Confidence ~75%.** Three reasons: the suite is five-plus
pages, which is too many to bolt onto another tool's nav; the short-link
redirect needs a path namespace of its own on a host where nothing else claims
short paths; and the extension talks to a fixed origin, which reads better as
`link.corpberry.com` than as a path under the IP tool. The cost is real and
recurring — a fourth subdomain is a fourth thing to keep alive — and moving it
later would still be one `Register` call and one vhost entry.

## 1. Tier 0 — pure Go, stdlib only, no network, no state

**Zero new modules.** `golang.org/x/net v0.57.0` is already a **direct**
requirement in `go.mod`'s main require block (pulled in by Echo v5 via
`x/net/http2`, and by `miekg/dns`). `x/net/idna` and, later, `x/net/html` are
packages inside a module that is already there: `go.mod` does not change and
`make deps` is a no-op.

| Feature | Built from | Notes |
|---|---|---|
| A1 query decomposition | `net/url`, `strings` | **Do not use `url.ParseQuery` for display** — it returns a map and loses order. Hand-split on `&`, then `url.QueryUnescape` per side. Keep `ParseQuery` only as a cross-check, comparing **key sets, not `err == nil`**: since Go 1.17 it returns partial values *alongside* `invalid semicolon separator in query`, silently dropping the offending pair. That error is the detection signal for the `?a=1;b=2` case |
| A2 URL anatomy | `net/url`, `x/net/idna` | `url.ParseRequestURI` differs from `url.Parse` in exactly two ways: it rejects relative references, and it does **not** split a `#fragment` (the fragment lands in `RawQuery`). It adds no validation of hostile schemes or userinfo — it accepts `javascript:alert(1)` and `https://paypal.com@evil.tld/` identically. Use it only for the missing-scheme check, with the fragment stripped first, or every URL with a `#` is reported as a disagreement |
| A3 layered decoding | `encoding/base64`, `encoding/json` | Cap ladder depth and output size. A nested-base64 bomb is cheap to make ([06 §7](06-security-and-abuse.md#7-decode-ladder-exhaustion)) |
| A4 tracking strip | a rule table — sourcing is [§4](#4-what-we-are-not-matching-and-the-clearurls-decision) | The only hand-maintained data in Tier 0 |
| A5 canonicalisation | `net/url`, hand-rolled `remove_dot_segments` | **`path.Clean` is wrong three times over**: it operates on `u.Path`, which is already percent-decoded, so `%2F` becomes a separator; it drops the trailing slash RFC 3986 §5.2.4 preserves after a final `.`/`..`; and it maps `""` to `"."`. Split `u.EscapedPath()` on `/`, resolve over the escaped segments, and `url.PathUnescape` each only for display |
| A11 UTM builder | `net/url` | An afternoon |
| A12 IDN / punycode | `x/net/idna` + **stdlib `unicode.Scripts`** | idna exposes no script data; the mixed-script check — A12's whole differentiator — comes from the stdlib range tables |
| A13 URL diff | A1's own structs | A second template over an existing parse |
| A15 round-trip edit | `net/url` + an htmx form | `Rebuild(Inspection) string`. Mind that query, path and fragment have different escaping rules — `url.QueryUnescape("a+b") == "a b"` but `url.PathUnescape("a+b") == "a+b"`, and using the wrong one renders `/a+b/` as `/a b/` |
| A16 wrapper unwrap | a rule table | SafeLinks, urldefense, `l.facebook.com`, `google.com/url`. Offline-decodable wrappers only — `t.co` and `lnkd.in` are opaque and belong to A6 |
| A14 encode/decode | already written for A3 | A page and a template, not new logic |
| A18 link extractor | `regexp`, `x/net/html` | An input adapter onto `Parse` |
| A19 `curl` builder | `net/url`, `strings` | Both directions; the parse-a-curl-line half is the useful one |
| A20 encoding reference | one template | No logic at all |

## 2. Tier 1 — outbound HTTPS

Mirrors `iptools/shodan.go` and `dnstools/domain.go`: a small client with an
injected base URL and timeout, `nil` meaning "feature off", never fatal.

| Feature | Caveat |
|---|---|
| A6 redirect trace | **Carries the entire SSRF surface of this suite.** Nothing else dials a caller-chosen host. Read [`06`](06-security-and-abuse.md) before writing a line of it |
| A17 user-agent persona | One dropdown, one header, only meaningful with A6. Turns "the target refused us" from an apology into a finding |
| A8 metadata preview | Same gate as A6, plus an HTML parse (`x/net/html`, already in the module graph) and a body-size cap |

Outbound 443 is already proven in production by `iptools`' Shodan client and
`dnstools`' RDAP/crt.sh clients, so **no egress test is needed before starting**
— unlike the DNS tool, which had to verify UDP/53 first.

## 3. Tier 2 — state or a new dependency

| Feature | Verdict |
|---|---|
| A7 short links | **Build it.** Mongo collection, an API key, a reserved-path list, open-redirect handling. [`04`](04-short-links.md) |
| A10 QR code | **Build it, after A7.** The only feature that adds a module to `go.mod`, but `rsc.io/qr` is small with no transitive dependencies, so the cost is one `go.mod` line rather than a dependency tree |

## 4. What we are not matching, and the ClearURLs decision

**ClearURLs, measured 2026-09-25:** 206 providers, 733 rules, **48 global
site-agnostic rules**, 79 exceptions, 106 KB, **LGPL-3.0**. The global block
covers precisely the ground this plan proposed hand-writing —
`utm(?:_[a-z_]*)?`, `fbclid`, `gclid`, `srsltid`, `msclkid`, `mc_(?:eid|cid|tc)`,
`__hstc`, `_ga`, `_gl`, `yclid`, `dclid`, `spm`. A Go implementation exists
([`ddlsmurf/clearurls-go`](https://pkg.go.dev/github.com/ddlsmurf/clearurls-go/clearurls),
LGPL-3.0, 13 deps).

106 KB is trivially embeddable in a 16 MB binary. **The blocker is licensing:
this repo is MIT.**

> **Open decision.** (a) Hand-write ~60 global rules and state the scope,
> accepting duplicated effort against a public list. (b) Embed ClearURLs' LGPL-3.0
> catalog with attribution, accepting an LGPL data file inside an MIT repo.
> (c) Fetch it at runtime, keeping it out of the binary and out of the licence
> question, at the cost of a network dependency on an otherwise pure feature.
>
> **Lean: (a) for v1, ~60%**, on licence grounds, with the rule table structured
> so (b) or (c) is a drop-in.

Also not matching:

- **httpstatus.io.** Free bulk-100 tracing in a browser. We do not compete there;
  A9 is cut because of it.
- **urlscan.io.** Their product renders the page in a real browser. That needs a
  headless browser: heavyweight, Node-adjacent, and a standing security
  liability on a box that also serves a portfolio.
- **Safe Browsing / malware verdicts.** Needs an API key and, more to the point,
  publishing "this link is safe" on a personal domain is liability with no
  upside.

## 5. Structurally impossible here

The pages should say so rather than quietly producing a wrong answer:

| Wanted | Why not |
|---|---|
| Following a JavaScript redirect | Needs a JS engine. **Note that wheregoes.com does this**, so it is not impossible in general, only impossible for an HTTP client. Detect and name it; never report the pre-redirect URL as final |
| Tracing a chain behind bot protection | Cloudflare and friends will serve our datacentre IP a 403 or a challenge. Honest output is "the target refused an automated request", not "dead link" |
| Tracing a link that needs a session | A one-time or authenticated link resolves differently for us, or burns the token |
| "% of trackers removed" as a score | Unfalsifiable without a ground truth we don't have |
| Knowing whether a short link was *created* by us | Only for our own codes |

## 6. The blocker before Phase 0

`platform/requestlog.go` persists the request URI for every non-static request
into Mongo (TTL 30 days), and `platform/app.go` logs it to stdout first. On this
host the URI *is* the user's pasted URL, tokens and all. That is a privacy
defect this tool introduces into shared infrastructure, and it needs a decision
and a fix before the Inspect page is reachable.
[06 §5](06-security-and-abuse.md#5-the-request-log-will-eat-pasted-urls).

## 7. Phases

See [`08-delivery-plan.md`](08-delivery-plan.md). Tiers answer "what can this
stack do"; phases answer "in what order", and keeping both tables here meant
maintaining the same content twice.
