# Link Tools (`link.corpberry.com`) — build plan

**Status: building.** These docs were the plan; `tools/linktools/` is now the
implementation. Where the two disagree, the code is right and the doc is stale —
say so rather than "fixing" working code to match a sentence here.

Decisions 1–4 below were taken during the build, per their documented leans, and
are recorded in [`08` §Decisions](08-delivery-plan.md#decisions).

A suite of URL tools on one subdomain, switched by sub-nav, in the same shape as
[`iptools`](../../iptools/docs/README.md) and
[`dnstools`](../../dnstools/docs/README.md). Named "Link Tools", not "URL
Shortener", for the same reason DNS Tools isn't called "DNS Lookup": shortening
is one of twenty candidate features, and the flagship page — taking a URL
apart — isn't shortening at all.

## What is planned to ship

| Page | What it does | Network? | State? |
|---|---|---|---|
| **Inspect** (`/`) | A URL taken apart: scheme, host (IDN both ways), port, path segments, and the query decomposed into an ordered key/value table with percent-decoding, repeated keys kept visible, **delimited lists split and the delimiter named**, and nested encodings unwrapped. Values are editable and the URL rebuilds | none | none |
| **Clean** (`/clean`) | Strips tracking parameters against a curated rule table, unwraps SafeLinks/urldefense-style wrappers, canonicalises the rest, and names every parameter removed and the rule that removed it | none | none |
| **Short** (`/short`, `/s/:code`) | Creates and resolves aliases. Write side and console are API-key gated, always | none | Mongo |
| **Trace** (`/trace`) | Follows the redirect chain hop by hop without a browser. *Optional — see the decisions below* | outbound HTTPS | none |
| *Preview* (`/preview`) | OG/Twitter-card metadata | outbound HTTPS | none |

Plus a browser extension that adds **Copy Short Link Address** to the right-click
menu on any link, talking to the same JSON endpoints.

Every page speaks HTML + JSON + an htmx fragment from one URL, like every other
tool here.

## Read in this order

| Doc | What it settles |
|---|---|
| [`00-landscape.md`](00-landscape.md) | What already exists, verified against the live products; where the gaps actually are |
| [`01-feature-inventory.md`](01-feature-inventory.md) | The menu — nineteen live features, one cut with reasons, and which half is cheap |
| [`reports/`](reports/) | The research corpus: every competitor driven live, one report each |
| [`02-build-fit.md`](02-build-fit.md) | The menu filtered through this stack. Tiers, the ClearURLs licence question, what's honestly impossible |
| [`03-architecture.md`](03-architecture.md) | Package layout file by file, the domain types, the route table, the `main.go` wiring diff |
| [`04-short-links.md`](04-short-links.md) | The one stateful, abusable feature: codes, collisions, schema, auth, redirect safety |
| [`05-extension.md`](05-extension.md) | The extension: the MV3 clipboard trap, menu mechanics, and whether to publish at all |
| [`06-security-and-abuse.md`](06-security-and-abuse.md) | The cross-cutting threat model. **Read before writing `trace.go`** |
| [`07-testing.md`](07-testing.md) | What's table-driven, what needs fakes, what needs the loopback seam |
| [`08-delivery-plan.md`](08-delivery-plan.md) | Phase order, acceptance criteria, and **the canonical decision list** |

## Decisions the owner needs to make

Four, all in [`08` §Decisions](08-delivery-plan.md#decisions) with reasoning,
leans and confidence. In short:

1. **Request-log redaction** — a `platform/` change across all four subdomains.
   **Blocks Phase 0.**
2. **Tracking-rule sourcing** — hand-write, or embed an LGPL-3.0 catalog into an
   MIT repo, or fetch at runtime.
3. **Does `/trace` ship at all?**
4. **Publish the extension, or keep it unpacked?**

## Provenance

Three passes.

1. A desk survey.
2. Four adversarial reviews — Go and repo-convention fit, security, product
   scope, browser-platform fact-checking.
3. **A firsthand corpus** in [`reports/`](reports/): every competitor driven
   live against one shared probe URL, the Go stdlib behaviours executed rather
   than recalled, and the ClearURLs catalog measured rather than estimated.

Each pass overturned something load-bearing. The first draft claimed competing
parsers don't preserve order, show repeats or decode recursively — all three
were wrong. It missed [httpstatus.io](reports/httpstatus-io.md) entirely, the
strongest incumbent in the tracing category. It overstated ClearURLs' catalog by
about 4×. It got the MV3 clipboard mechanism wrong in a way that would have cost
a day of debugging — an offscreen document can't use `navigator.clipboard`
either. And it proposed `path.Clean` for URL normalisation, which silently turns
`/a%2Fb/c` into three path segments.

What the corpus bought that citation alone didn't: the observation that
[calcbe](reports/calcbe-query-string-parser.md) and
[jsonutilities](reports/jsonutilities-query-string-parser.md) return **opposite
answers for `q=a+b`** on the same input, neither flagging it. That is now the
strongest single argument in the plan, and no amount of reading about those
tools would have produced it.

## What shipped

Built 2026-09-25. Every page speaks HTML + JSON + an htmx fragment from one URL.

| Route | Feature | Network | State |
|---|---|---|---|
| `/` | Inspect (A1, A2, A3, A12, A15) | none | none |
| `/clean`, `/clean/rules` | Clean + unwrap (A4, A5, A16) | none | none |
| `/diff` | Compare two URLs (A13) | none | none |
| `/curl` | URL ⇄ curl, both directions (A19) | none | none |
| `/extract` | Links out of pasted text (A18) | none | none |
| `/utm` | Campaign builder (A11) | none | none |
| `/encode` | Encode/decode playground (A14) | none | none |
| `/encoding` | Percent-encoding reference (A20) | none | none |
| `/trace` | Redirect chain + UA personas (A6, A17) | HTTPS out | none |
| `/short`, `/s/:code` | Short links (A7) | none | Mongo |
| `/extension/privacy` | For the extension listing | none | none |

Plus `tools/linktools/extension/` — MV3, no build step, load-unpacked.

**Engine changes this required**, both shared by all four subdomains:

- `platform/redact.go` — strips the value of `u`/`a`/`b`/`curl`/`text`/`v` from
  the request URI, called once in `LogValuesFunc` so it catches the stdout log
  *and* the Mongo corpus. `v` is `/encode`'s input, which makes it the likeliest
  key in the suite to carry a pasted token. It hand-splits rather than using
  `url.Query()`, which silently drops any pair containing a malformed escape — a
  value like `?u=%zz%SECRET` would otherwise be invisible to the redactor and
  perfectly visible in the log. `/static/` paths are exempt: `AssetVersioner`
  hangs `?v=<content hash>` off every asset URL, so without the exemption `v`
  would turn every static log line into `?v=<redacted>` — unreadable, and
  protecting nothing, since no user input reaches a `/static/` query.
- `platform/netgate.go` — `PubliclyRoutable` promoted from `botcheck` (the only
  complete copy of four in the repo) and extended with the ranges none of them
  covered, plus `EgressGuard` (a `Dialer.Control` hook, a port allowlist and a
  host deny list) and `RateLimitKey`, which keys IPv6 on the /64 because a
  per-address bucket is not a limit when the client holds 2⁶⁴ of them.

### Not built

- **A8 metadata preview** and **A10 QR** — both specified, neither written.
- **A9 bulk check** — cut on abuse grounds, not crowding.
  [01 A9](01-feature-inventory.md).
- **Chrome Web Store listing** — decision 4. The extension is load-unpacked.
