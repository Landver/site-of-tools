# Feature inventory — the full menu

Eighteen live features, plus one cut and kept for the record (A9) so the
reasoning isn't rediscovered later. The bar for inclusion is deliberately low:
this is a site of tools, and a useful thing that is cheap to build earns its
place without having to be a differentiator. This doc says what each *is* and why someone
would want it. Which ship is [`02-build-fit.md`](02-build-fit.md); in what order is
[`08-delivery-plan.md`](08-delivery-plan.md).

---

## A1. Query-string decomposition — *the flagship*

Take a query string apart into an ordered table of key/value pairs, decoded
properly. The feature that started this plan. Worked example, verbatim from the
request:

```
?cityIdList=95&subdistrictIds=6%2C7%2C8%2C9%2C10%2C11%2C13%2C14%2C15%2C16%2C17%2C18%2C19%2C24&currencyId=1&rooms=1%2C2
```

should render as:

| # | Key | Value | |
|---|---|---|---|
| 1 | `cityIdList` | `95` | number |
| 2 | `subdistrictIds` | `6` `7` `8` `9` `10` `11` `13` `14` `15` `16` `17` `18` `19` `24` | comma list, 14 values |
| 3 | `currencyId` | `1` | number |
| 4 | `rooms` | `1` `2` | comma list, 2 values |

Ordered output, repeated keys as rows, and recursive decoding are **table
stakes** — the incumbents already do all three
([00 §1](00-landscape.md#1-the-five-categories)). What is not yet done anywhere:

- **Delimited lists get split, and the delimiter gets named.** Comma, pipe,
  semicolon. Named, not silently applied, because `name=Smith,John` is one value
  containing a comma, not two values. **This is the differentiator.**
- **Broken escapes are reported, not swallowed.** `%zz`, a truncated `%2`.
- **`+` is ambiguous and must be shown as such.** In a query string `+` decodes
  to a space (`application/x-www-form-urlencoded`), which is what
  `url.QueryUnescape` does. When the value is base64 — where `+` is a real
  character — that reading destroys it. Where a value both contains `+` and
  looks like base64, show both readings rather than picking one.
- **Typed values.** number, bool, uuid, timestamp, url, json, jwt, base64.

Still required, even though others manage it, because getting any of these wrong
makes the page worse than the incumbents:

- **Order is preserved.** `url.Values` is a `map[string][]string` and therefore
  unordered. The query must be split by hand. This is the single most important
  implementation constraint on the page and it is easy to get wrong by reaching
  for the stdlib helper.
- **Repeated keys stay visible.** `?id=1&id=2` is two rows, the second marked.
- **Valueless and empty are different.** `?debug`, `?debug=`, and absent are
  three states.
- **Double encoding gets a ladder.** `%2520` → `%20` → space, shown as steps.
- **Legacy `;` separators are detected.** `url.ParseQuery` has rejected them
  since Go 1.17 — and returns partial values alongside the error, which is its
  own trap ([02 §1](02-build-fit.md#1-tier-0--pure-go-stdlib-only-no-network-no-state)).
- **Fragments carry parameters too.** OAuth implicit flow puts the access token
  after `#`.
- **Nested payloads are offered, not forced.** See [A3](#a3-layered-decoding).

## A2. URL anatomy

The rest of the URL: scheme, userinfo, host, port, path segments, fragment.

- **IDN, both directions.** Show `xn--80ak6aa92e.com` and `аррӏе.com` side by
  side, and flag when they differ — the classic homoglyph attack.
- **Userinfo is a phishing vector.** `https://paypal.com@evil.tld/` — the host is
  `evil.tld`. A loud note, and never a clickable link.
- **Default ports**, **dot segments**, and **path segments decoded
  individually**, because `%2F` inside a segment is not a separator.

## A3. Layered decoding

"Decode until it stops changing", capped in depth. Percent, base64 and base64url,
JSON, JWT (header and payload only — never claim to verify a signature), and
URL-in-URL. Powers A1's expandable sub-views and stands alone as a page.

## A4. Tracking-parameter removal

Strip `utm_*`, `fbclid`, `gclid`, `gbraid`, `wbraid`, `msclkid`, `mc_eid`,
`igshid`, `si`, `ref`, `_ga`, `yclid`, `ttclid`, `srsltid` and friends. Output
names every parameter removed and the rule that removed it, so it is auditable
rather than magic. Rule sourcing is an open decision —
[02 §4](02-build-fit.md#4-what-we-are-not-matching-and-the-clearurls-decision).

## A5. Canonicalisation

Lossless-ish normalisation, kept separate from A4 because A4 is lossy: lowercase
scheme and host, strip the default port, resolve dot segments, normalise
percent-encoding case, drop a trailing `?` or empty `#`, IDN-normalise. Sorting
query parameters is **optional and off by default** — it makes two URLs
comparable and breaks signed ones.

## A6. Redirect tracing

Follow `3xx` hops one at a time: status, `Location`, elapsed ms, final URL.

Honesty requirements: detect `<meta http-equiv="refresh">` **and the `Refresh:`
HTTP header**, which is widely honoured and easy to miss; name a JS-driven
redirect as unfollowable rather than reporting the pre-redirect URL as final;
distinguish "the target refused an automated request" (403/503 from bot
protection) from "broken".

## A7. Short links

Create an alias for a URL; resolve it. Custom slugs, optional expiry, a hit
counter. The half the extension needs. Full treatment in
[`04-short-links.md`](04-short-links.md).

## A8. Link metadata preview

Fetch a URL and render its `og:*` / `twitter:*` tags — what it looks like pasted
into Slack. Flags relative `og:image`, missing dimensions, images behind auth.

## A9. ~~Bulk link check~~ — cut

Dropped, and the reason is abuse rather than crowding — a "useful and easy"
feature that still shouldn't ship. Fanning out N caller-supplied fetches per
request is the easiest thing in this inventory to turn into a DDoS amplifier
with our Hetzner IP as the source, and this project has already shelved the
`iptools` port scanner over exactly that risk.

That it is also thoroughly occupied — [httpstatus.io](reports/httpstatus-io.md)
does free bulk-100 tracing in a browser — just removes any reason to take the
risk.

## A10. QR code

A QR for the current URL as SVG. Pairs with A7: shorten, then show the QR.

The only feature in the suite that adds a module to `go.mod` — but `rsc.io/qr`
is small and has no transitive dependencies, so the cost is one line in
`go.mod`, not a dependency tree. Cheap enough to be worth it.

## A11. UTM / campaign builder

The inverse of A4. Trivial, genuinely used. The only feature here aimed at a
non-developer audience on a developer's portfolio — deliberate, on the grounds
that the Clean page will attract exactly that person and sending them away
empty-handed is a waste.

## A12. IDN / punycode converter

Standalone A2 conversion plus a confusables check: flag more than one Unicode
script in a single label. **The script data comes from the stdlib's
`unicode.Scripts` range tables, not from `x/net/idna`**, which exposes no script
information.

## A13. URL diff

Two URLs in, a field-by-field and parameter-by-parameter diff out. The "why does
staging behave differently from prod" tool. Reuses A1's structs entirely — a
second template, not new logic.

## A14. Encode / decode playground

Percent-encode (query rules vs path rules — they differ), base64 and base64url,
HTML entities, unicode escapes. A scratchpad.

Crowded and undifferentiated: [urldecoder.org](reports/urldecoder-org.md) owns
this category and there are a hundred SEO farms behind it. Kept anyway, because
every operation is already implemented for A3's ladder, so exposing them as a
page is a template and a route rather than new logic. It is also the page people
search for by name, which makes it the cheapest traffic in the suite.

The one thing to do better than the incumbents: **show query-vs-path encoding
side by side.** `a+b` is `a b` in a query and `a+b` in a path
([go-url-stdlib-behaviour.md §3](reports/go-url-stdlib-behaviour.md)), and no
tool surveyed makes that visible.

## A15. Round-trip edit

**The strongest answer to "why not DevTools."** The Inspect table's value cells
become inputs. Change one, delete a row, reorder rows, and get a correct URL back
out — with the right encoding rules per position, since query, path and fragment
differ.

Zero network, zero state. It is the *write* half of the `Inspection` struct
[03 §2](03-architecture.md#2-domain-types) already defines: an htmx form over
the existing fragment plus a `Rebuild(Inspection) string`. DevTools shows you
the parse and then makes you hand-edit the raw string; calcbe emits a normalised
query but not an edited one.

## A16. Known-wrapper unwrap

Microsoft SafeLinks, Proofpoint `urldefense`, `l.facebook.com/l.php?u=`,
`google.com/url?q=`, LinkedIn's `lnkd.in` interstitial params.

Pure string work: a percent-decode of a named query parameter. No network, no
dependency, **no SSRF surface**. The plan otherwise reaches these only through
A6 Trace — the one feature carrying the entire security surface, gated behind a
maybe-ship decision — when the common cases need no fetch at all.

A rule table sharing A4's shape, surfaced as a note on Inspect ("this is a
SafeLinks wrapper; the real target is …") and as an explicit step in Clean. It
is also the one thing in this suite a non-developer would use repeatedly, since
corporate email rewrites every link they receive.

## A17. User-agent persona on Trace

Ask the target as Googlebot, Slackbot, Twitterbot, GPTBot or an ordinary
browser, and say which one answered.

Stolen wholesale from [httpstatus.io](reports/httpstatus-io.md), which offers 27
personas. It costs one dropdown and one request header, and it converts our
biggest honesty problem into a feature: when the browser UA gets a 403 and
Googlebot gets a 200, the tool can state that the target **discriminates by user
agent**, instead of reporting a dead link
([02 §5](02-build-fit.md#5-structurally-impossible-here)).

Only meaningful if A6 ships.

## A18. Link extractor

Paste HTML, Markdown, an email body or any text; get every URL out, deduplicated,
counted, with the anchor text where there is one. Feeds straight into Clean
(strip trackers from all of them) and into Inspect (click one through).

Pure `regexp` plus `x/net/html` when the input looks like markup. No network.
The "audit every link in this newsletter before it goes out" job, which is real
and which nothing in the survey does without also fetching every URL.

## A19. `curl` command builder

A URL in, a runnable `curl` line out: properly quoted, `-H` flags for a chosen
user-agent persona, `-L` or `--max-redirs 0`, `-i`. And the inverse — paste a
`curl` command, get the URL parsed by A1.

Trivial, and the inverse direction is the genuinely useful half: people paste
`curl` lines out of documentation and browser "Copy as cURL" constantly, and
nothing takes one apart.

## A20. Percent-encoding reference

A static table: which characters are reserved, which are safe in a path vs a
query vs a fragment, what RFC 3986 actually says, and the `+`-in-a-query special
case with a worked example.

Zero logic, one template. It exists because every one of these features leads
someone to the same question, and because a reference page that is correct is
the cheapest durable traffic on a tools site.

---

## Which of these are actually one feature

Worth noticing before anything is built, because it collapses the file count:

- **A1 + A2 + A3 + A12 + A15 are one parser** with five views, one of them
  writable. One `Parse` and one `Rebuild` feed all of them.
- **A4 + A5 + A16 are one page** ("clean this"), three rule sets.
- **A13 is a second rendering of A1's output**, not new logic.
- **A6 + A8 share one HTTP client** and one egress gate — build the gate once,
  correctly ([06 §2](06-security-and-abuse.md#2-ssrf-the-one-that-matters)).
- **A7 shares nothing** with anything else, and is the only stateful feature in
  the suite. **A10** hangs off it.
- **A14 and A20 are A3's internals, exposed** — a page and a template each, no
  new logic.
- **A18 and A19 are input adapters**: both end in a call to `Parse`, so they are
  new front doors onto A1 rather than new features.

## The cheap half

Ranked by lines-of-code per unit of usefulness, for when there is an hour rather
than a weekend: **A13** (URL diff — a template over existing structs), **A20**
(reference page — no logic), **A19** (`curl` builder), **A11** (UTM builder),
**A14** (encode/decode — A3 exposed), **A18** (link extractor). None needs a
network call, a dependency or a database, and every one of them is a page that
works the day it ships.
