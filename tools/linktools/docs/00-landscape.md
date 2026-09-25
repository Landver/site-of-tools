# Landscape — what already exists, and where the gap is

**Verified 2026-09-25** by driving each tool live. Every claim here traces to a
report in [`reports/`](reports/), which records the probe input and the actual
output. The first draft of this doc asserted a list of gaps that turned out to
be roughly half wrong; what follows is what survived.

---

## 1. The five categories

### Query-string / URL parsers — crowded, and better than assumed

The serious free ones:

- [calcbe.com/en/tools/query-string-parser](https://calcbe.com/en/tools/query-string-parser/)
- [jsonutilities.com/query-string-parser](https://www.jsonutilities.com/query-string-parser)
- [urldecoder.org](https://www.urldecoder.org/) (needs the `www.`; bare host 403s)
- Chrome DevTools' Payload tab

**What they already do, and which we therefore do not get to claim as a gap:**

| Assumed gap | Reality |
|---|---|
| Order preservation | calcbe advertises it explicitly: "Decode raw query strings without losing the original repeated-key order" |
| Repeated keys shown as repeats | calcbe keeps them as separate rows with a duplicate count; jsonutilities emits arrays |
| An index / key / value table | jsonutilities renders exactly the table sketched in [01 A1](01-feature-inventory.md#a1-query-string-decomposition--the-flagship) |
| Recursive decoding | urldecoder.org ships it, documented, capped at 16 rounds — but as a *string* decoder with no structure at all ([report](reports/urldecoder-org.md)) |
| **Catching malformed escapes** | calcbe warns *"Some key/value pairs contain invalid percent-escape sequences"* and keeps the row raw ([report](reports/calcbe-query-string-parser.md)). This was claimed as a gap and is not |
| Round-trip | calcbe emits a normalised query string you can copy back out |
| DevTools being shallow | It isn't. Payload preserves order, shows repeats as rows, and has a view-decoded / view-URL-encoded toggle |

**What actually survives as unoccupied:**

- **Splitting delimited lists.** `subdistrictIds=6%2C7%2C8…` decodes to a comma
  soup that is still unreadable. None of the three splits it, counts it, or
  names the delimiter.
- **Showing the `+`-vs-base64 ambiguity** instead of silently choosing. The
  corpus caught the two best parsers giving **opposite answers on the same
  input** in the same minute — calcbe returns `a+b`, jsonutilities returns
  `a b` — with neither flagging it. That is the strongest evidence in the survey.
- **Parsing fragment parameters.** Both parsers discard everything after `#`;
  jsonutilities documents it. An OAuth implicit-flow token is invisible to both.
- **Recognising nested payloads** — a value that is a URL, JSON, a JWT or base64.
- **Ordered JSON output.** jsonutilities emits an *object*, so its JSON view
  loses the order its own table just preserved.
- **Speaking JSON over HTTP.** All three are client-side-only and say so.
  Nothing in the category is curl-able.
- **Working on a URL you must not visit.** DevTools only parses requests the
  browser already made. A URL pasted out of a log, a ticket or a phishing report
  has to be navigated to before DevTools can see it. This is the structural
  limitation, and it is the real wedge.

### Tracking-parameter cleaners — one serious player, and its catalog is smaller than assumed

**ClearURLs** is the real one. Measured from
[the raw catalog](https://raw.githubusercontent.com/ClearURLs/Rules/master/data.min.json)
on 2026-09-25:

| | |
|---|---|
| Providers | 206 |
| Rules | 733 |
| **Global (site-agnostic) rules** | **48** |
| Exceptions | 79 |
| Size | 106 KB |
| Licence | **LGPL-3.0** |

Two things follow. First, "thousands of rules across hundreds of sites" is wrong
by about 4×, and 206 providers is matchable. Second, the 48 global rules cover
precisely the ground this plan proposed hand-writing — so the build-vs-adopt
question is real and turns on licensing, not scale. That decision is argued in
[02 §4](02-build-fit.md#4-what-we-are-not-matching-and-the-clearurls-decision).

The shape gap is still real: ClearURLs cleans links *as you browse*. There is no
server-side, shareable, curl-able cleaner that tells you which rule removed what.

### Redirect tracers — one strong incumbent the first draft missed entirely

[**httpstatus.io**](https://httpstatus.io/) is free, ad-free, actively
maintained, traces up to 10 hops with status, headers and round-trip time per
hop, and handles 100 URLs at once. Its [API](https://httpstatus.io/api) is paid
above a free tier (€15/mo for 20k calls).

[wheregoes.com](https://wheregoes.com/) is **not** abandoned — © 2008–2026,
current, no account required, and it claims to follow **JavaScript redirects and
meta-refreshes**, which are the two things
[02 §5](02-build-fit.md#5-structurally-impossible-here) lists as impossible for
us. It has no API yet ("API" is an advertised upcoming feature).
[unshorten.it](https://unshorten.it/) is live, with a legacy API plus
destination title, description and screenshot.

So the honest remaining gap here is narrow: **a free, keyless JSON API for
redirect tracing.** Not "ad-free", not "honest", not "fast" — those are taken.

[urlscan.io](https://urlscan.io/) remains a different product: a sandboxed
headless browser that renders and records the page. Out of scope
([02 §5](02-build-fit.md#5-structurally-impossible-here)).

### Shorteners — fully commoditised, and the leaders have left

Bitly, TinyURL, self-hosted YOURLS and Shlink. [dub.co](https://dub.co/) is no
longer in this category at all — it now positions as "the modern link
attribution platform": conversion analytics, revenue attribution, affiliate
programs, with short links as the substrate.

That migration is itself the argument: the category's serious players abandoned
plain shortening years ago because there is nothing left to win. Which is
exactly why [A7](01-feature-inventory.md#a7-short-links) exists here only to
serve the extension, and is deliberately not a public service
([04 §5](04-short-links.md#5-authentication-and-why-the-write-path-is-closed)).

### Metadata / preview tools — thin, ad-supported

`opengraph.xyz`, `metatags.io`. Easy to match, low value, last thing to build.

---

## 2. The extension shelf — where the deliverable actually sits

The first draft surveyed web tools only and never looked at the category the
original request lives in. What the extension will sit beside:

- **Firefox ships "Copy Clean Link" natively**
  ([Bugzilla 1924493](https://bugzilla.mozilla.org/show_bug.cgi?id=1924493)), so
  the planned Firefox port's second menu item is redundant on arrival.
- Chrome already has several, e.g.
  [Copy Clean Link – Remove URL Tracking](https://chromewebstore.google.com/detail/copy-clean-link-remove-ur/jimbfjhnmbojbhihalhngfkcbmgnjafa).
- Shorten-from-context-menu is long established: TinyURL Extension, Context Menu
  URL Shortener, Bitly's own.

None of that makes the extension pointless — it is *ours*, pointed at *our*
alias space, with *our* rules. It does mean a Chrome Web Store listing is a
weaker proposition than it first looked, which is argued in
[05 §7](05-extension.md#7-publishing--a-decision-not-a-given).

---

## 3. What's actually unoccupied

Ranked by how confidently it survived checking:

1. **A free, keyless JSON API for parse and clean.** Every parser surveyed is
   client-side-only *by design*; every cleaner is an extension or a client-side
   page; httpstatus.io's API is paid above a free tier. This is the clearest gap
   in the survey.
2. **A URL you must not visit.** DevTools needs the browser to have made the
   request. Hosted parsers are pages you didn't write, running JS on a URL that
   may carry a token. Neither helps with a URL pasted from a log, a ticket or a
   phishing report.
3. **Delimited-list splitting and typed values.** Nothing surveyed does it.
4. **One `?u=` carried across four pages on one host.** Not a market gap — a
   house convention, the same one `dnstools` uses. Worth having, not worth
   claiming as novel.

The first draft claimed the gap was "the loop": inspect → clean → trace →
shorten, each feeding the next. That was a rationalisation. Nobody performs that
sequence. Someone decoding `subdistrictIds=6,7,8` is debugging an API and will
not shorten the result; someone tracing a suspicious link will not publish an
alias to it. These are four jobs that share a noun — which is exactly what IP
Tools and DNS Tools are, and that is fine, argued the way `dnstools` argues it
rather than dressed up as a market gap.

**Would a developer use this over DevTools + ClearURLs?** For a URL already in
their browser: no, and the page should not pretend otherwise. For a URL in a
ticket, a log, an email or a Slack message: yes. That is the entire addressable
case, and the Inspect page's copy should be written at that person.

Two structural advantages this repo has regardless:

- **Content negotiation is free.** Every page is a JSON API on the same URL with
  no extra work ([ARCHITECTURE §4](../../../docs/ARCHITECTURE.md)) — which is
  gap #1, handed to us by the existing engine.
- **The heavy work is pure.** Inspect and Clean are `net/url` plus a rule table.
  No upstream, no key, no quota, nothing to rot.

## 4. What this is deliberately not

- **Not a security scanner.** No malware verdict, no phishing score, no
  sandboxed render.
- **Not a Bitly competitor.** And not a dub.co competitor either — that ship
  sailed into a different ocean.
- **Not ClearURLs.** See [02 §4](02-build-fit.md#4-what-we-are-not-matching-and-the-clearurls-decision).
- **Not httpstatus.io.** They do bulk-100 tracing free in a browser. We do not
  compete on that axis.
- **Not an archiver.** Nothing traced or inspected is stored — subject to
  [06 §5](06-security-and-abuse.md#5-the-request-log-will-eat-pasted-urls),
  which is currently not true and must be made true.
