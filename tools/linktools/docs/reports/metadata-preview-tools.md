# OG / metadata preview tools

**Driven 2026-09-25.** `https://www.opengraph.xyz/` and `https://metatags.io/`

The [A8](../01-feature-inventory.md#a8-link-metadata-preview) category. Two tools
with opposite failure modes: one validates and is honest about being blocked, one
validates nothing and will show you a preview of the wrong website without
saying so.

## Method

Same probe URL for both, plus two variants:

| Probe | Why |
|---|---|
| `https://github.com/` | Complete `og:*` **and** `twitter:*`, and — verified — **no `og:image:width` / `og:image:height`** |
| `http://github.com/` | `301` to `https://`. Does the tool follow it, and does it tell you? |
| `https://www.g2.com/` | Returns `403` to automated clients (Cloudflare). The bot-block honesty test |

Ground truth from `curl` on this machine. GitHub declares `og:site_name`,
`og:title`, `og:description`, `og:image`, `og:image:alt`, `og:type` (`object`),
`og:url`, and `twitter:card` / `site` / `title` / `description` / `image`. A grep
for `og:image:(width|height)` returns **0**. The image itself is
`1200×630`, `618778` bytes (604 KB), `image/png`.

## Side by side

| | opengraph.xyz | metatags.io |
|---|---|---|
| Platform previews | Facebook, X, LinkedIn, WhatsApp, Discord, raw tags | Google SERP, X, Facebook, LinkedIn, **Pinterest**, **Slack** |
| Validation | **0 errors / 4 warnings / 9 passes** | None. Character counts only |
| `og:image:width` missing | **Not flagged** — measures the file instead | Not flagged |
| Follows redirects | Yes, silently | Yes, **and rewrites the input to the final URL** |
| Blocked site | **Names the block, publishes its egress IPs** | **Silently shows the previous site's preview** |
| schema.org | No | No — links out to Google's tool |
| Editable / round-trip | No | Yes, with a "Get Code" emitter |
| Public API | None | `/api/hello`, origin-gated, `403` from outside |
| Cookie consent | Yes. "Reject All" at top level | None presented |

Between them they cover eight surfaces. Neither covers all of them; **Slack is
metatags.io only, Discord and WhatsApp are opengraph.xyz only.**

## opengraph.xyz

Cookie dialog on arrival, with `Reject All` and `Accept All` side by side at the
top level — rejected, and it stuck across a reload. Better than most.

### The inspector is the best thing in this report

A scored panel: 0 errors, 4 warnings, 9 passes, each tagged with the tag it
judged. The four warnings on `github.com`, verbatim:

> **Image is missing conversion text** — `og:image`
> No a call-to-action was detected. Adding one can make the image more clickable. *[sic]*
>
> **Description is too long** — `og:description`
> 186 characters — social previews often show ~125 characters and may truncate on mobile.
>
> **Page title is too long** — `title`
> 61 characters — Google typically truncates titles over ~60 characters in search results.
>
> **Meta description is too long** — `description`
> 190 characters — Google typically truncates around 150–160 characters in search results.

Every warning carries the **number and the threshold**, not just a verdict. That
is the pattern worth copying.

The first one is not a technical check at all — it is upsell surface, wired to an
"Improve image" button that opens their template generator. The product is a
paid OG-image generator with a free linter attached.

### The dimension check is measured, not read

The most useful finding here. It passed with:

> **Image dimensions are perfect** — `og:image`
> 1200×630 — matches what every major platform expects.
>
> **Image loads cleanly** — `og:image`
> 604 KB image/png

Both numbers match my `curl` byte-for-byte: `1200×630`, `618778` bytes = 604 KB,
`image/png`. So it **downloads the image and measures it** — which is why it can
also tell you an image is behind auth or 404s.

But GitHub declares **no `og:image:width` or `og:image:height` at all**, and
opengraph.xyz never says so. It reports measured dimensions in the slot where a
reader will assume declared ones. Platforms that lay out the card before the
image arrives get nothing from GitHub here, and the tool rates it "perfect".

Neither tool flags undeclared dimensions. Checking `theverge.com` and
`bbc.com/news`, neither of those declares them either — so this is the common
case, not an edge case, which is what makes the missing check worth having.

### The raw-tags tab is a re-emission, not a dump

A `</>` tab shows "the tags". It is not what the page served. Two discrepancies:

- **`og:type` and `og:image:alt` are missing.** GitHub serves both
  (`og:type` = `object`). They do not appear.
- **Entities are double-escaped in one field and correct in the next.** GitHub's
  source has `Join the world&#39;s most widely adopted` in *both*
  `name="description"` and `og:description`. opengraph.xyz renders
  `og:description` as `world's` — correct — and `description` as
  `world&amp;#39;s`. Same source escape, same pane, two treatments.

So the tab you would reach for to check what is actually on the page is the one
that cannot be trusted to show it.

### Blocked sites, done right

`https://www.g2.com/` produced no preview and this instead:

> Access to this website is blocked. To allow our scanner through, add these IP
> ranges to your firewall: 74.220.48.0/24 and 74.220.56.0/24.

It names the block as a block, and it publishes its egress ranges so a site owner
can allowlist it. This is the single best behaviour observed across both link
reports.

### Redirects, API, caching

`http://github.com/` scanned fine, with an identical 0/4/9 result — so it follows
the `301`. But **the input box still read `http://github.com/`** afterwards and
nothing named the final URL. It follows silently.

No public API: the scan runs as a Next.js server action, and the nav carries only
Scan / Generate / Short Links / Pricing, no docs. The second scan of the same
destination returned in under 3s against roughly 8s cold — consistent with
caching, though that is one observation and not proof.

## metatags.io

No cookie dialog. The layout is an **editable** form (image, title, description,
each with a live character count) beside a stack of previews — the closest thing
in either link report to [A15](../01-feature-inventory.md#a15-round-trip-edit).

It renders six surfaces: Google, X, Facebook, LinkedIn, Pinterest, **Slack**. It
also links out to the platforms' own debuggers — Facebook, X, LinkedIn, and
**Structured Data** — which is a tidy admission that it does not read schema.org
itself and that only the platform is authoritative.

It takes the 61-character `<title>` rather than the 52-character `og:title` for
its cards, where opengraph.xyz uses `og:title`. Same page, two different
headlines, neither tool mentioning that the two tags disagree.

**It flags nothing.** No errors, no warnings, no thresholds. The only guidance is
a greyed "Recommend 1200×628" label over the image well and the raw counts `61`
and `186`.

### The stale-result bug

The headline finding, and it is bad.

Scanning `https://www.g2.com/` right after `https://github.com/` returned a fully
rendered preview: the URL line reads `https://www.g2.com/`, and the title,
description and image are **still GitHub's**. Six platform cards, all showing
GitHub's artwork, all labelled g2.com.

The network layer shows what happened:

```
GET https://metatags.io/api/hello?url=https:%2F%2Fwww.g2.com%2F → 400
```

The fetch failed with a `400` and the UI **said nothing, kept the previous parse,
and relabelled it with the new URL**. That is worse than unshorten.it reporting
"no title available" for the same blocked site: this one manufactures a confident,
plausible, entirely wrong answer. Anyone checking a client's link against a
blocked site gets a green light.

### Redirects

Tested on a **fresh page load**, since stale state would otherwise confound it:
`http://github.com/` in, and the input box came back reading
`https://github.com/`, with the Google preview showing the `https://` URL. It
follows the redirect **and** surfaces the final URL by rewriting your input —
more than opengraph.xyz does. Still no hop, no status code.

### "Get Code" is a generator, not a round trip

The button emits a block to paste into `<head>`. Given `https://github.com/`, it
produced (trimmed):

```html
<meta name="title" content="GitHub · Change is constant. GitHub keeps you ahead. · GitHub" />
<meta property="og:type" content="website" />
<meta property="og:image" content="https://metatags.io/images/meta-tags.png" />
<meta property="twitter:card" content="summary_large_image" />
<meta property="twitter:image" content="https://metatags.io/images/meta-tags.png" />
```

Four defects in five lines:

1. **`og:image` is metatags.io's own logo.** The preview panes two inches away
   are rendering GitHub's real 1200×630 image; the code emits
   `metatags.io/images/meta-tags.png`. A modal warning does say *"Be sure to
   upload your image to your CMS or host"*, which hints at it without ever saying
   "we replaced your image with ours".
2. **`og:type` is fabricated.** GitHub declares `object`; the output says
   `website`. It is emitting a default in the slot where it read a real value.
3. **`twitter:*` uses `property=`** where GitHub's source and the X card spec both
   use `name=`.
4. **`<meta name="title">` is invented.** Not a tag GitHub serves, and not part of
   any spec.

This is calcbe's failure exactly
([calcbe](calcbe-query-string-parser.md#one-inconsistency-worth-recording)): the
display pane is faithful and the copy button quietly rewrites the data. Second
independent sighting of the same bug class in this corpus.

### API

`/api/hello?url=…` is the endpoint the page uses. Called from outside the browser
it returns `403` with `{"error":3}`, for `github.com` and `g2.com` alike. Origin
or referer gated. There is **no public API**, documented or otherwise.

## For us

**Closes.** Per-platform preview rendering is done, twice, and well — between
these two you can see a link as Google, X, Facebook, LinkedIn, Pinterest, Slack,
WhatsApp and Discord. A8 should not claim "shows you what it looks like in Slack"
as a differentiator. Nor should it claim tag extraction, image fetching, or
image-dimension measurement; opengraph.xyz does all three and reports bytes and
content-type with them.

Also closes: **nobody offers an API here either.** Same conclusion as the
[unshortener report](unshorten-it.md) — one public endpoint exists and it is
origin-gated to `403`. If we want this, we fetch it ourselves, which A8 already
assumes.

**Leaves open.** Three of A8's four stated checks are genuinely unoccupied:

- **Missing `og:image:width` / `og:image:height` is flagged by neither**, and
  opengraph.xyz actively papers over it by substituting a measured size. GitHub,
  The Verge and BBC News all omit these tags, so this fires on most real input.
- **Relative `og:image`** — untested here because none of the probe sites had one,
  so this stays an open claim rather than a closed gap.
- **`og:title` vs `<title>` disagreement.** Each tool silently picks a different
  one. Saying "these two disagree, here is what each platform will use" is free
  and nobody does it.
- **schema.org** is read by neither. metatags.io links out for it.
- **The hop is invisible** in both, same as the unshortener category. A6 and A8
  sharing one HTTP client
  ([inventory](../01-feature-inventory.md)) means we get "followed 2 redirects to
  here, then read the tags" for free, and that is a combination neither category
  offers.

**Worth stealing, in order.**

1. **opengraph.xyz's blocked-site message.** Name the block, and publish the
   egress IPs so an owner can allowlist. Directly satisfies A6's requirement to
   distinguish "refused" from "broken", and it is a better answer than anything
   in the unshortener report.
2. **Warnings that carry the number and the threshold** — "186 characters —
   previews often show ~125" rather than "description too long". Cheap, and it
   makes the check auditable in the same way A4's rule-naming does.
3. **The error / warning / pass counter.** Showing the passes, not just the
   problems, is what makes an empty result trustworthy instead of ambiguous.
4. **metatags.io's outbound links to the official debuggers.** Conceding that
   only Facebook's own scraper is authoritative costs nothing and buys the page
   credibility we would otherwise have to claim.

**Worth stealing as a warning.** metatags.io's stale preview is the strongest
argument in the corpus for A8 failing loudly: a preview tool that renders a
confident card for a site it never reached is actively worse than no tool. If our
fetch fails, the card must not render at all.
