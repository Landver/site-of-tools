# unshorten.it — the unshortener category

**Driven 2026-09-25.** `https://unshorten.it/` — plus `https://unshorten.me/`,
which is alive and is a different company.

Both are alive. Neither shows a hop. That is the whole category finding, and it
holds at the API level as well as in the UI, so it is not a rendering choice.

## Method

Ground truth first, from `curl -L -D -` on this machine, so the reports compare
against a known chain rather than against memory. Four probes:

| Probe | Real chain | Hops | `curl` total |
|---|---|---|---|
| `http://github.com/` | `301` → `https://github.com/` `200` | 1 | 0.917s |
| `http://bit.ly/GVBQJS` (**their own** advertised sample) | `301` → `http://www.unshorten.it/` → `301` → `https://www.unshorten.it/` `200` | 2 | 0.530s |
| `https://aka.ms/wsl` | `301` → `https://learn.microsoft.com/windows/wsl/about` → `302` → `/en-us/windows/wsl/about` (**relative** `Location`) `200` | 2 | 1.002s |
| `https://www.g2.com/` | `403` to any automated client (Cloudflare) | 0 | — |

No short link was created for this. `bit.ly/GVBQJS` is the sample unshorten.it
prints on its own homepage; `aka.ms/wsl` is Microsoft's public shortener.

## Probe results

| Probe | What unshorten.it reported |
|---|---|
| `http://github.com/` | `https://github.com/` — **plus a failure notice** |
| `http://bit.ly/GVBQJS` | `https://www.unshorten.it/`, title *"This website does not have a title available."* |
| `https://aka.ms/wsl` | `https://learn.microsoft.com/en-us/windows/wsl/about` |
| `https://www.g2.com/` | `https://www.g2.com/`, *"This website does not have a title available."* |

Final destinations are **correct in all four cases**, including the relative
`Location` on hop 2 of `aka.ms/wsl`. The resolver itself is fine. Everything
around it is not.

## There is no hop list, and the API confirms it

The homepage posts to `/main/get_long_url`. The entire response body for the
`github.com` probe:

```json
{"success": true, "message": "Woops! We can't seem to unshorten that URL, …",
 "long_url": "https://github.com/"}
```

`long_url` and nothing else. No array of hops, no status codes, no elapsed time,
no final-vs-requested distinction. The documented public API has the same shape —
it returns `fullurl`, `domain`, or `fullurl|domain` separated by a pipe. **There
is no field in this product that could carry a 301.**

Note also `"success": true` sitting next to a message that says it failed.

## The honesty test, and it fails it

`https://www.g2.com/` returns `403` to automated clients. unshorten.it rendered:

> This website does not have a title available.
>
> This site does not have a description available.

No mention of a 403 anywhere on the page. It reports **"the target refused our
request" as "the page has no title"** — precisely the confusion
[A6](../01-feature-inventory.md#a6-redirect-tracing) names as a honesty
requirement, demonstrated live.

## The failure notice is a heuristic, and it goes stale

On `http://github.com/` it printed, in full:

> **Notice:** Woops! We can't seem to unshorten that URL, this could be for a few
> reasons, it may not be a short URL in the first place, it may not be a real URL
> or could no longer be active or the service used to shorten the URL may not be
> compatible with Unshorten.It!
>
> Note that due to technical limitations, we do not support URL shortening
> services that do not take you directly to the destination website such as
> adf.ly which shows an advert before taking you to the final destination.
>
> Below are the safety ratings for **github.com**

It said this *while correctly resolving the URL* — so "can't unshorten" appears
to mean "the host didn't change in a way I recognise as a shortener", not "I
failed".

Worse: **that notice never cleared.** Across the following three lookups it
stayed on screen still reading `github.com`, while the result pane below it
updated to `unshorten.it`, then `learn.microsoft.com`, then `g2.com`. From the UI
alone you cannot tell whether a later lookup succeeded, because the verdict pane
is showing the first query's answer indefinitely.

The adf.ly disclaimer is the one genuinely useful piece of honesty on the site:
it names interstitial shorteners as out of scope rather than guessing.

## Three of the four enrichment widgets are broken

The page fans out to four widgets after resolving. Observed status:

| Widget | Endpoint | Result |
|---|---|---|
| Title / description | `/widgets/meta?url=…` | Works on GitHub and Microsoft. **Reported its own homepage as having no title** (`www.unshorten.it` does have `<title>Unshorten that URL! - Unshorten.It!</title>`) |
| Screenshot | `/widgets/screenshot?url=…` | **HTTP 500.** The spinner says "Screenshot Loading, please wait…" forever |
| Web of Trust | `/widgets/wot?url=…` | `200`, but "Not enough ratings" for both Trustworthiness and Child Safety on **github.com** |
| Blacklists | `/widgets/blacklists?url=…` | "hpHosts - Service Unavailable" |

hpHosts has been defunct for years. The "safety" half of the product — which the
site's own explainer page leads with, *"analysing the website for safety and
letting you see it before you decide whether to proceed"* — returns nothing
usable for any URL tested.

## The API: closed to new users, still running

`https://unshorten.it/api/documentation` opens with:

> **API No Longer Supported**
>
> The Unshorten.It! API is no longer supported and new registrations for API keys
> will not be accepted. The API will continue to operate for current users
> however it is recommended that users migrate away from it.

It is in fact still up. Unauthenticated probes to `api.unshorten.it` behave
exactly as the docs describe:

```
$ curl 'https://api.unshorten.it/'
error (0)
$ curl 'https://api.unshorten.it/?shortURL=http://bit.ly/GVBQJS&responseFormat=json'
{"error": 4}
```

So: **no free API available to us** — there is no way to obtain a key. No rate
limits are documented anywhere, for the API or the web UI; five lookups in a few
minutes hit nothing.

## They publish their own algorithm, and it is a Go `http.Client`

The same page hands you the implementation and tells you to go build it yourself:

> It is suggested that instead of using the API, Applications implement the logic
> to expand the shortened URL themselves, this is a fairly simple task.

Their pseudocode, verbatim in shape: `GET` the URL; if `301`, recurse on
`Location`; if `200`, check the body for a meta redirect and recurse on that;
otherwise it is final.

Two things worth recording. First, it branches on **`301` only** — no `302`,
`303`, `307` or `308`. The live service nonetheless resolved the `302` in the
`aka.ms/wsl` chain, so the running code is ahead of its own docs. Second,
**meta-refresh is claimed** ("check the body for any meta redirect") and
**JavaScript redirects are not mentioned at all**; the adf.ly disclaimer is the
closest thing to an admission that JS-driven and interstitial hops are
unfollowable. The `Refresh:` *HTTP header* is not mentioned either.

I did not find a public meta-refresh or JS-redirect URL to test against without
creating one, so meta-refresh support here is **documented but unverified**.

## Storage, ads, consent

Its privacy policy does not mention retaining submitted URLs, and no public trace
archive exists — traces are not published, unlike some tracers in this category.
It does still say your data is stored *"as per the Data Protection Act 1998"*, an
act repealed in 2018, which dates the page fairly precisely.

Ads are heavy: a Google AdSense display unit sits **above** the result, pushing
the answer below the fold, plus a sticky bottom banner. A Facebook Like button is
disclosed in the policy. No cookie-consent dialog was presented in this session.

Stack, self-disclosed in the footer: Python and Django. jQuery 2.0.3 (2013) on
the front end, behind Cloudflare.

## unshorten.me — alive, and gated

A separate service. The homepage claims *"More than 11786000 unique short URLs
resolved"*.

**Its free web form could not be driven: every lookup raises a reCAPTCHA image
challenge** ("Select all images with a fire hydrant"). Solving CAPTCHAs is out of
bounds, so the UI results below are from its published docs, not from a driven
lookup.

The v2 API is `GET https://unshorten.me/api/v2/unshorten?url={short_url}` with an
`Authorization: Token …` header, and returns:

```json
{"unshortened_url": "https://www.youtube.com/",
 "shortened_url": "https://bit.ly/3DKWm5t", "success": true}
```

**Same shape, same omission.** No hops, no status codes, no timing.

| Plan | Rate limit | Price |
|---|---|---|
| Free | **10 API requests per hour** | INR 0 |
| Basic | 3,000/hour | INR 500/mo |
| Professional | 10,000/hour | INR 1,500/mo |

Two things it is explicit about. It **caches**: *"If the URL is already shortened
by our service, then the result is stored in the database."* And it **retains
every URL you submit**: *"The website URLs collected during the unshortening
process and expanding process is stored in our database seperately."* [sic] For a
tool people paste one-time invite links, password-reset links and signed
CDN URLs into, that is worth knowing.

Its API docs also print what appear to be three live example tokens in the
copy-paste samples. Not used, obviously — noted only as evidence of the care
level.

## What these do that a plain Go HTTP client cannot

Short list, and it is the point of the report:

- **Render a screenshot of the destination.** Needs a headless browser, genuinely
  out of reach for `net/http`. Currently returning **HTTP 500**.
- **Third-party reputation and blacklist data** (Web of Trust, hpHosts). Both
  dead or empty for every URL tested.
- **Fetch from someone else's IP**, so the shortener's click-tracker sees their
  egress rather than yours. Real, and undercut by the fact that unshorten.me
  stores the URL.
- **Follow JavaScript redirects.** Neither claims to. unshorten.it explicitly
  disclaims the interstitial case.

Everything else in the category — following `3xx`, resolving a relative
`Location`, reading a meta-refresh, pulling `<title>` and `<meta name=
"description">` — is `http.Client` with a `CheckRedirect` func. Their own
documentation says so: *"this is a fairly simple task."*

## For us

**Closes.** The "unshortener" is not a capability gap. There is nothing in this
category that [A6](../01-feature-inventory.md#a6-redirect-tracing) needs a
dependency, a browser or a paid API to match — the one thing requiring real
infrastructure is the screenshot, and it is broken. The plan should stop treating
"resolve a short link" as a feature to win and treat it as a byline on Trace.

Also closes: **there is no free unshortener API to lean on.** unshorten.it is
closed to new keys; unshorten.me's free tier is 10 requests/hour and requires an
account. If we want this, we fetch it ourselves.

**Leaves open — and this is the whole opportunity.** Not one of them shows a hop
list. Ground truth for `aka.ms/wsl` is two redirects with a relative `Location`
in the middle; every tool here renders that as a single string. Status codes,
per-hop timing, the cross-host jump, the `http`→`https` upgrade, the
requested-vs-final distinction: all invisible, in the UI *and* in the JSON. A6's
hop table is a differentiator against this entire category, not table stakes.

Also open: `Refresh:` **header** detection (nobody mentions it), naming a JS
redirect as unfollowable rather than silently stopping, and distinguishing a
`403` from an empty page.

**Worth stealing.** One thing: the adf.ly disclaimer. Naming the class of link
you *cannot* follow, in the product, before the user finds out the hard way, is
exactly the honesty posture A6 asks for — and it is the only place in this report
where a tool volunteered a limitation instead of hiding it.

**Worth stealing as a warning.** unshorten.it's stale verdict pane is the same
failure mode as calcbe's copy button
([calcbe](calcbe-query-string-parser.md#one-inconsistency-worth-recording)): two
panes of one tool disagreeing, with the wrong one on top. If Trace renders a
verdict separately from the hop table, they have to be produced by the same call
or they will drift apart exactly like this.
