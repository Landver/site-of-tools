# httpstatus.io

**Driven 2026-09-25.** `https://httpstatus.io/`

The serious incumbent in redirect tracing, and the reason
[A9 bulk check was cut](../01-feature-inventory.md#a9-bulk-link-check--cut).
The plan's first draft omitted it entirely.

## Probe

Input `http://github.com/`, one click:

| Request URL | Status codes | Redirects |
|---|---|---|
| `http://github.com/` | `301` → `200` | 1 |

Fast, no ads, no account, no friction.

## Does

- **Bulk by default.** "Enter URLs to check, one per line", with result-page
  sizes of 10 / 25 / 50 / 100.
- **A 27-entry User-Agent selector.** Your browser, Googlebot (desktop and
  smartphone), Bingbot, YandexBot, Applebot, DuckDuckBot, Twitterbot,
  LinkedInBot, Facebook Crawler, **Slackbot Link Expanding**, Slackbot, CCBot,
  GoogleOther, **GPTBot**, ChatGPT-User, plus the ordinary browsers and
  `httpstatus/2.0`.
- Canonical domain check (bare vs `www`, http vs https).
- Filters on the result set: all redirects / 301 only / no redirects / by status.
- Export to Google Sheets, download CSV.
- Integrations: Google Sheets, Make, Pipedream, Airtable, **n8n**, Retool.
- A documented API, free tier then paid (~€15/mo for 20k calls).
- `Ctrl+Enter` to submit.

## The idea worth stealing

**The User-Agent persona selector.** "What does Googlebot see at this URL" and
"what does Slack see when this link is pasted" are different questions from
"what do I see", and the answers differ whenever a site cloaks, geo-redirects,
or serves a bot challenge. It costs one dropdown and one request header.

It also makes our honesty requirement testable rather than theoretical: if the
browser UA gets a 403 and Googlebot gets a 200, the tool can *say* the target
discriminates, instead of reporting a dead link.

## Does not

- Free JSON API. The API is the paid product.
- Follow JavaScript redirects (no claim made; contrast
  [wheregoes](wheregoes-com.md)).
- Parse or clean the URL — it is purely a status/redirect/header checker.

## For us

**Closes:** ad-free, honest, fast bulk redirect tracing. All of it. The plan's
first draft claimed those as gaps and they are not.

**Leaves open:** a *free, keyless* JSON API for tracing. That is the entire
remaining wedge in this category, and it is narrow.

**Consequence:** A9 (bulk check) is cut — it is thoroughly occupied *and* it is
the easiest feature in our inventory to turn into a DDoS amplifier. A6 (single
trace) survives only on the API axis, which is why
[whether `/trace` ships at all](../08-delivery-plan.md#decisions) is an open
decision rather than an assumption.
