# wheregoes.com

**Driven 2026-09-25.** `https://wheregoes.com/` — trace permalink produced:
`https://wheregoes.com/trace/20264931708/`

Not abandoned, contrary to the plan's first draft: © 2008–2026, current, no
account required.

## Probe

Input `http://github.com/`:

```
#  Code  Requested URL
1  301   h|t|t|p|:|/|/|g|i|t|h|u|b|.|c|o|m|/      301 Redirect
2  200   🍪 https://github.com/
Trace Complete                                    Redirects: 1
```

Plus `Date Traced: 2026-09-25 08:18:40 GMT` and
`User Agent: Wheregoes.com Redirect Checker/1.0`.

## Three design choices worth noting

**Pipe-separated URLs.** Non-final hops render as `h|t|t|p|:|/|/|…`. A
deliberate defence so the page can't be scraped for live malicious URLs and
can't be clicked by accident. It also makes the URL uncopyable, which is a real
cost — but the instinct is right, and our
[rendering rules](../06-security-and-abuse.md#8-rendering-hostile-urls) are
reaching for the same goal by a different route.

**A 🍪 marker per hop** where the response set a cookie. Cheap, and it turns an
invisible side effect into a visible one. Worth stealing.

**Per-hop Response Body and Response MetaData** panes, collapsed by default.

## The honesty disclaimers

Printed on every result, unprompted:

> NOTICE: The results above may vary depending on the user-agent used during the
> test and whether or not the responding server is blocking WhereGoes. If you are
> seeing a 403 response code, the trace might have been blocked.

> Warning: This service does not evaluate if the links are safe to visit. Use
> your discretion on whether you should visit the final destination. If you are
> not sure, assume it is not safe.

This is precisely the standard
[02 §5](../02-build-fit.md#5-structurally-impossible-here) sets for our own
Trace page — and it is already met here. We do not get to claim honesty as a
differentiator.

## The capability we cannot match

Their copy claims the trace follows *"php redirects, htaccess redirects, NGINX
redirects, **JavaScript redirects** and **meta-refreshes**"*. **Claimed, not
verified** — confirming it needs a JS-redirect page under our control, which
does not exist yet.

If true it means a headless browser behind the service, which is exactly the
dependency [02 §5](../02-build-fit.md#5-structurally-impossible-here) rules out
for us. So the honest framing in our own docs is **"impossible for an HTTP
client"**, not "impossible in general".

## The thing they do that we deliberately won't

**Traces are persisted and publicly addressable.** Every run yields a
`wheregoes.com/trace/<id>/` permalink recording the URL, the timestamp and the
user agent. Convenient; also exactly the traced-URL corpus
[06 §6](../06-security-and-abuse.md#6-never-store-what-was-traced--which-is-not-currently-true)
refuses to build, and a reminder that our own request log currently builds it by
accident.

Also present: a two-entry User-Agent selector (their bot, or yours) — a thinner
version of [httpstatus.io's 27](httpstatus-io.md#does).

## For us

**Closes:** honest disclaimers, hop tables, shareable results, JS-redirect
following.

**Leaves open:** a free keyless JSON API. Their API is listed as an upcoming
feature, not a shipped one — the same narrow wedge httpstatus.io leaves.

**Steal:** the per-hop cookie marker, and the instinct not to render a hostile
URL as a live link.
