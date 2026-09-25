# Delivery plan — phases, acceptance, decisions

Four phases, then extras. Each ends with something deployed and useful on its
own.

**Order is by technical dependency**, now that shipping the short link first is
explicitly not a requirement. Clean before Short means the extension launches
with both context-menu items and the `/clean/rules` endpoint already live,
which also settles the one-vs-two-items question
([05 §2](05-extension.md#2-one-menu-item-or-two)) without having to guess.

Each phase carries some of [the cheap half](01-feature-inventory.md#the-cheap-half)
alongside its main feature — pages that are a template and a route rather than
new logic, and that make the suite feel finished rather than like one page with
plans.

## Phase 0 — Inspect

*The flagship. Pure Go, no network, no state. Also where the subdomain gets
wired end to end, once, with one page on it.*

**Build:** `url.go`, `rebuild.go`, `decode.go`, `embed.go`, `handler.go`,
`templates/{index,inspect,nav,notes,error}.html`, `tests/url_test.go`,
`tests/rebuild_test.go`, `decode_test.go`. Plus `main.go`, `site.Tools`, nginx,
DNS.

**Rides along** (all pure, all template-and-route): **A20** percent-encoding
reference, **A13** URL diff, **A19** `curl` builder. A13 in particular is a
second template over structs `Parse` already returns.

**Done when:**

- `link.corpberry.com/?u=…` renders the anatomy and the ordered parameter table.
- The request's example string splits into 4 params with `subdistrictIds`
  showing 14 values and the delimiter named.
- `curl 'https://link.corpberry.com/?u=…'` returns the same data as JSON, with
  no view-model keys leaking into the body.
- htmx swaps the fragment without a full-page reload.
- Round-trip edit (A15) works: change a value, get a correct URL back.
- Every case in [07 §2](07-testing.md#2-the-url-corpus) passes; `FuzzParse` and
  `FuzzRebuild` run clean for 60s; the `dns/nav` collision test passes.
- **The request-log decision (§Decisions #1) is made and implemented.** Blocker,
  not a follow-up — and the fix is in `LogValuesFunc`, not `Record`
  ([06 §5](06-security-and-abuse.md#5-the-request-log-will-eat-pasted-urls)).

## Phase 1 — Clean

*Still pure. Adds the rule tables and the endpoint the extension will cache.*

**Build:** `clean.go`, `rules.go`, `canonical.go`, `/clean`, `/clean/rules`
(content-negotiated, **not** a `.json` endpoint), `tests/clean_test.go`,
`rules_test.go`. Backfill `Param.Tracking` on Inspect so both pages visibly
share one table. **A16** wrapper unwrapping ships here — it is the same rule-table
shape and it is the feature a non-developer uses daily.

**Rides along:** **A11** UTM builder, **A14** encode/decode playground.

**Done when:**

- A URL with eleven trackers comes back clean, each removal named and attributed.
- A SafeLinks-wrapped URL reveals its real target **with no fetch**.
- `/clean/rules` serves JSON to the extension, a readable rules page to a
  browser, and carries a version and a working `ETag`.
- The never-strip allowlist test passes — `redirect_uri` and `state` survive.
- **No rule can change scheme, host, port or path.** This is what keeps
  create-time validation meaningful on the short-link path, and it is the
  specific reason ClearURLs' catalog cannot be adopted wholesale: it carries
  64 host-changing `redirections` rules
  ([reports/](reports/)).
- Sorting parameters is **off** unless asked for.
- A14 shows query-vs-path encoding side by side — the one thing the incumbents
  don't ([reports/go-url-stdlib-behaviour.md](reports/go-url-stdlib-behaviour.md)).

## Phase 2 — Short links + the extension

*The original ask. First state, first secret, first thing that can get the
domain blocklisted.*

**Build:** `short.go`, `store.go`, `GET|POST /short`, `GET /s/:code`, the
`platform` expiry-index doc fix, `LinkAPIKey` config, `templates/short.html`,
`tests/short_test.go`. Then `extension/` — manifest, `sw.js`, `offscreen.html`,
`options.html`, icons — with **both** menu items, since Clean shipped in Phase 1.

**Rides along:** **A10** QR code, hanging off the alias page.

**Done when:**

- `POST /short` with a key returns a working alias; without a key `401`; with
  `LINK_API_KEY` unset `503`. `GET /short` shows no list without a key.
- `/s/<code>` is a `302` with `no-store`, `noindex` and `no-referrer`, all set
  **before** `c.Redirect` — Echo v5 commits headers in that call.
- A stored `javascript:` target is refused **at resolve**, not only at create.
- An IP-literal target is refused at create.
- An expired link stops resolving **immediately**, by the code check, not
  whenever Mongo's reaper gets to it.
- Two codes colliding retries and succeeds; the unique index demonstrably exists.
- The extension, loaded unpacked, puts its items on a link's context menu and
  copies within ~1s. The clipboard write goes through `document.execCommand`
  inside the offscreen document, **not** `navigator.clipboard`, which throws
  there ([05 §1](05-extension.md#1-the-clipboard-problem-in-full)).
- Clean runs **locally in the extension** off the cached rule table, so only the
  short path costs a round trip.
- **`CF-Connecting-IP` handling confirmed for this vhost** before `created_ip`
  is treated as evidence ([06 §9](06-security-and-abuse.md#9-claims-that-need-qualifying)).

## Phase 3 — Trace

*The only feature that dials a stranger's host. Last on purpose, and optional —
see §Decisions #3.*

**Prerequisite, before any of it:** promote `botcheck.publiclyRoutable` to
`platform` and extend it. The check has been written four times already and only
that copy is complete ([06 §2](06-security-and-abuse.md#2-ssrf-the-one-that-matters)).

**Build:** the gate first, the chain walk second, then `/trace` and
`templates/{trace,chain}.html`, `trace_test.go`.

**Rides along:** **A17** user-agent personas, stolen from
[httpstatus.io](reports/httpstatus-io.md). One dropdown, one header, and it
turns "the target refused an automated request" from an apology into a finding:
browser UA gets 403, Googlebot gets 200, so the page can say the target
discriminates.

**Done when:**

- The address-gate table in [07 §4](07-testing.md#4-trace-and-the-loopback-problem)
  passes, including `::ffff:127.0.0.1`, `169.254.169.254`, `100.64.0.1`,
  `198.18.0.1` and the IPv4-embedding IPv6 prefixes.
- `Proxy` is nil and `DisableKeepAlives` is true, both asserted by test.
- The port allowlist is 80/443, with no dev-port exception.
- Own vhosts and own interface addresses are refused.
- Every hop is gated, and the scheme/host/port policy is enforced above the
  transport too.
- No `Referer` is forwarded; no `Authorization` crosses hosts; no cookie jar;
  an https → http downgrade is flagged.
- Header caps (`MaxResponseHeaderBytes`, `ResponseHeaderTimeout`) are set.
- Meta-refresh, the `Refresh:` header, and a JS redirect are each *named* rather
  than treated as the end of the chain.
- A `403` from bot protection reads as "the target refused an automated request".

## Phase 4 — As appetite allows

**A8** metadata preview and **A18** link extractor. A18 is pure and needs no
network, so it can jump the queue any time; A8 shares A6's egress gate and
should not ship before it.

---

## Deployment checklist (Phase 0, once)

| # | Step | Where |
|---|---|---|
| 1 | Proxied Cloudflare DNS record for `link.corpberry.com` | Cloudflare |
| 2 | nginx block for the subdomain, copied from the `dns` one | host (see note) |
| 3 | `proxy_set_header Host $host;` present — or host routing collapses | that file |
| 4 | `nginx -t` passes, then reload | prod |
| 5 | `cfg.VHost("link")` in the vhost map | `main.go` |
| 6 | `TemplateSource` registered on the renderer | `main.go` |
| 7 | `RegisterSEO(linkApp, cfg.URL("link"), linktools.SitemapPages)` | `main.go` |
| 8 | Catalog entry, and fix the apex `Desc` that still omits DNS Tools | `site/site.go` |
| 9 | `LINK_API_KEY` in the production `.env` (Phase 2) | prod |
| 10 | `make test` green; pre-push hook not bypassed | local |

**Note on step 2:** `deploy/nginx/` does not exist in this repo — DEPLOYMENT §3
describes canonical blocks living there, but the real ones are on the host.
Either create the directory as that doc describes, or fix the doc. Don't add a
fourth subdomain that references a path that isn't there.

No new bind mount and no `make mongo-init`: no data files, and Mongo creates
`links` lazily.

---

## Rough sizing

The ratio matters, not the numbers.

| Phase | Main feature | Rides along | Templates |
|---|---|---|---|
| 0 | ~800 Go (incl. `Rebuild`) | ~200 (A20, A13, A19) | ~400 |
| 1 | ~350 Go + ~300 rule data | ~150 (A11, A14) | ~280 |
| 2 | ~400 Go | ~60 (A10) | ~140, plus ~250 lines of extension JS |
| 3 | ~400 Go, half of it the gate | ~40 (A17) | ~120 |

Phases 0 and 1 are the ones worth doing well: no upstream to blame, no quota,
nothing to rot, and they are where the tool is differentiated
([00 §3](00-landscape.md#3-whats-actually-unoccupied)). The ride-alongs are
cheap on purpose — they are what turns a single good page into a suite, and
none of them is load-bearing.

---

## Decisions

**All four were taken during the build**, each per its documented lean, because
the owner was away and blocking on any of them would have stopped everything.
Each is reversible; the reasoning is below so it can be revisited rather than
rediscovered.

| # | Decision | Taken | Where it lives |
|---|---|---|---|
| 1 | Request-log redaction | **Redact**, in `LogValuesFunc` so it catches stdout *and* Mongo | `platform/redact.go`, `platform/app.go` |
| 2 | Tracking-rule sourcing | **Hand-write.** Raised to 80% by the corpus: ClearURLs is missing `gbraid`/`wbraid`/`gclsrc`/`ttclid` entirely, and adopting it would break "delete query parameters only" four separate ways | `tools/linktools/rules.go` |
| 3 | Does `/trace` ship | **Yes**, with the full gate promoted to `platform` first | `platform/netgate.go`, `tools/linktools/trace.go` |
| 4 | Publish the extension | **No.** Load-unpacked only. Shlink's published BYO-key extension has 337 users after four years | `tools/linktools/extension/` |

The original reasoning follows.

*Resolved 2026-09-25 by the owner: phase order is by technical dependency, not
by getting the short link out first. "I'm building a site of tools, all useful
tools can be added, especially if they are easy to add" — which is why the
inventory grew to twenty and every phase carries some of
[the cheap half](01-feature-inventory.md#the-cheap-half).*

1. **Request-log redaction.** A `platform/` change affecting all four
   subdomains: redact the URI once in `LogValuesFunc` so it misses both stdout
   and Mongo. **Blocks Phase 0**, and is also a prerequisite for `/trace`, since
   `request_logs` is already the traced-URL corpus
   [06 §6](06-security-and-abuse.md#6-never-store-what-was-traced--which-is-not-currently-true)
   says we refuse to build. Lean: redact, plus an honest note on the page, ~70%.
   [06 §5](06-security-and-abuse.md#5-the-request-log-will-eat-pasted-urls)
2. **Tracking-rule sourcing.** Hand-write ~60 global rules, embed ClearURLs'
   106 KB **LGPL-3.0** catalog into an MIT repo, or fetch it at runtime. Lean:
   hand-write for v1 on licence grounds, ~60%, with the table structured so
   either alternative is a drop-in.
   [02 §4](02-build-fit.md#4-what-we-are-not-matching-and-the-clearurls-decision)
3. **Does `/trace` ship at all?** It carries the entire SSRF surface, requires
   promoting a `platform` helper first, and the suite is useful without it.
   httpstatus.io already occupies the browser-facing version of this
   ([00 §1](00-landscape.md#1-the-five-categories)); what is left is a free
   keyless JSON API. No lean — this is genuinely the owner's appetite for
   security work.
4. **Publish the extension, or keep it unpacked?** Its headline feature is inert
   for anyone who isn't the owner, because shortening needs the API key. Lean:
   don't publish for v1, ~70%.
   [05 §7](05-extension.md#7-publishing--a-decision-not-a-given)

**Settled, recorded so they aren't relitigated:** `/s/<code>` rather than a bare
root path (~80%, [04 §2](04-short-links.md#2-where-the-redirect-lives)); a short
domain is deferrable at zero cost as long as the base URL stays config-driven;
own subdomain rather than tabs inside `ip.corpberry.com` (~75%,
[02 §0](02-build-fit.md#0-why-its-own-subdomain)); `GET /short` is key-gated,
which is a bug fix rather than a choice.
