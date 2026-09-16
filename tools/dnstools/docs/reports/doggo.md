# doggo (mr-karan)

Modern `dig` replacement by **Karan Sharma** (`mr-karan`), written in Go on `miekg/dns`, plus a hosted web front end at doggo.mrkaran.dev serving the same core. Closest existing prior art to what this repo would build: **one Go module, two `main` packages (CLI + web server), sharing a domain layer** — exactly the ARCHITECTURE §4 shape CLAUDE.md mandates. Study it for the layering, the transport-selection mechanic, and the trace result schema; do **not** copy code (GPL-3.0).

- **URL:** https://doggo.mrkaran.dev · repo https://github.com/mr-karan/doggo · **Category:** open-source CLI DNS client + hosted single-query web UI · **Registration:** none, no account, no key · **Pricing:** free, GitHub Sponsors only · **API:** undocumented but live & unauthenticated (see below).
- **Firsthand check (all 2026-09-16, re-verified 2026-09-16 in a second pass w/ ~35 more requests):** `GET /` -> **200** (note: `curl -I` sends HEAD and gets a misleading 405 here — the route is `GET`-only; use a real `GET` for this host), `server: cloudflare`, `via: 1.1 Caddy` (twice). `dig api.doggo.mrkaran.dev A` -> **NOERROR/NODATA**, curl "Could not resolve host" — the discovery note's separate API host does **not** exist. But reading `/assets/main.js` firsthand gave `apiURL = '/api/lookup/'`; I POSTed to it (JSON body keys are `query`/`type`/`class`/`nameservers`, per `pkg/models.QueryFlags`, not `names`/`types`) and **got real DNS answers with no key and no auth**. So the web side is *not* UI-only: correcting the brief. Endpoint inventory then confirmed against `web/api.go` in the repo. Source files read via raw.githubusercontent; GitHub's REST API worked cleanly on the second pass (no rate-limit hit) and gave exact star count + license + latest-release date directly.

## What it is

CLI first: `doggo example.com`, `doggo MX github.com @9.9.9.9`. Author's stated origin is porting Rust's [`dog`](https://github.com/ogham/dog) to Go to learn. **4,476 stars** (GitHub REST API, 2026-09-16), latest release **v1.4.0**, published **2026-09-01T09:36:51Z** (GitHub Releases API), packaged in FreeBSD ports as `dns/doggo` at **1.4.0,1** (maintainer `yuri@FreeBSD.org`, port added 2021-04-22) with **two flavors: `doggo` & `doggo-webui`** — the web server is a shipped, self-hostable artifact, not a one-off deploy.

The hosted instance self-reports `v1.1.0 (885c0e5 2025-10-30)` via `GET /api/`, i.e. **~3 minor releases behind the CLI**, which has observable consequences (below).

## Registration, access & pricing

Free, no account, no key, no quota page, no ToS or acceptable-use page that I could find. Monetization is a GitHub Sponsors link in the README. Nothing gated.

## Features — complete inventory

| Aspect | Feature | CLI | Hosted API | Hosted UI |
|---|---|---|---|---|
| Record lookup | Query by name + type + class, multi-value each | ✓ | ✓ | 1 name / 1 type |
| | Fan-out: every name × type × class × nameserver combination as a separate response | ✓ | ✓ (verified: 2 names × 2 types -> **4 responses**) | ✗ |
| | `--any` = loop over 10 common types (A AAAA CNAME MX NS PTR SOA SRV TXT CAA) | ✓ | ✓ (`any:true`) | ✗ |
| | `-x`/`--reverse` PTR lookup, auto `in-addr.arpa`/`ip6.arpa` formatting | ✓ | **✗** (`ReverseLookup()` only called from `cmd/doggo`) | ✗ |
| | IDN -> punycode via `golang.org/x/net/idna` before the question is built | ✓ | ✓ | ✓ |
| | `search`/`ndots` from resolv.conf for unqualified names | ✓ | ✓ | n/a |
| Transport | `udp://` `tcp://` `tls://` (DoT) `https://` (DoH) `quic://` (DoQ) `sdns://` (DNSCrypt / DoH stamp) as a **scheme on the nameserver** | ✓ | ✓ (DoT & DoH verified live) | 30 presets across 9 providers + custom (counted from `<option>`/`<optgroup>` tags in served `index.html`) |
| | `--http3` explicit HTTP/3 for DoH (quic-go `http3.Transport`) | ✓ | ✓ (`http3:true`) | ✗ |
| | Auto TCP retry when UDP response has TC=1 | ✓ | ✓ | ✓ |
| | `--tls-hostname`, `--skip-hostname-verification` | ✓ | ✓ | ✗ |
| | `-b`/`--source` bind to local source IP, like `dig -b` (not for DNSCrypt; no fixed source port) | ✓ | ✓ | ✗ |
| | `-4`/`-6` restrict address family | ✓ | ✓ | ✗ |
| Resolver choice | Multiple nameservers in one invocation | ✓ | ✓ (verified: 3 resolvers -> 3 tagged responses) | ✗ |
| | `--strategy` = `all` \| `random` \| `first` \| **`internal`** (keep only private-IP system resolvers: VPN/Tailscale split-DNS) | ✓ | ✗ (`Strategy` struct tag is `strategy:"-"`, not `json:"-"` — see Gaps) | ✗ |
| | `-A`/`--authoritative`: walk up to the closest enclosing zone by SOA, fetch that zone's NS, query those | ✓ | ✓ (`authoritative:true`) | ✗ |
| Delegation | `--trace`: **iterative** walk from the root, referral/answer/CNAME/DNAME/NXDOMAIN/NODATA classification, per-hop attempts w/ RTT & RCODE, lame-delegation detection, 13 root hints (v4+v6) compiled in | ✓ | **✗** (no `trace` field in the API payload at all) | ✗ |
| DNS flags | `--aa --ad --cd --rd --z --do` | ✓ | ✓ | 6 checkboxes |
| EDNS0 | `--nsid --cookie --padding --ede --ecs=<prefix> --bufsize` | ✓ | ✓ | 5 controls (no bufsize) |
| | EDNS response block: nsid, cookie, subnet + scope, `extended_errors[]` (code + description + extra text), udp_size, dnssec_ok | ✓ | ✓ | dedicated **EDNS tab** |
| Output | Colour tabular (`olekukonko/tablewriter`), honors `NO_COLOR` & non-TTY | ✓ | n/a | n/a |
| | `--json`, `--short`, `--time` (RTT column), `--debug` | ✓ | JSON only | tables only |
| | Versioned trace JSON (`schema_version`) w/ partial-result reporting & documented exit codes | ✓ | ✗ | ✗ |
| Distributed | **Globalping**: `--gp-from Germany,Japan --gp-limit 2` runs the measurement on jsdelivr's global probe network instead of locally | ✓ | ✗ | ✗ |
| Config | TOML at `--config` / `$DOGGO_CONFIG` / `$XDG_CONFIG_HOME/doggo/config.toml` / `~/.doggo.toml`, plus `DOGGO_*` env vars; **unknown keys are a hard error** | ✓ | server-only keys | ✗ |
| Shell | zsh & fish completions | ✓ | ✗ | ✗ |
| Server | `GET /api/` (version string), `GET /api/ping/` ("PONG"), `POST /api/lookup/`, `GET /`, `GET /faq`, `GET /assets/*` | n/a | ✓ | ✓ |

**Not present anywhere:** propagation checking across many geographies in the UI, DNSSEC chain validation, AXFR/zone transfer (zero `AXFR` occurrences in source), WHOIS/RDAP, blocklist/RBL checks, email-auth (SPF/DKIM/DMARC) parsing, subdomain enumeration, monitoring/alerting, history, reverse-IP/passive DNS.

## Record types & query options supported

CLI accepts **any type `miekg/dns` knows**, by name, by decimal number, or RFC 3597 `TYPE<n>` (added in v1.3.0). Verified live: `HTTPS` (SVCB) returns the full parameter set rendered into one string — `1 . alpn="h3,h2" ipv4hint="..." ipv6hint="..."`. Classes: IN, CH, HS. Knobs, all first-class flags: resolver address **and transport scheme**, authoritative-NS mode, trace, TCP (explicit or via TC retry), EDNS/ECS/NSID/cookie/padding/EDE/bufsize, DNSSEC `--do`, timeout, ndots, search, IP family, source address, TLS hostname. TTLs are rendered as duration strings (`"287s"`), not raw integers. The **web UI is far narrower**: 10 types in a `<select>`, no trace, no reverse, no Globalping.

## How it works

Fully **server-side**. The browser posts JSON; the Go process opens the actual sockets. `web/handlers.go` unmarshals the body straight into `models.QueryFlags` (the same struct koanf fills from CLI flags), calls `app.LoadFallbacks()` -> `app.PrepareQuestions()` -> `app.LoadNameservers()` -> `resolvers.LoadResolvers()`, then fans out one goroutine per resolver under a **5s `context.WithTimeout`**, collecting responses under a mutex. Partial success is preserved deliberately: responses are appended even when the resolver also returned an error, so one dead nameserver in a fan-out does not discard the others.

Resolvers are **recursive by default** (RD=1); `--authoritative` does its own SOA/NS discovery first; `--trace` is a separate iterative tracer (`pkg/resolvers/trace.go`, ~36 KB) that never touches a recursive resolver after bootstrap. **No caching layer of its own** — TTLs shown are whatever the upstream returned, and repeated queries hit the upstream every time. DoH is POST `application/dns-message` w/ a GET wire-format fallback; DoQ uses ALPN `doq`; DNSCrypt via `ameshkov/dnscrypt/v2` + `dnsstamps`.

Observable infra: Cloudflare -> Caddy -> the Go binary, containerized. Firsthand leak: `{"authoritative":true}` for `corpberry.com` returned correct NS records but reported the answering nameserver as **`127.0.0.11:53`**, Docker's embedded DNS — so that response came from the container resolver, not from the zone's own NS as the flag implies.

## Output & UX

Terminal: aligned colour table, columns NAME/TYPE/CLASS/TTL/ADDRESS/NAMESERVER, plus optional Time Taken and Status columns, with a grouped EDNS footer per nameserver. Record types are colour-coded.

Web: a single form (domain, type, nameserver preset, collapsible **Advanced Options** holding the 6 header-flag checkboxes and the 5 EDNS controls), a submit button that swaps to a spinner, then a results panel that scrolls itself into view with **4 tabs: Answers / Authorities / Additional / EDNS**, each an empty-state-aware table. `Answer.Address` is a catch-all value column, so RRSIG, SVCB and SOA data all land in the "Address" header — sloppy but cheap.

What the UI **does not** have, verified by grepping `main.js`: zero occurrences of `pushState`, `searchParams`, `localStorage`, `clipboard` or any download/CSV path. **No shareable result URLs, no copy button, no export, no history, no dark/light toggle, no rate-limit messaging.** Errors surface as one text line from the JSON envelope's `message`.

## Monetization, limits & abuse controls

No pricing, no keys, no quotas. `config-api-sample.toml` declares `read_timeout`/`write_timeout` 7000ms, `keepalive_timeout` 5000ms and `max_body_size=10000`, but I found no body-size middleware wired into the chi router in `web/api.go` — only `RequestID`, `RealIP`, `Logger`, `Recoverer`. **No CORS:** `OPTIONS /api/lookup/` -> **405** with `allow: POST`, and a POST carrying `Origin: https://corpberry.com` came back with no `access-control-allow-origin`. So the endpoint is usable by any server or CLI but **unusable from another site's browser**. I saw no 429 across ~55 requests, and **no cap on fan-out**: the question list is the Cartesian product of names × types × classes, each multiplied by the nameserver count, with one goroutine per resolver. That is a free, unauthenticated, server-side DNS query amplifier pointed at third-party resolvers. Anyone shipping the same shape needs a question-count cap, a per-IP limit, and a resolver allowlist.

## Ideas worth stealing

- **Transport as a URL scheme on the resolver field, not a separate control.** `@1.1.1.1`, `@tcp://1.1.1.1`, `@tls://1.1.1.1`, `@https://cloudflare-dns.com/dns-query`, `@quic://dns.adguard.com`, `@sdns://…`. `initNameserver` sniffs the scheme, defaults bare IPs to `udp://`, and applies per-scheme default ports (53/853/853). One input, six transports, and it collapses to one htmx form field. Pair it with a preset `<select>` (theirs, counted directly from `index.html`: 30 `<option>` entries grouped under 9 `<optgroup>` providers — Cloudflare, Google, Quad9, AdGuard, Mullvad, Control D, DNS0.eu, OpenDNS, CleanBrowsing — plus a separate "Custom" group) and a "Custom server" text box that unhides on `custom`.
- **Per-response `nameserver` + `rtt` tagging is the whole comparison feature.** One POST with 3 resolvers returned 3 responses, each stamped with which resolver answered and how long it took — and `corpberry.com` genuinely differed (`172.67.134.67` from 1.1.1.1 vs `188.114.96.1` from 8.8.8.8). That is a "do these resolvers agree?" view for free, no probe network needed. Render as one row per resolver with a visual agree/disagree marker.
- **Surface NSID.** `{"nsid":true}` against `cloudflare-dns.com` returned `"nsid":"hel02"` in one run and `"nsid":"arn02"` in a later run from a different network path — the actual anycast PoP that answered, which is expected to vary with the requester's route, not a fixed value for the service. One checkbox, and suddenly the result says *which* Cloudflare node you reached. Almost nobody's web DNS tool shows this.
- **Show Extended DNS Errors with the code.** `dnssec-failed.org` w/ `rd+do+ede` returned `Code: 9, Info: no SEP matching the DS found for dnssec-failed.org.` That is a human-readable DNSSEC failure explanation handed to you by the resolver, no validation logic required on your side. Cheapest possible DNSSEC feature.
- **Steal the `TraceResult` schema, not the tracer.** `schema_version`, `query`, `status` (complete/partial/failed), `verdict` (answer/nxdomain/nodata/error), `hops[]` each w/ `number`, `zone`, `role` (root/delegation/authoritative), `attempts[]` (nameserver, ip, protocol, rtt_ms, rcode, truncated, error), `delegation{child, nameservers[]}`, `answers[]`/`authorities[]`/`additional[]` (each `{name,type,class,ttl,data}`), `outcome` (referral/answer/cname/nxdomain/nodata/error), plus `summary{hop_count, total_rtt_ms}` — confirmed by reading the struct definitions directly in `pkg/resolvers/trace.go`. That is a finished blueprint for a trace UI: one card per hop, the delegation NS set as the card body, RTT badges from `attempts`. Versioning the schema so the UI can refuse an unknown shape is the detail worth copying.
- **`--any` as "query the 10 common types", not QTYPE 255.** Verified: `any:true` produced 10 separate questions, not one ANY query. RFC 8482 has made real ANY useless; this is the honest replacement and it gives you a "full record sweep" page for free.
- **Partial-success collection.** Append responses even when the resolver also errored, then log a warning. A multi-resolver view where one dead resolver blanks the page is worse than one showing 2 of 3.
- **`GET /api/ping/` returning `"PONG"` and `GET /api/` returning the build version.** Two-line handlers, and the version endpoint is how I dated their deployment. Worth having on our binary.
- **The FAQ page, wired but not yet deployed.** `web/faq.html` embeds a schema.org **`FAQPage` JSON-LD block** ("What is a DNS lookup?", "What is DoH/DoT/DoQ?", "Which DNS server should I use?"). Pure SEO surface for a tool subdomain, and it costs one static template. Current `main`'s `web/api.go` actually registers `r.Get("/faq", ...)` serving the `go:embed`-ed `faqHTML` — the code path exists — but `GET /faq` on the live site is **404**, consistent with the hosted build lagging behind `main` (same lag as the version string, below). Corrected from an earlier draft of this report, which called it "an idea they have not executed"; it is executed in source, just not deployed.
- **Config precedence done properly:** defaults < TOML file < `DOGGO_*` env < flags, with **unknown keys a hard error** so typos surface. Their `config-cli-sample.toml` doubles as the reference doc, every key commented with its default.

## Gaps & what it does not do

- **The hosted UI is a single-query toy relative to the CLI.** No trace, no reverse, no Globalping, no multi-resolver, 10 record types. Everything distinctive lives behind the CLI.
- **RD default trap, reproduced.** `web/handlers.go` sets `RD=true` only when *no* header flag was set: `if !RD && !AA && !AD && !CD && !Z && !DO`. So `{"do":true,"ede":true}` silently ships RD=0 — I got `Code: 0, Info: no local cache to fulfill non recursion (RD=0) request` back from 1.1.1.1. Adding `"rd":true` fixed it. Same with `{"aa":true}` alone against 9.9.9.9: empty answers, no explanation. **Lesson for a JSON API over DNS: a bool that defaults to false cannot express "unset" for a flag whose real default is true.** Use `*bool`, or an explicit `flags` object.
- **Silent type degradation on the deployed build.** `{"type":["TYPE65"]}` and `{"type":["BOGUS"]}` both came back `200 success` with question type `"None"` (= QTYPE 0) and a NODATA SOA. Numeric/RFC 3597 types landed in v1.3.0 and current `main`'s `ParseRecordType` returns an error, but the live v1.1.0 build just coerces to zero. A bad type should be a 400, never a plausible-looking empty result.
- **ECS + DoH returned nothing.** `{"query":["cloudflare.com"],"type":["A"],"nameservers":["https://dns.google/dns-query"],"ecs":"203.0.113.0/24"}` -> `{"answers":null,"authorities":null,"questions":[{"name":"cloudflare.com.","type":"A","class":"IN"}],"edns":{"subnet":"203.0.113.0/24","udp_size":512}}` — reproduced identically across 3 repeat requests. ECS alone over UDP works (answers populate normally); the ECS+DoH combination consistently drops the answer on the hosted build. Not reproduced against a local build, so I cannot say whether it is fixed upstream.
- **Struct-tag typos leak Go field names into the JSON contract.** In `pkg/models`, `ShortOutput` carries `short:"-"`, `ReverseLookup` carries `reverse:"-"` and `Strategy` carries `strategy:"-"` where `json:"-"` was intended, so those fields marshal under their Go names. I POSTed `{"ReverseLookup":true}`; it was accepted without error and **had no effect** (the handler never calls `ReverseLookup()`), producing A/AAAA questions for the literal string `8.8.8.8.`. Accepting a key and ignoring it is worse than rejecting it.
- **No DNSSEC validation.** `--do` sets a bit and RRSIGs come back as opaque strings; `trace.go` contains zero `DNSKEY`/`DS`/`RRSIG` handling. Delegation tracing only.
- No propagation view, no monitoring, no history, no export, no shareable URLs, no AXFR, no WHOIS/RDAP, no email-DNS or blocklist checks.
- **GPL-3.0**, which for a Go binary means linking their packages pulls the whole work under GPL. Fine to read and learn from; not fine to vendor into a differently-licensed site.

## Verified firsthand vs inferred

**Verified (2026-09-16, two passes, ~55 requests total):** `GET /` -> 200 w/ Cloudflare+Caddy headers (note: a HEAD request to `/` gets a misleading 405, only `GET` is routed); `api.doggo.mrkaran.dev` NODATA & unresolvable by curl; `apiURL='/api/lookup/'` in the served JS, with JSON body keys `query`/`type`/`class`/`nameservers` confirmed against `pkg/models.QueryFlags`; POST to it returning real answers unauthenticated; `GET /api/` -> `v1.1.0 (885c0e5 2025-10-30)`; `GET /api/ping/` -> `PONG`; `GET /faq` -> **404**, while current `main`'s `web/api.go` registers and serves it (route exists in source, absent from the deployed build); OPTIONS -> 405 `allow: POST` and no ACAO header on a POST carrying an `Origin` header; DoH & DoT transports through the API; SVCB/HTTPS rendering; NSID (`hel02` on one run, `arn02` on another — PoP varies by request path, not a fixed value); EDE code 9 for `dnssec-failed.org`; the RD trap and its fix, reproduced exactly against `web/handlers.go`'s literal condition; TYPE65 & BOGUS degrading to `"None"`, reproduced 3x; ECS+DoH answers dropping while `questions`/`edns` still populate, reproduced 3x; `ReverseLookup` accepted-but-ignored, producing an ordinary forward question for the literal string `8.8.8.8.`; `authoritative:true` reporting `127.0.0.11:53` when no `nameservers` field is sent (Docker's embedded resolver, not the zone's own NS); 3-resolver and 2×2 fan-out counts; 30 nameserver presets across 9 `<optgroup>` providers + a separate "Custom" group, counted directly from served `index.html`; `/robots.txt`, `/privacy`, `/terms`, `/tos`, `/legal`, `/about` all return no content-signal privacy/ToS page (`robots.txt` only states AI-crawling content-signals; the rest are 404); no `/sitemap.xml`; **4,476 stars**, **GPL-3.0** license, latest release **v1.4.0** published `2026-09-01T09:36:51Z` — all three read directly off the GitHub REST API (`api.github.com/repos/mr-karan/doggo`), which was reachable cleanly on this pass, not scraped; FreeBSD `dns/doggo` 1.4.0,1 w/ `doggo`/`doggo-webui` flavors, maintainer `yuri@FreeBSD.org`, port added 2021-04-22 (FreshPorts); `Resolver` interface confirmed as exactly `Address() string` + `Lookup(ctx, questions, flags) ([]Response, error)` in `pkg/resolvers/resolver.go`; `TraceResult` and its nested types confirmed field-for-field in `pkg/resolvers/trace.go` (35.6 KB, matches the "~36 KB" estimate); 13 compiled-in root hints (`a`–`m.root-servers.net`, each w/ v4+v6 address) confirmed by name.

**Read from source, not executed:** everything about the CLI (I did not install doggo), including `--trace`, `--gp-from`, `--strategy=internal`, shell completions, colour table output, `--short`/`--time`, config-file precedence, and the DNSCrypt (`sdns://`) transport, which was read in `pkg/resolvers/dnscrypt.go` but not exercised against the hosted API. `internal/app/*`, `web/*.go`, `go.mod`, `CHANGELOG.md` and both sample configs were read in full or grepped.

**Inferred / uncertain:** whether the ECS+DoH failure and the silent type coercion are fixed in v1.4.0 — the hosted `/faq` 404 despite the route existing in `main` is a second, independent data point that the deployed build genuinely lags `main` (not just a stale version string), which makes "fixed upstream, not yet deployed" the more likely explanation, but this remains unconfirmed since a local v1.4.0 build was not run. Whether `max_body_size` from `config-api-sample.toml` is enforced anywhere: declared in the sample config, not visible as middleware in `web/api.go` (only `RequestID`, `RealIP`, `Logger`, `Recoverer` are registered). Whether any rate limiting exists upstream at Cloudflare: none observed across ~55 requests this session, none proven absent. Whether the hosted instance logs or retains queries: no privacy, terms, or acceptable-use page found at any guessed path, which is an absence, not a confirmed no-logging policy. I did not test abuse limits at volume, did not attempt AXFR, and did not stress the endpoint.

## Open source / reusable

`github.com/mr-karan/doggo`, **GPL-3.0**, Go 1.26.6. Deps worth noting for our own build: `miekg/dns` v1.1.72 (the only real choice), `go-chi/chi/v5`, `knadh/koanf/v2`, `quic-go/quic-go` v0.61 + `http3`, `ameshkov/dnscrypt/v2` + `ameshkov/dnsstamps`, `jsdelivr/globalping-go` v0.3.0, `olekukonko/tablewriter`. Layout to imitate: `pkg/resolvers` (transport implementations behind a 2-method `Resolver` interface: `Address()` + `Lookup(ctx, questions, flags)`), `pkg/models` (flags + shared types), `internal/app` (question building, nameserver loading, output), then thin `cmd/doggo` and `web/` mains. Swap chi for Echo v5 and that is our ARCHITECTURE §4 with the domain package returning structs and the handler doing `platform.Respond(...)`. Their `web/api.go` even `go:embed`s `index.html`, `faq.html` and `assets/*` into the binary, same pattern as our `shared/` and `site/` packages.

## Sources

- [doggo repository (README, source, GPL-3.0 LICENSE)](https://github.com/mr-karan/doggo)
- [GitHub REST API — `repos/mr-karan/doggo`: star count, license, `pushed_at`](https://api.github.com/repos/mr-karan/doggo)
- [GitHub REST API — `repos/mr-karan/doggo/releases/latest`: v1.4.0, published timestamp](https://api.github.com/repos/mr-karan/doggo/releases/latest)
- [`config-cli-sample.toml` — every flag with its default, documented](https://raw.githubusercontent.com/mr-karan/doggo/main/config-cli-sample.toml)
- [`config-api-sample.toml` — server timeouts, `max_body_size`](https://raw.githubusercontent.com/mr-karan/doggo/main/config-api-sample.toml)
- [`pkg/resolvers/dnscrypt.go` — DNSCrypt resolver via `ameshkov/dnscrypt/v2`](https://raw.githubusercontent.com/mr-karan/doggo/main/pkg/resolvers/dnscrypt.go)
- [`web/api.go` — chi routes, embedded assets, server timeouts](https://raw.githubusercontent.com/mr-karan/doggo/main/web/api.go)
- [`web/handlers.go` — the `/api/lookup/` handler, fan-out and the RD default](https://raw.githubusercontent.com/mr-karan/doggo/main/web/handlers.go)
- [`pkg/models/models.go` — `QueryFlags`, the JSON contract and the struct-tag typos](https://raw.githubusercontent.com/mr-karan/doggo/main/pkg/models/models.go)
- [`pkg/resolvers/resolver.go` — `Resolver` interface, `Response`/`Answer`/`EdnsInfo` shapes](https://raw.githubusercontent.com/mr-karan/doggo/main/pkg/resolvers/resolver.go)
- [`pkg/resolvers/trace.go` — `TraceResult` schema, root hints, hop classification](https://raw.githubusercontent.com/mr-karan/doggo/main/pkg/resolvers/trace.go)
- [`internal/app/questions.go` — `LoadFallbacks`, `PrepareQuestions`, IDN, `ReverseLookup`](https://raw.githubusercontent.com/mr-karan/doggo/main/internal/app/questions.go)
- [`CHANGELOG.md` — v1.2.1 / v1.3.0 / v1.4.0 feature dates](https://raw.githubusercontent.com/mr-karan/doggo/main/CHANGELOG.md)
- [doggo docs: CLI reference](https://doggo.mrkaran.dev/docs/guide/reference/)
- [doggo docs: protocol tweaks (DNS flags & EDNS0)](https://doggo.mrkaran.dev/docs/features/tweaks/)
- [doggo docs: output formats](https://doggo.mrkaran.dev/docs/features/output/)
- [FreshPorts `dns/doggo` — version, flavors, maintainer](https://www.freshports.org/dns/doggo/)
- [RFC 8482 — ANY queries no longer return everything](https://www.rfc-editor.org/rfc/rfc8482.html)
- [RFC 8914 — Extended DNS Errors (the EDE codes doggo surfaces)](https://www.rfc-editor.org/rfc/rfc8914.html)
- [RFC 9250 — DNS over QUIC (ALPN `doq`)](https://www.rfc-editor.org/rfc/rfc9250.html)
- [`dog` (Rust) — the tool doggo was modelled on](https://github.com/ogham/dog)
