# DNS Tools (`dns.corpberry.com`)

Suite of DNS tools on one subdomain, switched by sub-nav. **Four pages ship today:**

- **DNS lookup** (`/`) — every common record type for a name in one query
  (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, HTTPS), in parallel, against one
  resolver from a fixed allowlist. Paste an IP and it becomes a reverse (PTR)
  lookup.
- **Consistency** (`/consistency`) — asks every one of the zone's own
  authoritative nameservers directly with recursion off, compares them against
  the three allowlisted public resolvers, reads each server's SOA serial, and
  audits the delegation (redundancy, network diversity, open recursion,
  TCP/53, registry-vs-zone NS).
- **Domain** (`/domain`) — registration via RDAP and subdomains from
  Certificate Transparency. Both public, both free, and neither sends a packet
  at the domain itself.
- **Email** (`/email`) — SPF including the RFC 7208 ten-lookup limit that
  silently breaks it, DMARC policy strength (including a policy inherited from
  a parent via `sp=`), DKIM keys at twelve common selectors, MTA-STS policy
  **fetched over HTTPS** rather than just its DNS pointer, TLS-RPT and BIMI.

Named as a suite, not "DNS Lookup", deliberately: lookup is 1 of the 14 aspects
in [the feature inventory](01-feature-inventory.md), and most of what shipped
alongside it (zone health, delegation audit, RDAP, email DNS) isn't a lookup at
all. Same shape as [`iptools`](../../iptools/docs/README.md), where "IP lookup"
is one page of "IP Tools".

Every page speaks HTML + JSON + an htmx fragment from the same URL, like every
other tool here.

**Build-fit status.** Built from the 37-report research corpus in
[`RESEARCH.md`](RESEARCH.md) + [`reports/`](reports/), against
[the build-fit filter](02-build-fit.md#4-tiered-build-proposal). What shipped is
all of Tier 0 plus most of Tier 1's DNS surface: multi-resolver comparison, the
DNSSEC panel (DO/AD/EDE/NSID), parent-vs-child NS diff and SOA-serial
agreement, CT + RDAP, and the answer cache. Still unbuilt, and honestly so, in
[Not built](#not-built) below.

## Package layout (`dnstools/`, self-contained)

- `dns.go` — **domain**: the lookup fan-out over `miekg/dns`. `Service`,
  `Result`, `ResultSet`, `Record`, `NewService`, `validDomain`, the `Looker`
  interface. `Service` also carries an `*http.Client`, but nothing in this file
  uses it: the package's only outbound HTTPS is `email.go`'s MTA-STS policy
  fetch and `domain.go`'s two upstreams.
- `cache.go` — TTL-respecting answer cache + single-flight, sitting *below* the
  domain service (rule #5). In-process only, deliberately not Mongo-backed.
- `decode.go` — pure, network-free decoders: CAA, SVCB/HTTPS params, SOA,
  TXT purpose labels, and the nameserver-suffix → DNS-provider table.
- `spread.go` — **domain**: `/consistency`. The zone-apex NS walk, the
  authoritative and resolver probes, `summarise()`, and the health audit
  (`AddDelegationHealth` takes the ASN lookup and the registry NS list as
  injected inputs, so the transport stays out of it).
- `domain.go` — **domain**: `DomainClient`, the RDAP and crt.sh halves of
  `/domain`. Speaks HTTP by design and sends no DNS at all; `nil` disables both
  halves.
- `email.go` — **domain**: `/email`'s seven checks (MX + FCrDNS, SPF, DMARC,
  DKIM, MTA-STS, TLS-RPT, BIMI) plus `judge()`, which turns them into
  fail/warn/ok/info notes. Owns the package's one outbound HTTPS request that
  isn't `domain.go`'s.
- `handler.go` — **transport**: `Register` + query-param parsing, then content
  negotiation through four shared helpers (`reply`, `needName`, `unavailable`,
  `answered`). The rate limiter lives here.
- `embed.go` — the `go:embed` of `templates/`.
- `templates/` — one page and one htmx fragment per route: `index.html` +
  `result.html`, `consistency.html` + `spread.html`, and `domain.html` /
  `email.html`, which each hold both. Plus `nav.html` (suite sub-nav, four
  entries), `notes.html` (the shared severity-note list, so the severity
  aria-label is written once) and `error.html`.
- `tests/` — black-box tests over the exported API. Live queries call
  `requireEgress(t)` and skip honestly when UDP/53 egress is blocked, instead
  of passing vacuously.
- White-box `*_test.go` beside the code, the rule #6 exception, where the
  subject is unexported: `cache_test.go`, `decode_test.go`, `spread_test.go`,
  `spf_test.go`, and `testserver_test.go` — a local `miekg/dns` UDP server plus
  the test-only resolver seam that makes `127.0.0.1` reachable past the
  allowlist.

**Subdomain:** `dns.corpberry.com` (dev: `dns.localhost:8080`). Go package: `dnstools`.

## Endpoints

| | |
|---|---|
| `GET /` | Empty form (browser) / `400` (JSON caller) |
| `GET /?name=example.com` | **Every type at once**, default resolver |
| `GET /?name=example.com&type=MX&resolver=quad9` | Narrow to one type + pick a resolver |
| `GET /?name=1.1.1.1` | IP literal auto-rewritten to a PTR query |
| `GET /consistency?name=example.com` | Zone's own nameservers vs the public resolvers |
| `GET /consistency?name=example.com&type=TXT` | Same, for one record type (default `A`) |
| `GET /domain?name=example.com` | RDAP registration + CT subdomains |
| `GET /email?name=example.com` | SPF / DMARC / DKIM / MTA-STS / TLS-RPT / BIMI |

Every one of those serves JSON to anything that doesn't ask for `text/html`,
and an HTML fragment to htmx. A bare hit with no `?name=` is the empty form to
a browser and `400` to a JSON caller. A route whose upstream is switched off
answers `503`, not `502`: nothing failed, the feature simply isn't running.

`?type=` on both `/` and `/consistency` is checked against this package's own
`Types` list, not `miekg`'s RR registry, so `ANY` and `AXFR` are `400` on both.

## What it does, and why

Every behaviour here traces to a specific finding in the research corpus:

- **Every type in one query, not a dropdown.** The fan-out replaces making the
  user pick types one at a time. It is deliberately **not** an `ANY` query:
  RFC 8482 lets resolvers answer ANY with a minimal stub, so ANY lies. Asking
  each type concurrently is the honest version, and the corpus rates it the
  highest value-per-line feature available here.
- **Empty types collapse into one card.** Nine types queried, the ones with
  nothing published get named together on a single line rather than as nine
  empty cards. NXDOMAIN short-circuits that entirely: if the name doesn't
  exist, it's said once instead of per type — but only when most of the
  fan-out actually answered, so one surviving NXDOMAIN beside a wall of
  SERVFAILs doesn't get to speak for the name.
- **A failed type is not a missing type.** A SERVFAIL or timeout lands in
  `failed`, never in `missing`: "couldn't find out" is a different claim from
  "isn't published", and one dead type never cancels the others.
- **Records are printed under their real owner.** A CNAME'd name's answer
  carries the *target's* records; labelling them with the name that was typed
  publishes a zone nobody owns. Each record carries its `owner`, and the zone
  block prints it.
- **Query lives in the URL.** GET-shaped form, so every result is shareable.
  The one pattern all nine tools driven live share
  ([firsthand-ui-observations.md](reports/firsthand-ui-observations.md)).
- **TTL as a duration *and* raw seconds.** `5m (300s)`. Humanising is common;
  the tools that do it keep the integer too. A cached answer's TTLs count down
  rather than replaying the number captured at fetch, because a TTL that never
  moves is the wrong number on a tool for watching changes land.
- **NODATA ≠ NXDOMAIN ≠ SERVFAIL.** Three different sentences, not one "no
  results". Conflating them is called "the most common bug in this category"
  in [dns-concepts-and-query-modes.md](reports/dns-concepts-and-query-modes.md).
- **The query card names what was actually asked and who answered** — the
  fully-qualified qname, the type count, the resolver, the header flags, the
  DNSSEC state (validated / signed-but-not-validated / unsigned / broken), the
  answering node's NSID, and the elapsed ms. Per-type rcodes sit with the
  failed types, where they belong. Makes the result falsifiable rather than a
  bare assertion, and the printed `dig` lines carry `+nsid` when we got one, so
  they reproduce the "Answered by" row too.
- **IP literal auto-detects to PTR**, and says so rather than silently changing
  the question.
- **Resolver allowlist, no free-form `@server`.** Closes the SSRF hole on day
  one per [abuse-ratelimits-and-ethics.md](reports/abuse-ratelimits-and-ethics.md).
- **TCP retry on a truncated UDP answer**, on the lookup path *and* on
  `/consistency`'s direct probes. Without it the authoritative half sees
  whatever fits in 512 bytes while every resolver sees the full EDNS0 answer,
  and a large TXT set renders as "your nameservers disagree".
- **ASN / AS-name / country on A and AAAA answers**, by calling `iptools`'
  already-open IP2Location handles in-process. Same binary, no new dependency,
  no HTTP hop.
- **`/consistency` states a cause only when it can tell them apart.** Round-robin
  and geo-steering are separated from a stalled rollout by the SOA serial:
  different records at the same zone version is rotation, not a rollout. The
  resolver-only group count drives any sentence about what the public sees,
  and serials are compared per DNS provider, because two independent providers
  legitimately keep independent serials.
- **`/domain` distinguishes "no record" from "lookup failed".** An RDAP 404 is
  the registry saying no such object (RFC 7480 §5.3), not an outage, and the
  page says so.

## Abuse controls (built)

A bare lookup is a fan-out of up to 9 upstream queries and `/consistency` is
several dozen, so the controls
[abuse-ratelimits-and-ethics.md](reports/abuse-ratelimits-and-ethics.md)
calls non-negotiable are in place:

- **Resolver allowlist.** No free-form `@server`, so the lookup path can't be
  pointed at an arbitrary host.
- **Type allowlist.** `ANY` and `AXFR` are rejected with `400` on both `/` and
  `/consistency` — the amplification shape, and on `/consistency` it would be
  aimed at nameservers the caller chose.
- **Name validation.** One `validDomain` on all four routes: 253 bytes, ten
  labels, 63-byte labels, hostname shape. It also bounds the zone walk's input.
- **Publicly-routable-only egress.** `/consistency` is the one place a request
  decides which address we send packets to: a nameserver name resolving to a
  loopback, private or link-local address is refused rather than probed (port
  53, A records only — not a general port oracle, but still ours to close).
  `/email`'s MTA-STS fetch gates the same way at dial time, after resolution,
  and refuses to follow redirects (RFC 8461 §3.3).
- **Rate limit**, per client IP (`c.RealIP()`, Cloudflare-aware), 2/s with a
  burst of 10, in-process. 429s are content-negotiated like everything else.
  This is the first rate limiter in the repo.
- **Answer cache + single-flight** (`cache.go`). Answers are held for the
  shortest TTL in them, clamped to 5s–5m, negatives for 30s, bounded at 4096
  keys; an answer with a zero TTL is not held at all. Concurrent identical
  questions collapse into one upstream query. Not Mongo-backed on purpose: a
  cache outliving the process would make "is my change live yet" stale across
  deploys, which is the question this tool exists to answer.
- **Per-request query budgets**, page by page, because one click is many
  upstream queries and the heavy pages are the ones worth bounding:
  | Page | Caps | Worst case per request |
  |---|---|---|
  | `/` | `FanoutTypes` = 9 types (`maxTypesPerRequest` = 12 ceiling) + `maxDanglingChecks` = 5 | ~14 DNS |
  | `/consistency` | `maxZoneWalk` = 8 NS steps + `maxAuthoritative` = 8 nameservers x 5 probes + 3 resolvers | ~51 DNS + 1 HTTPS |
  | `/domain` | RDAP + crt.sh, one request each | 2 HTTPS, 0 DNS |
  | `/email` | 12 DKIM selectors + `maxSPFIncludes` = 15 + `maxMailHosts` = 5 x 4 FCrDNS + DMARC parent climb <= 3 + 6 fixed | ~56 DNS + 1 HTTPS |

  `/consistency`'s five probes per nameserver are: resolve its address, the
  question itself, an open-recursion probe, a TCP/53 reachability probe, and
  its SOA serial. The one HTTPS request is the RDAP fetch behind the
  registry-vs-zone delegation check.

  The SPF cap costs no accuracy: the only question is whether the record
  exceeds the RFC limit of 10, so once resolution passes that the verdict is
  settled and further queries buy nothing.

## Not built

- **`+trace`** — the delegation walk from the root. Egress allows it (below);
  it is simply not written.
- **Geographic propagation grid** — needs Globalping or equivalent. Asking
  from one vantage point and calling it "% propagated" is the false verdict
  `/consistency` exists to avoid, so this waits for real vantage points.
- **Local DNSSEC validation.** What ships is what the *resolver* reports: the
  AD bit, the presence of signatures, and a bogus verdict proven by a
  checking-disabled retry. The chain of trust is not walked or verified here,
  and `/domain` reports only whether the registry says a DS record exists.
- **Lookup history** — see [Decisions taken](#decisions-taken); declined, not
  pending.
- **DNSBL / RBL reputation card**, the ECS geo-steering explorer, and Tier 2's
  resolver-identity beacon zone.

## Decisions taken

Resolved from [02-build-fit.md §5](02-build-fit.md#5-open-questions-for-the-owner):

- **Own subdomain**, not a tab in `ip.corpberry.com` — the suite is too big to
  bolt onto another tool's nav, and Tier 2's beacon zone needs subdomain-shaped
  infra anyway. Moving it would still be a `Register` call and one vhost entry.
- **Abuse bar for v1:** allowlist + rate limit + cache + query budget, above.
  No Turnstile or challenge gating: that adds a third-party JS dependency and
  friction to every visit, for a tool whose expensive path is already bounded.
- **`miekg/dns` v1**, pinned in CLAUDE.md. v2 lives at `codeberg.org/miekg/dns`
  and is the faster, actively-developed one, but it requires **Go 1.27** (this
  repo pins 1.26), is pre-1.0 (`v0.6.x`) and reserves the right to break
  compatibility until roughly 2028. v1 is maintenance-only and will eventually
  be archived, which is the cost of this choice. Revisit when the Go pin moves.
- **No lookup history.** A DNS history row is domain + requester IP, i.e. closer
  to "who looked up what" than iptools' IP history. Not worth the liability for
  a feature nobody asked for.

## Egress: verified

Outbound DNS was tested **on the production host** (`stas-projects`, hostname
`test-2` — misleading name, it is prod) on 2026-09-16. All the paths the tool
needs are open:

| Path | Used by | Result |
|---|---|---|
| UDP/53 → 1.1.1.1 / 8.8.8.8 / 9.9.9.9 | every page | answers, `NOERROR` |
| TCP/53 (truncation fallback) | `/`, `/consistency` | works |
| Direct to an authoritative server (`+norecurse @198.41.0.4 . NS`) | `/consistency` | `l.root-servers.net.` |

So the UDP/53 transport this tool is built on works in production, **no
DoH-over-443 fallback is needed**, and `+trace` is available whenever it gets
written — that delegation walk was the one planned feature that would have died
behind a restrictive egress policy.

Three HTTPS paths leave the box as well, and were not part of that UDP test:
`rdap.org` and `crt.sh` for `/domain`, and `https://mta-sts.<domain>/.well-known/mta-sts.txt`
for `/email`. Outbound 443 is already exercised in production by `iptools`'
Shodan InternetDB client, so none of them needed a separate check. The MTA-STS
host is attacker-chosen by construction, which is why that fetch is gated at
dial time and refuses redirects.

Re-run only if the tool moves to a different host:

```
dig +timeout=5 @1.1.1.1 example.com A
dig +tcp +timeout=5 @1.1.1.1 example.com A
dig +timeout=5 +norecurse @198.41.0.4 . NS
curl -sS -o /dev/null -w '%{http_code}\n' https://rdap.org/domain/example.com
curl -sS -o /dev/null -w '%{http_code}\n' 'https://crt.sh/?q=%25.example.com&output=json'
```
