# Subdomain enumeration & Certificate Transparency

DNS answers questions you already know how to ask. It will not hand you the list of names in a zone: `AXFR` is refused by every sane authoritative server, & NSEC walking is mostly dead. **Certificate Transparency** is the accidental replacement. Chrome & Apple both refuse certs that aren't logged, so every publicly-trusted cert a domain ever received sits in an append-only public log w/ its full SAN list. Query that & you get a subdomain inventory for free, zero packets to the target. This covers the services that expose CT for enumeration (**crt.sh**, **Cert Spotter**, **Chaos**), the two tools that aggregate them (**subfinder**, **Amass**), & what a Go+htmx tool can realistically ship.

- **Scope:** crt.sh · SSLMate Cert Spotter · ProjectDiscovery Chaos · subfinder · OWASP Amass · adjacent: CertStream, MerkleMap, static-CT tiles · **Category:** passive asset discovery, not DNS resolution
- **Firsthand check (2026-09-15, re-verified & corrected 2026-09-16):** curled crt.sh JSON + atom + advanced form + `showSQL` + the form's `doSearch()` JS; Cert Spotter `/v1/issuances` incl. live rate-limit headers; Chaos `/dns/…/subdomains` & `/count` (401 no key) + its open `index.json`; MerkleMap `/v1/search` (401); Google CT log list v3; a Let's Encrypt static-CT `checkpoint`. Read subfinder & Amass **source** on GitHub; neither binary is installed here, so tool behaviour is read, not run. `dig`ged NSEC/NSEC3 posture on 3 zones & the wildcard trap on `corpberry.com`.

## What it is

**Why CT substitutes for zone transfers.** Three ways to get a name list out of a zone, two of which no longer work (probed 2026-09-16):

| Mechanism | Status |
| --- | --- |
| `AXFR` ([RFC 5936](https://www.rfc-editor.org/rfc/rfc5936.html)) | Refused in practice. **Not probed against third parties, by policy** — this row is RFC + general practice, not observation. |
| NSEC walking (RFC 4034) | Still works on plain-NSEC zones. `dig +dnssec +norecurse @ns.nlnetlabs.nl zzz.nlnetlabs.nl` -> NXDOMAIN w/ `zuul-aws.nlnetlabs.nl NSEC nlnetlabs.nl` & `!.nlnetlabs.nl NSEC 6only.nlnetlabs.nl`: real neighbour names, zone walkable. |
| NSEC3 (RFC 5155) / "black lies" | `iana.org` returned hashed owners (`jvg1fk7l….iana.org NSEC3 1 0 0 -`), recoverable only by offline cracking. `cloudflare.com` returned `zzzz-nope-3496.cloudflare.com NSEC \000.zzzz-nope-3496.cloudflare.com`, a synthesized range covering exactly the queried name. Walking yields nothing. |
| **CT logs** | Public, append-only, complete for publicly-trusted certs. **The one that works.** |

**Why CT is complete.** Chrome requires, for embedded SCTs, ≥2 SCTs for certs w/ lifetime ≤180 days & **≥3 for certs >180 days**, w/ ≥2 from distinct log operators. Apple requires 2 SCTs ≤180 days & 3 for 181-398 days, ≥1 from an RFC 6962 log. A CA that skips logging ships a cert no major browser trusts, so CAs log everything, incl. the **precertificate** (hence near-duplicate pairs). Firsthand, Google's log list v3 (version 91.6, `2026-09-15T13:35:08Z`) carries **8 operators, 26 RFC 6962 logs (21 usable, 2 readonly, 3 retired) & 33 tiled static-CT logs (22 usable, 11 qualified)**.

**The hard limit, up front:** CT only knows names that appear in a cert. Internal-only hosts, names hidden behind a wildcard cert, & anything served w/ a private CA are invisible. That is exactly why Amass & subfinder bolt brute-force, permutation & passive-DNS onto CT rather than shipping CT alone.

## Registration, access & pricing (checked 2026-09-16)

| Service | Key | Free tier | Paid | CORS |
| --- | --- | --- | --- | --- |
| **crt.sh** | No | Unmetered in practice, no published quota, no rate-limit headers seen across ~20 requests | None (Sectigo runs it as a public good) | `access-control-allow-origin: *` on simple GET ✅; `OPTIONS` preflight returns `allow: GET,POST,OPTIONS,HEAD` but **no ACAO**, so a preflighted request (custom headers) would fail |
| **Cert Spotter** | Optional | **100 single-hostname & 10 full-domain queries/hr** unauthenticated (pricing page "Small", matches live `x-ratelimit-limit`) | Medium $50/mo (1,000 / 100), Large $500/mo (10,000 / 1,000), 2x Large $1,000/mo, 3x Large $1,500/mo; Firehose $1,000/mo; provisioned indexes from $100/mo/domain | `*` + full preflight ✅ |
| **Chaos** | **Yes** (PDCP) | Free key, **60 req/min/IP** (their docs). Personal use only; commercial use is the enterprise plan | Enterprise, contact sales | n/a (401 w/o key) |
| **subfinder** | n/a (MIT) | Free; 52 sources, many need their own keys | n/a | n/a |
| **Amass** | n/a (Apache-2.0 per LICENSE; GitHub's detector says NOASSERTION because of the prepended copyright header) | Free; **all 38 v5 data sources require credentials** | n/a | n/a |
| **MerkleMap** | **Yes** | None listed | €49/mo incl. 100,000 requests, then pay-as-you-grow | n/a (401 w/o key) |

Adjacent SSLMate products: hosted **Cert Spotter monitoring** from **$15/mo or $150/yr, 30-day trial** (not free), plus free browser tools CAA Record Helper, What's My Chain Cert? & **CT Policy Analyzer**.

## Features — complete inventory

### crt.sh (Sectigo) — the reference CT search

Firsthand `GET https://crt.sh/?q=corpberry.com&output=json` -> HTTP 200, ~143 KB, **365-366 rows**. Fields returned, exactly: `issuer_ca_id`, `issuer_name`, `common_name`, `name_value` (newline-joined SAN list), `id`, `not_before`, `not_after`, `serial_number`, `result_count`.

**Search types**, verbatim from the `?a=1` advanced form's `searchtype` select (21 options):

| Group | Values |
| --- | --- |
| Certificate | `c`, `id` (crt.sh ID), `ctid` (CT entry ID), `serial`, `ski` (Subject Key Identifier), `spkisha1`, `spkisha256`, `subjectsha1`, `sha1`, `sha256` |
| CA | `ca`, `CAID`, `CAName` |
| Identity | `Identity` (default), `CN`, `E` (emailAddress), `OU`, `O` (organizationName) |
| SAN | `dNSName`, `rfc822Name`, `iPAddress` |

**Modifiers**, same form: `match` = *Autoselect* (empty) / `=` / `ILIKE` / `LIKE` / `single` / `any` / `FTS`; checkboxes `excludeExpired`, `deduplicate`, `showSQL`, `searchCensys`.
- **`output=json`** works on identity/SAN/CN searches. It is **not** supported on `id=`, & the failure is silent: `?id=1&output=json` returns **HTTP 200** w/ an HTML body `Unsupported output type: json`. crt.sh returns 200 for any unrecognised path or output too (`/rss`, `/monitored-domains` both 200 w/ the same body), so **status code is useless as an error signal**: parse the body.
- **`exclude=expired`** is the highest-value knob. `identity=%.corpberry.com` unfiltered -> 366 rows / **82 unique names (81 non-wildcard)**; w/ `exclude=expired` -> 13 rows / **10 names (9 non-wildcard)**. Historical vs live footprint, one parameter apart.
- **`deduplicate=Y`** collapses the precert/cert pair every issuance produces. **Atom feed** `https://crt.sh/atom?identity=corpberry.com` -> HTTP 200, `application/atom+xml`, 949 KB: a **free monitoring primitive**, subscribe for new certs w/o polling.
- **`showSQL=Y`** prints the generated query into a `TEXTAREA`. Observed: `plainto_tsquery('certwatch', $1) @@ identities(cai.CERTIFICATE) AND cai.NAME_VALUE ILIKE ('%' || $1 || '%')` over `certificate_and_identities`, w/ **`LIMIT 10000` on that inner scan**, *then* a `GROUP BY sub.CERTIFICATE` dedup in an outer CTE. The cap therefore bites at 10,000 **identity rows**, not 10,000 returned certs, so a domain w/ many SANs per cert hits it sooner than the row count suggests.
- **Linters:** `cablint`, `x509lint`, `zlint`, `keylint` & an ALL option whose value is `lint`, each w/ a *1-week Summary* or *Issues* view. The interactive linters link out to `pkimet.al/linttbscert` & `pkimet.al/lintcert`.
- **Other tools on the same host** (from the `?a=1` nav, not just "CA listings"): `/cert-populations`, `/revoked-intermediates`, `/ca-issuers`, `/ocsp-responders`, `/test-websites`, `/monitored-logs`, `/accepted-roots-missing`, `/gen-add-chain` (Certificate Submission Assistant), `/mozilla-disclosures`, `/mozilla-certvalidations`, `/mozilla-onecrl`, `/apple-disclosures`, `/chrome-disclosures`. A compliance-reporting product bolted to a search box.
- **`searchCensys` does nothing server-side.** Read out of the form's `doSearch()` JS: when checked, it rewrites the submit target to `//search.censys.io/search?resource=certificates&q=…`, mapping crt.sh types to Censys fields (`Identity`->`names`, `CN`->`parsed.subject.common_name`, `dNSName`->`parsed.extensions.subject_alt_name.dns_names`, `sha256`->`fingerprint_sha256` …) & `alert()`ing "Censys doesn't support this search type" for `id`, `ctid`, `ski`, `spkisha1`, `spkisha256`, `subjectsha1` & `E`. It is a redirect, not a federated search.
- **Public PostgreSQL:** `crt.sh:5432`, db `certwatch`, user `guest`. TCP connect **succeeded** firsthand; **no session was ever established** (no `psql` here, & a raw protocol handshake was blocked by local policy). The DSN is taken from subfinder's source, not from a login: `host=crt.sh user=guest dbname=certwatch sslmode=disable binary_parameters=yes connect_timeout=<n>`, w/ a fallback to `https://crt.sh/?q=%25.<domain>&output=json` when the SQL path returns nothing.
- **Reliability, observed:** crt.sh returned `HTTP 502` from nginx on every request for ~2 min mid-pass, then recovered. The 5xx history is firsthand, not folklore.

### SSLMate Cert Spotter — the clean API

| Endpoint | Params |
| --- | --- |
| `GET /v1/issuances` | `domain` (required), `include_subdomains`, `match_wildcards`, `after`, `expand` (repeatable) |
| `GET /v1/issuances/firehose` | `after`, `expand`. Every issuance across all logs, paid. W/o `after` it returns ~the last hour |

`expand`: `dns_names`, `pubkey_der`, `pubkey`, `issuer`, `issuer.name_der`, `issuer.website`, `issuer.caa_domains`, `issuer.operator`, `issuer.operator.pubkey_der`, `revocation`, `problem_reporting`, `cert_der`. Firsthand fields: `id`, `tbs_sha256`, `cert_sha256`, `dns_names[]`, `pubkey_sha256`, `issuer{friendly_name,pubkey_sha256,name}`, `not_before`, `not_after`, **`revoked`**, `cert{type:"precert",sha256,data}`.
- **Cursor pagination via `Link` header**, firsthand: `link: <https://api.certspotter.com/issuances?after=16751734253&domain=…>; rel="next"` (note the next URL drops the `/v1` prefix). No offset math, no page numbers. Cleanest pagination in this space.
- **Live quota headers:** `x-ratelimit-limit: 10` / `remaining: 9` on a full-domain query, `100` / `99` on a single-hostname one. The API tells you your budget on every response. Docs also specify a **`Retry-After`** on empty responses, which is the polling contract.
- **Structured errors:** HTTP 400 w/ `{"code":"bad_query","message":"…","sub_errors":[{"code":"missing_field","field":"domain"}]}`. **`cache-control: public, max-age=14400, must-revalidate`** (4h) & `vary: Authorization`: they expect & permit caching.

### ProjectDiscovery Chaos

- **Base `https://dns.projectdiscovery.io/dns/`**, paths `/{domain}/subdomains` & `/{domain}/count`. Both returned **HTTP 401 `{"error":"unauthorized","message":"get access token here https://cloud.projectdiscovery.io"}`** firsthand. Auth = PDCP key. Their docs state the API is rate-limited to **60 requests/min/IP** & accepts a domain name only.
- **How the data is built**, verbatim from their landing page: ingests "live certificate streams and uses various techniques like DNS PTR lookups, TLS grabs, HTTP header collection, and IPv4 scanning on non-default ports." CT is one input among several, which is why Chaos returns names CT alone misses.
- **`chaos-client` CLI:** `-key`, `-d`, `-dL`, `-count`, `-json`, `-o`, `-silent`, `-v`, `-version`, `-up`, `-duc`; env `CHAOS_KEY` (subfinder reads `PDCP_API_KEY`). MIT, Go.
- **The genuinely free part:** `https://chaos-data.projectdiscovery.io/index.json` is **open, no key, CORS `*`**. Firsthand 2026-09-16: 289 KB, **802 programs, 37,627,494 subdomains**, per-entry `{name, program_url, URL (.zip), count, change, is_new, platform, bounty, last_updated}` across hackerone / bugcrowd / intigriti / yeswehack / hackenproof / bugbountych (`platform` is sometimes `""`). Largest: Cisco Meraki 10,404,098 names. Refreshed daily. Served as `content-type: binary/octet-stream`, so a browser `fetch` needs `.text()` + manual parse, not `.json()`. Bug-bounty scope only, so useless for arbitrary domains, but free & pre-computed.

### subfinder (ProjectDiscovery, MIT, ~14.4k★, Go)

The aggregator. **52 active sources**, from the `[52]subscraping.Source` array literal in `pkg/passive/sources.go` on `dev`: `alienvault anubis bevigil bufferover builtwith c99 censys certspotter chaos chinaz commoncrawl crtsh digitalyama digitorus dnsdb dnsdumpster dnsrepo domainsproject driftnet fofa fullhunt github hackertarget hudsonrock intelx leakix merklemap netlas onyphe profundis pugrecon quake rapiddns reconeer redhuntlabs robtex rsecloud scanmalware securitytrails shodan shodanct sitedossier submd thc threatbook threatcrowd urlscan virustotal waybackarchive whoisxmlapi windvane zoomeyeapi`. Three more are commented out in-tree w/ reasons given: `reconcloud` ("failing due to cloudflare bot protection"), `riddler` ("cloudfront protection"), `threatminer` ("failing api"). Useful signal about which free sources rot.

Per-source contract worth copying: each implements `Name()`, `KeyRequirement()` (`NoKey`/`OptionalKey`/`RequiredKey`), `HasRecursiveSupport()`, `Statistics()` (requests / results / errors / timeTaken / skipped). From source: **crtsh = `NoKey` + recursive**; **certspotter = `RequiredKey`** (the 10/hr free limit is too low to default to) + recursive; **chaos = `RequiredKey`, no recursion**; **merklemap = `RequiredKey`** + recursive.

Flags: `-d`/`-dL` input · `-s`/`-es`/`-all`/`-recursive` source selection · `-m`/`-f` match/filter · `-rl`/`-rls`/`-t` rate & concurrency · `-o`/`-oJ` (JSONL)/`-oD`/`-cs` (collect sources)/`-oI` (IPs) output · `-nW` active-only · `-r`/`-rL` resolvers. Usable as a Go library (`examples/main.go`), which matters for a Go monolith.

### OWASP Amass v5 (Apache-2.0, ~15.2k★, Go)

Not a subdomain tool any more, an **asset graph**. v5.1.1 released 2026-04-07.

- **Open Asset Model:** typed assets (`FQDN`, `IPAddress`, `Netblock`, `AutonomousSystem`, `TLSCertificate`, `Service`, `URL`, `Organization`, `Person`, `Contact`, `Product`, `File`, `Location`, `Identifier`, `FundsTransfer`) w/ typed relations & properties, persisted in `asset-db` (Postgres supported).
- **Transformations** replace v4's flag soup: config declares `FQDN->DNS`, `AutonomousSystem->RDAP`, `Product->ALL` etc., each w/ `ttl` (freshness, minutes), `confidence` (0-100 threshold) & `priority` (1-10). Their own docs say `priority` "may influence queue ordering in some future extensions", i.e. it is declared but not yet acted on. `->ALL` is the wildcard.
- **Plugin families** from the repo tree: `api/` (crtsh, chaos, binaryedge, dnsrepo, hackertarget, hunterio, leakix, passivetotal, securitytrails, virustotal, zetalytics, grepapp, rdap/, gleif/, aviato/) · `scrape/` · `brute/alterations.go` (permutation) · `dns/` · `archive/wayback.go` · `whois/` · `enrich/tls_cert.go` · `horizontals/` · `service_discovery/`.
- **Horizontal correlation** is the distinctive mechanic & nobody else here does it, but the mechanism is narrower than it sounds. Reading `engine/plugins/horizontals/tls_cert.go`: it fires on a discovered `TLSCertificate`, bails if the cert's **subject common name** is already in scope, pulls `Organization` entities off the cert's contact record, &, **only if one of those orgs is already in scope**, resolves the subject CN back to its registered domain & `enqueueIfOutOfScope`s it plus the orgs. It works off the **subject CN, not the SAN list**, `getZoneApexFQDN` walks incoming `node` edges in the asset DB rather than parsing the name, & the code comment says the result "should be added to the scope and reviewed", so it queues candidates rather than silently widening scope. The idea (certs reveal *sibling domains*, not just names under one domain) survives; the SAN-driven version of it does not exist in the code.
- 38 data sources, **all requiring credentials**, w/ per-source cache TTLs (BinaryEdge 10080 min, Chaos 4320, AlienVault 1440, global floor 1440) & multi-account key rotation to spread rate limits. crt.sh is *not* in that table: its plugin is keyless & hits `https://crt.sh/?CN=<name>&output=json&exclude=expired`, i.e. the `CN` search type w/ expired excluded, not `q=` or `identity=`.

### Adjacent, worth knowing

- **CertStream** (Calidog, MIT, Elixir): websocket firehose of every cert entering CT, near real time. The maintained drop-in is **`d-Rickyy-b/certstream-server-go`** (230★, MIT, pushed 2026-09-14). This is the mechanic behind every domain-squatting alert product.
- **Static CT API (tiled logs):** 33 of the logs in Google's list are now tile-based. Firsthand, `GET https://mon.sycamore.ct.letsencrypt.org/2026h2/checkpoint` -> HTTP 200, `text/plain`, a signed checkpoint reporting **914,375,106 entries**, no auth. Tiles are plain cacheable static files behind a CDN, which is what makes self-hosting a monitor newly affordable. No `access-control-allow-origin` header, so server-side only.
- **MerkleMap**, a newer CT index, is `RequiredKey` in subfinder & returned `401 {"status":"Unauthorized","message":"Missing Authorization header"}` on `/v1/search?query=*.<domain>`. Pricing page lists one plan, €49/mo for 100k requests, no free tier.

## Query surface: what you can pivot on

CT has no RR types; the equivalent axis is **which certificate identity you search & how**. Complete free pivot set today:

| Pivot | crt.sh | Cert Spotter |
| --- | --- | --- |
| Domain / subdomain | `Identity`, `q`, `dNSName`, `CN` | `domain` + `include_subdomains` |
| Wildcards | `%` in value, `match=ILIKE/LIKE` | `match_wildcards` |
| Org / OU / email | `O`, `OU`, `E`, `rfc822Name` | no |
| IP in SAN | `iPAddress` | no |
| By issuer | `ca`, `CAID`, `CAName` | client-side on `issuer` |
| By public key | `ski`, `spkisha1`, `spkisha256` | `pubkey_sha256`, `expand=pubkey` |
| By cert hash / serial | `sha1`, `sha256`, `serial`, `subjectsha1` | `cert_sha256`, `tbs_sha256` |
| Validity filter | `exclude=expired` | client-side on `not_after` |
| Dedup precert pairs | `deduplicate=Y` | client-side on `tbs_sha256` |
| Revocation | via linter / OCSP monitors | **`revoked` inline**, `expand=revocation` |

`spkisha256` is the sleeper: searching by **public-key hash** finds every cert that reused one key, tying together hosts that share nothing else. No DNS lookup & no passive-DNS service can do that.

## How it works

crt.sh is a Postgres database (`certwatch`) fed by Sectigo's own `ct_monitor` daemon consuming the logs, w/ the web tier as a `mod_certwatch` PL/pgSQL gateway; the `showSQL` output shows search is one full-text query against a `certificate_and_identities` view, so freshness = ingest lag. Cert Spotter is SSLMate's own log-monitoring index (`server: sslmatehttpd`) behind a cursor-paginated REST API. Chaos is a scan+CT hybrid served only to keyed clients. None of them touch the target: **a CT lookup is zero-packet reconnaissance**, which is why it belongs in a hobby tool. No outbound scan traffic, no abuse complaints, none of the Hetzner-ban risk that shelved the live port scanner.

## Output & UX

crt.sh's HTML is a 2003-era table & its JSON is flat & ungrouped: ~366 rows w/ the same handful of names repeated, precert+cert pairs, expired & live mixed. **Every consumer does the same three-step cleanup**: split `name_value` on newlines, drop `*.` entries, dedupe into a set, 366 rows -> 81 names. That cleanup is the entire product opportunity. Cert Spotter's JSON is already clean (`dns_names` is a real array) but is ordered by discovery, not grouped by name. Neither offers a shareable result URL beyond the query string, neither exports CSV, & neither tells you which names still exist.

## Monetization, limits & abuse controls

crt.sh sells nothing & publishes no quota; the `LIMIT 10000` in its own generated SQL is the real throttle, plus the 5xx-under-load behaviour observed during this pass. Treat it as best-effort infrastructure & always carry a fallback (subfinder does exactly this: Postgres first, HTTP JSON second). Cert Spotter gates on **query shape**, not just volume: a full-domain query costs 10x a single-hostname one, a smart & copyable pricing axis. Chaos gates behind a key & restricts free use to personal, non-commercial. Amass v5 pushed every credentialled source behind the user's own accounts, offloading rate limits onto them.

## Ideas worth stealing

- **The two-step CT pipeline is ~60 lines of Go & is the whole feature.** `GET https://crt.sh/?q=%25.<domain>&output=json&deduplicate=Y` -> split each `name_value` on `\n` -> lowercase, strip `*.`, dedupe into a `map[string]struct{}`. One call turned 366 rows into 81 names for `corpberry.com`. Everything below is polish. **Check the body, not the status:** crt.sh answers 200 even when it is refusing you.
- **Ship the expired/live toggle as the headline control.** `exclude=expired` took `corpberry.com` from 82 names to 10. Render it as a segmented control: *Currently valid (10)* / *Ever issued (82)*. One parameter, two genuinely different answers, & it teaches the user something about their own attack surface.
- **Resolve discovered names & badge them, but detect wildcard DNS first.** Firsthand trap: all 81 non-wildcard CT names for `corpberry.com` resolved, incl. long-dead ones, because Cloudflare answers `*`; a control label `zz-random-9999-probe.corpberry.com` resolved to `188.114.97.3`. Fix: probe one random label up front, & if it answers, suppress the "live" badge & fall back to an HTTP status probe, which did discriminate (`ip.corpberry.com` -> 200, random label -> 404).
- **Group by name, not by cert, & htmx the enrichment in.** Invert crt.sh's shape: one row per FQDN w/ *first seen* (min `not_before`), *last seen* (max `not_after`), *cert count*, *issuers*. Return that list immediately (~1-4s observed, latency is volatile), then let each row `hx-get` its own resolve+status badge. The view every user wants, no free service renders it, & no spinner blocks the page.
- **Cache per domain in Mongo w/ a TTL index** (`platform.EnsureTTLIndex`, rule #5) so repeat lookups are free & crt.sh is not hammered; Cert Spotter's own `max-age=14400` is a defensible TTL to copy. **"New since last time" then falls out for free**: diffing today's name set against the stored one is a `map` subtraction, & it delivers the one thing Cert Spotter charges $15/mo for. No firehose, no websocket, no cron.
- **Steal Cert Spotter's `X-RateLimit-Limit`/`-Remaining` headers & its `Link: <…?after=…>; rel="next"` cursor** for the JSON side of the tool. Both cost nothing, both beat offset pagination, & a Mongo `_id` cursor already has the right shape.
- **`corpberry.com` is a live demo of the tool's own value.** CT returned `mongodb.corpberry.com`, `n8n.corpberry.com`, `test1.corpberry.com`, `chat.corpberry.com` & 77 more. A "try it on this site" button sells the feature in one click & doubles as a blog post.
- **Show the wildcard blind spot, & link the atom feed.** If a `*.domain` cert exists, say so: "a wildcard cert covers this domain, so CT cannot show names issued under it." Then link `https://crt.sh/atom?identity=<domain>`: zero code, real monitoring utility, honest that someone else is doing the watching.
- **Do not build source aggregation.** subfinder has 52 sources & 3 already commented out as broken. Two free CT sources, clearly labelled, is a shippable tool; 52 keyed sources is a treadmill.

## Gaps & what it does not do

- **CT is blind to anything without a public cert:** internal DNS, names behind wildcards, private-CA hosts, `MX`/`TXT`/`SRV` targets that never got a cert.
- **CT is blind to whether a name still exists.** It is an issuance archive; liveness needs resolution, which needs the wildcard workaround above. No CT source offers reverse-by-IP, historical A records, or anything a passive-DNS product gives. Different tool.
- **crt.sh caps at 10,000 identity rows** per query (its own generated SQL, applied before dedup) & 502'd for minutes during this pass, no SLA. **Free Cert Spotter** cannot be a default backend at 10 full-domain queries/hr shared across all users. **Chaos** is unusable unauthenticated & its free data is bug-bounty scoped. **MerkleMap** has no free tier at all.
- Names in CT are public, but enumerating someone else's attack surface still warrants an authorization note in the UI, same conclusion the port-scanner report reached.

## Verified firsthand vs inferred

**Verified firsthand (curl/dig from this machine, 2026-09-15 & 2026-09-16):** crt.sh JSON status/size/fields/row counts; the `exclude=expired` (366->13 rows, 82->10 names) & `deduplicate=Y` deltas; the 21 `searchtype` values, 7 `match` modes, 4 checkboxes & the full nav tool list read out of the `?a=1` form HTML; the `searchCensys` redirect logic read out of that page's own `doSearch()` JS; the `showSQL` output incl. `LIMIT 10000` sitting on the inner scan; atom feed content type & size; `output=json` on `id=` returning **200** w/ an HTML error, & the same 200-on-unknown-path behaviour for `/rss` & `/monitored-domains`; crt.sh 502ing for ~2 min; crt.sh `access-control-allow-origin: *` on GET & its *absence* on `OPTIONS`; Cert Spotter response schema, `Link` cursor, `x-ratelimit-limit` 10 vs 100, `cache-control` incl. `must-revalidate`; Chaos 401 on both paths; chaos-data `index.json` open, CORS `*`, 802 programs / 37,627,494 names / `binary/octet-stream`; MerkleMap 401 body; Google CT log list v3 counts & states; a static-CT `checkpoint` w/ 914,375,106 entries & no CORS header; NSEC vs NSEC3 vs black-lies on nlnetlabs.nl / iana.org / cloudflare.com; wildcard DNS on `corpberry.com` & the 404-vs-200 discriminator; TCP 5432 open on crt.sh; GPL-3.0 LICENSE files in all six `crtsh/*` repos; Apache-2.0 LICENSE in `owasp-amass/amass`; MPL-2.0 in `SSLMate/certspotter`.

**Read from primary source, not executed:** all subfinder behaviour (the `[52]` source array, `KeyRequirement`, recursion flags, the crt.sh Postgres DSN & the HTTP fallback URL) & all Amass v5 behaviour (`horizontals/tls_cert.go` logic, the crt.sh plugin URL, the 38-source credential table & TTLs, transformations semantics). Neither binary is installed here. Pricing read from vendors' own pricing pages, not from a transaction: SSLMate's five tiers + Firehose + provisioned indexes, Cert Spotter monitoring at $15/mo, MerkleMap at €49/mo; the Chaos 60 req/min/IP figure is from ProjectDiscovery's own docs.

**Still unverified:** that the crt.sh Postgres interface accepts the `guest` login. TCP 5432 connects, but no session was ever established here (no `psql`, & a raw wire-protocol handshake was blocked by local policy), so the working DSN rests entirely on subfinder's source. **Cut since the last revision as unsupportable:** a "10 new domains/month" Chaos free-tier figure (absent from the Chaos landing page, `opensource/chaos/overview` & `opensource/chaos/running`), a `gitlab` entry in subfinder's source list (not in the array), a claimed 195-row unfiltered crt.sh result (actual 366), and the SAN-driven reading of Amass's horizontal cert pivot (the code uses the subject CN). AXFR remains RFC-and-practice only: none was attempted against a third party, by policy.

## Open source / reusable

- **`github.com/crtsh/*`** (all GPL-3.0, LICENSE files checked): `certwatch_db` (the schema), `ct_monitor` (Go log consumer), `libx509pq`, `mod_certwatch`, `ctlint`, `crtsh-web`. The entire crt.sh stack is public; GPL, so read it for schema & query shapes rather than vendoring.
- **`software.sslmate.com/src/certspotter`** (`SSLMate/certspotter`, MPL-2.0, Go, ~1.2k★): the omission that matters most here. A self-hostable CT monitor that **needs no database**, reads a watchlist file (`.example.com` for a whole tree) & emails on match. If the tool ever wants real monitoring rather than polling, this is the thing to run or read, & MPL-2.0 is file-level copyleft, far friendlier than crt.sh's GPL.
- **`github.com/projectdiscovery/subfinder`** (MIT, Go): usable as a library, & `pkg/subscraping/sources/crtsh/crtsh.go` + `certspotter/certspotter.go` are ~150-line reference implementations of exactly the two calls this tool would make, incl. the Postgres-then-HTTP fallback.
- **`github.com/owasp-amass/amass`** (Apache-2.0), & `open-asset-model` / `asset-db` / `resolve` are separately importable Go modules. **`certstream-server-go`** (MIT) for a live CT ticker; **`chaos-client`** (MIT) as a thin, readable client.

## Sources

- crt.sh: [advanced search form (`?a=1`): searchtype, match, checkbox, nav & `doSearch()` JS](https://crt.sh/?a=1) · [`certwatch_db` schema, GPL-3.0](https://github.com/crtsh/certwatch_db)
- subfinder source: [`pkg/passive/sources.go`, the `[52]` source array & disabled-source comments](https://github.com/projectdiscovery/subfinder/blob/dev/pkg/passive/sources.go) · [`crtsh.go`, Postgres DSN, SQL & HTTP fallback](https://github.com/projectdiscovery/subfinder/blob/dev/pkg/subscraping/sources/crtsh/crtsh.go)
- SSLMate: [CT Search API v1 reference: endpoints, params, `expand`, `Retry-After`](https://sslmate.com/help/reference/ct_search_api_v1) · [CT Search API pricing, five tiers + Firehose + provisioned indexes](https://sslmate.com/pricing/ct_search_api) · [Cert Spotter monitoring, $15/mo](https://sslmate.com/certspotter/) · [certspotter OSS monitor, MPL-2.0, Go](https://github.com/SSLMate/certspotter)
- Amass v5: [data sources, the 38-source credential table & TTLs](https://github.com/owasp-amass/docs/blob/master/docs/data_sources/data_sources.md) · [transformations config, ttl / confidence / priority](https://github.com/owasp-amass/docs/blob/master/docs/configuration/transformations.md) · [`horizontals/tls_cert.go`, the subject-CN sibling-domain pivot](https://github.com/owasp-amass/amass/blob/main/engine/plugins/horizontals/tls_cert.go) · [`api/crtsh.go`, the `?CN=…&exclude=expired` call](https://github.com/owasp-amass/amass/blob/main/engine/plugins/api/crtsh.go)
- Chaos: [running Chaos, the 60 req/min/IP limit](https://docs.projectdiscovery.io/opensource/chaos/running) · [landing page, how the dataset is built](https://chaos.projectdiscovery.io/) · [public bug-bounty dataset index, open & CORS `*`](https://chaos-data.projectdiscovery.io/index.json)
- [Google CT log list v3, operators, RFC 6962 logs & tiled static-CT logs](https://www.gstatic.com/ct/log_list/v3/log_list.json) · [certstream-server-go, maintained Go CT firehose](https://github.com/d-Rickyy-b/certstream-server-go)
- [Chrome CT policy, SCT counts by lifetime](https://googlechrome.github.io/CertificateTransparency/ct_policy.html) · [Apple's CT policy, 2 SCTs ≤180d / 3 for 181-398d](https://support.apple.com/en-us/103214)
- [MerkleMap pricing, €49/mo, no free tier](https://www.merklemap.com/pricing)
- [RFC 6962, Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962.html) · [RFC 9162, CT v2](https://www.rfc-editor.org/rfc/rfc9162.html) · [RFC 5936, AXFR](https://www.rfc-editor.org/rfc/rfc5936.html) · [RFC 4034, NSEC](https://www.rfc-editor.org/rfc/rfc4034.html) · [RFC 5155, NSEC3](https://www.rfc-editor.org/rfc/rfc5155.html)
