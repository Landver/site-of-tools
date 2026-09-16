# ViewDNS.info

The **grab-bag**: 26 free web tools + 22 paid API products under one roof, live since 2010, rebuilt ~2024-25 into a green-accent Tailwind site w/ accounts, credits & an MCP gateway. **Not an SPA**: the archived HTML is plain server-rendered multi-page, `<form action="">` submitting GET, nav tiles doing `onclick="window.location.href='…'"`, no client-side router. Closer to our Echo+htmx shape than it looks. Relevant to us for two reasons: it is the canonical "one domain, many small lookups" information architecture (exactly the shape a `dns.corpberry.com` could take), and its **free tool = paid API, same backend** monetization is the cleanest freemium mechanic in the DNS-tool space.

- **URL:** https://viewdns.info · **Category:** multi-tool DNS/IP/domain intelligence portal + commercial data vendor · **Registration:** free tools need no account; copy/export & all API access need one · **Pricing:** 250 free trial queries, then $29-$549/mo (2026-06-05 capture, still the newest archived as of 2026-09-16) · **API:** `https://api.viewdns.info/<tool>/`, REST GET, `apikey` query param, JSON or XML
- **Firsthand check (2026-09-15, re-run 2026-09-16):** the **entire `viewdns.info` origin is behind a Cloudflare challenge**. `curl` & WebFetch both get **403** w/ `cf-mitigated: challenge`, even on `/robots.txt` & `/.well-known/security.txt`. **No rendered tool page was observed live.** Everything about the web UI below comes from Wayback captures of their own pages (snapshot dates inline), not from a live view. Probed live: `api.viewdns.info` (not challenged), the MCP endpoint, RDAP, `dig`. Those are flagged firsthand.

## What it is

Registered **2010-02-03**, expiring 2027-02-03, last registry change 2026-08-12, NS `jim`/`lorna.ns.cloudflare.com`, all four `clientXxxProhibited` locks set (firsthand, RDAP 2026-09-16). Now positions as "your trusted source for domain and IP intelligence". `/about-us/` (capture 2026-09-10) is pure boilerplate: **no named founder, no team page, no company entity**, contact is `feedback@viewdns.info`. Treat data provenance as opaque. Three business lines stack on one property: **free tools** (SEO funnel) -> **API subscriptions** -> **bulk data feeds**. A `/research/` section carries 3 content-marketing articles (Iran censorship survey, DNS cache poisoning in China, DOJ seized-domain "graveyards"), each doubling as the justification for a tool.

## Registration, access & pricing

Free tools run w/o login. Accounts gate three things: **copy button**, **export button**, and the API (dark mode too: "Sign in to enable dark mode"). Pricing, capture **2026-06-05**, unverified live because of the challenge:

**Headline plans:** Sandbox $0 / **250 Trial Queries** / "Access **most** APIs, not all" · Developer $49-mo / 2,500 · Professional $149-mo / 15,000 (badged Most Popular) · Business $549-mo / 100,000 · Enterprise, contact us, "Custom APIs possible".

Sub-tiers run $29/mo (1k) -> $549/mo (100k); annual $319 -> $6,039; **prepaid one-off packs** $49 (1k) -> $3,599 (500k). Every paid row says "Monthly Queries" while Sandbox says only "Trial Queries", so the free 250 reads as one-off rather than recurring, but that is our reading of the wording, not a stated term. **One credit pool spans every endpoint**: "The query limit for all paid plans ... is able to be used across all our APIs with one single subscription." That single-pool framing is the pitch, & it is why they can keep adding endpoints cheaply.

## Features, complete inventory

**Free web tools (26).** Verbatim names & descriptions from the homepage, capture **2026-09-08**. "API?" = does a matching paid product exist.

| Tool | Path | What it claims | API? |
|---|---|---|---|
| Reverse IP Lookup | `/reverseip/` | all sites hosted on a given server | yes |
| Reverse Whois Lookup | `/reversewhois/` | domains owned by an individual/company | yes |
| IP History | `/iphistory/` | historical IP addresses for a domain | yes |
| **DNS Report** | `/dnsreport/` | complete report on DNS settings | **no** |
| Subdomain Discovery `New` | `/subdomains/` | all known subdomains for a domain | yes |
| Reverse NS Lookup | `/reversens/` | all sites using a given nameserver | yes |
| IP Location Finder | `/iplocation/` | geographic location of an IP | yes |
| Chinese Firewall Test | `/chinesefirewall/` | accessible from China? | yes |
| DNS Propagation Checker | `/propagation/` | have recent DNS changes propagated | yes |
| Is My Site Down | `/ismysitedown/` | down for everyone or just you | **no** |
| Reverse MX Lookup | `/reversemx/` | all sites using a given mail server | yes |
| WHOIS Lookup | `/whois/` | detailed WHOIS for a domain | yes |
| Get HTTP Headers | `/httpheaders/` | HTTP headers returned by a domain | yes |
| DNS Record Lookup | `/dnsrecord/` | all DNS records for a domain | yes |
| Port Scanner | `/portscan/` | common ports open on a server | yes |
| Traceroute | `/traceroute/` | hops from ViewDNS to a remote host | yes |
| Spam Database Lookup | `/spamdblookup/` | is your mail server blacklisted | yes |
| Reverse DNS Lookup | `/reversedns/` | PTR entry for an IP | yes |
| Iran Firewall Test | `/iranfirewall/` | accessible from Iran? | yes |
| Global Ping Test | `/ping/` | ping from multiple locations worldwide | yes |
| **DNSSEC Test** | `/dnssec/` | is the domain configured for DNSSEC | **no** |
| URL Decode | `/urldecode/` | `%##` -> readable | **no** |
| Abuse Lookup | `/abuselookup/` | abuse contact address for a domain | yes |
| MAC Address Lookup | `/maclookup/` | manufacturer of a network device | yes |
| Free Email Test | `/freeemail/` | does a domain provide free email | yes |
| **ASN Lookup** | `/asnlookup/` | details on an ASN | **no** |

**Five web-only tools** (DNS Report, Is My Site Down, DNSSEC Test, URL Decode, ASN Lookup) & **one API-only product** (Newly Registered Domains): 26 - 5 + 1 = the 22 APIs listed in every page footer. The DNS Report result page states it outright: *"This tool is not currently available via the ViewDNS.info API."* Their single most differentiated tool is the one you cannot automate. Deliberate lead-gen, not oversight.

**DNS Report check catalogue.** The reason to study this page. Capture **2025-09-17** (`?domain=www.wotter.be`) renders **41 named checks** in a `Status | Test Case | Information` table across 5 sections, closed by a `Test Summary` block:

| Section | Checks |
|---|---|
| **Parent Nameserver** (5) | NS records listed at parent (+ names the parent server that answered, "This information was kindly provided by `z.nsset.be`"), domain listed at parent, NS records listed at parent, parent servers return glue, A record for each NS at parent |
| **Local Nameserver** (15) | NS records at your local servers, glue at local NS, same glue local-vs-parent, same NS records at each local NS, all NS respond, all NS names valid, number of nameservers, NS answer authoritatively, missing NS at parent, missing NS at child, no CNAME for domain, no CNAME for nameservers, NS on different `/24` subnets, NS have public IPs, **NS allow TCP on port 53** |
| **SOA** (8) | SOA dump (MNAME, hostmaster, serial, refresh, retry, expire, minimum TTL), all NS agree on serial, SOA MNAME listed at parent, serial in `YYYYMMDDnn` format, refresh in 3600-86400, retry in 300-14400, expire in 604800-2419200, minimum TTL < 259200 |
| **MX** (10) | MX dump w/ priority + TTL, all NS agree on MX, MX hostnames valid, MX IPs public, MX not a CNAME, MX A records not CNAMEs, >1 MX record, no duplicate MX A records, MX A vs authoritative mismatch, **MX IPs have PTR records** (prints the `in-addr.arpa` pairs) |
| **WWW** (3) | `www` A records, `www` A public IP, `www` CNAME resolves to A in one answer |

Two separate vocabularies, worth copying exactly: the **Status column carries `INFO` / `OK` / `WARNING` / `FAIL`** (machine-sortable, 4 values), while the Information cell opens w/ a conversational verdict word, `Good!` / `OK.` / `Oops!`, then the prose. Several checks cite an RFC inline (`RFC1912 section 2.4`, `RFC2181 section 10.3`). Their nameserver-count text cites *"RFC218 section 2.5"*, a mangling of **RFC 2182 §5 "How many secondaries?"**, which does recommend three (verified against the RFC text). Output toggles **HTML | JSON**, w/ `Sign in to enable copy` / `Sign in to enable export`.

**Paid API products (22).** All `GET https://api.viewdns.info/<path>/`, all take `apikey` (required) & `output` (`json` default, or `xml`). Params read off their own doc pages, captures **2025-12-10 to 2026-09-14**:

| Endpoint | Required param | Extra | Paging |
|---|---|---|---|
| `/dnsrecord/` | `domain` | `recordtype` (default `ANY`) | no |
| `/propagation/` | `domain` | | no |
| `/reversedns/` | `ip` | returns single `rdns` string | no |
| `/reverseip/` | `host` | `domain_count` + `last_resolved` per row | `page`, 10,000/page |
| `/reversens/` | `ns` | | `page`, 10,000/page |
| `/reversemx/` | `mx` | | `page`, 10,000/page |
| `/reversewhois/` | `q` (email, name, org, domain) | | `page`, 1,000/page |
| `/subdomains/` | `domain` | | `page`, 1,000/page |
| `/iphistory/` | `domain` | | no |
| `/whois/v2` | `domain` | **versioned path** | no |
| `/abuselookup/` | `domain` (accepts IP too) | | no |
| `/spamdblookup/` | `ip` | "Checks over **30** Spam blacklists" | no |
| `/freeemail/` | `domain` | free/disposable-email classifier | no |
| `/httpheaders/` | `domain` | "consistently parsed" headers + `http_status` | no |
| `/iplocation/` | `ip` | city, zipcode, region code+name, country code+name, lat/long, GMT & DST offset | no |
| `/maclookup/` | `mac` | OUI database | no |
| `/portscan/` | `host` | common ports, `open`/`closed` per port w/ service name | no |
| `/traceroute/` | `domain` | from ViewDNS server, single origin | no |
| `/ping/v2/` | `host` | **versioned path**; grouped by region, min/max/avg RTT + packet-loss % per location | no |
| `/chinesefirewall/` | **`domain`** | per-location `resultstatus`, mainland China vantage points | no |
| `/iranfirewall/` | **`siteurl`** | | no |
| `/nrd/` | `date` (`YYYY-MM-DD`) | `type` = `domains` \| `enriched`, returns a `.gz` download | n/a |

Plus two docs entries that are not tools: **Account API** (`/api/account/`) & **Error Messages** (`/api/documentation/errors/`). Both are ordinary click-through pages in the docs index, not JS accordions, but neither URL has ever been archived, so their content is unknown. Note the param-naming drift: `domain`, `host`, `ip`, `ns`, `mx`, `q`, `mac`, `siteurl` all mean "the thing you are looking up", and the two firewall tests disagree w/ each other. Any Go client needs a per-endpoint param map, not one generic caller.

**Agent surface.** **MCP gateway** at `https://api.viewdns.info/mcp`, `Authorization: Bearer <apikey>`, documented w/ a copy-paste `claude mcp add --transport http viewdns ...` line & OpenAI Playground steps. No tool list is published. **Integrations** (a page the free-tool grid never links to): **SpiderFoot** OSINT module, **Make.com** modules, **Metasploit** modules. **Data feeds:** ccTLD zone files & a daily NRD snapshot across "over a thousand supported TLDs".

## Record types & query options supported

Thinner than the marketing, but not as thin as the parameter list suggests. The free DNS Record Lookup form (captures 2026-08-14 & 2026-09-08) is a **single `<input name="domain">` plus a submit button**: no `<select>`, no record-type control in the rendered HTML, and no JS that would inject one. `recordtype` exists **only on the API**, defaults to `ANY`. Careful here: the docs give `A,AAAA,MX,TXT,ANY` as an **"e.g. … etc." example list**, not an enumeration, and the page headline claims "retrieval of **any** record type for any Domain or Hostname". Whether `CAA`, `SRV`, `SVCB`, `DS` etc. actually work is **untested**, we have no key. Record objects carry `name`, `ttl`, `class`, `type`, `data`, plus `priority` on MX (JSON and HTML alike), so **TTL is raw seconds**, never humanized.

Absent across the whole product: choose-your-resolver, query a named authoritative NS, delegation trace, TCP vs UDP toggle, EDNS/ECS subnet, `+dnssec` / AD-flag, raw `dig`-style output, IDN/punycode handling, or a bulk/multi-domain mode. The propagation tool is A-record only (`expectedresponse` is a flat IP list).

## How it works

**Entirely server-side.** The free HTML tool & the paid API are the same engine: the `/dnsrecord/` result page embeds a JSON tab whose payload reads `"tool": "dnsrecord_PRO"`, & every API sample response carries the same `_PRO` suffix (`reverseip_PRO`, `propagation_PRO`, `iphistory_PRO`, `abusecontact_PRO`, `ping_PRO_v2`). The web page is a renderer over the API response. One backend, two skins, two price points.

**Propagation, the one genuinely good mechanic.** The result page prints *"Expected value (discovered direct from the root servers):"* and then a `Location | Lookup Result | Status` row per vantage point, each `resultstatus: "ok"` or not. So they do **not** poll N resolvers & show a wall of IPs to eyeball, they first resolve the **authoritative truth by walking down from the root**, then diff every vantage point against it & reduce each to a boolean. Same 17 locations in the 2024 free page & the 2026 API sample, unchanged in two years: Atlanta, Beauharnois, Hong Kong, Johannesburg, London, Los Angeles, Mumbai, New York, Perth, Rotterdam, Sandefjord, Santiago, Seattle, Seoul, Singapore, Sydney, São Paulo. Docs claim "more than a dozen". (The result-page layout we read is the pre-redesign 2024 site; the current one was not observable.) Reproduced the mechanic firsthand w/ `dig` against `corpberry.com` and immediately hit its failure mode: authoritative `lisa.ns.cloudflare.com` returns `104.21.25.133 / 172.67.134.67`, `1.1.1.1` agrees, but `8.8.8.8` returns `188.114.96.3 / 188.114.97.3` & `9.9.9.9` returns `188.114.96.4 / 188.114.97.4`. Cloudflare is geo-steering per resolver, so a naive expected-vs-actual diff reports two thirds of the planet as "not propagated". Any propagation feature we build has to special-case anycast CDNs or it will lie confidently.

**Reverse IP / NS / MX / subdomains are cached, not live.** The `/reverseip/` sample response returns `domain_count` plus a `last_resolved` date per domain (values from 2024 in a page captured in 2026). Passive-DNS style corpus, so results are stale by construction and must be labeled as such. `/iphistory/` returns `ip`, `location`, `owner`, `lastseen` rows from the same corpus. Actual refresh cadence is undisclosed; the `last_resolved` fields are the only freshness signal. By contrast `/dnsrecord/` and `/propagation/` are marketed as "Live Data … real-time", consistent w/ their per-request cost.

**DNSSEC Test looks like a presence check, not a validator.** A 2019 capture shows it printing one row per RRSIG (`Record Type | Algorithm | Signed By | Signature` w/ the raw base64), headed "This domain DOES have DNSSEC enabled." No DS-at-parent check, no chain-of-trust validation, no expiry or algorithm-rollover warning. **Caveat, unresolved:** the newest capture (2026-08-28) is the empty form page only, so no current result page was ever seen. The homepage blurb ("Test if any domain name is configured for DNSSEC") is unchanged since 2019, which is weak evidence the behaviour is too.

## Output & UX

Green-accent Tailwind, **dark-mode toggle gated behind login**. Per-tool result pages, **result URL is a plain GET query string** (`/dnsreport/?domain=…`), so results are shareable & crawlable. Every result page renders an **`HTML | JSON` tab pair**, plus copy & export icons that are inert until you log in.

The conversion mechanic is the thing worth writing down. On `/dnsrecord/`, the JSON tab shows the **first record fully & correctly**, then renders every subsequent row as placeholder glyphs:

```
{ "name": "zerocostbacklinks.blogspot.com.", "ttl": "297", "class": "IN", "type": "CNAME", "data": "blogspot.l.googleusercontent.com." },
{ "name": "xxxxxx.xxx.", "ttl": "xx", "class": "xx", "type": "x", "data": "xx.xxx.xxx.xx" },
```

followed by "Sign up or Login for instant API access". You are shown the exact response *shape* you would integrate against, far more persuasive than a pricing link. **But check the arithmetic before copying it:** in that capture the JSON tab shows 1 real + 3 redacted rows, while the HTML tab shows 1 row total, and `dig ANY/A/TXT @8.8.8.8` against that name (firsthand, 2026-09-16) returns **only the CNAME**, which by RFC 1912 §2.4 excludes other records at the same owner. So the 3 placeholder rows almost certainly are **fixed padding, not withheld real data**. Steal the shape-teaser idea, not the fake rows. DNS Report error states are conversational & prescriptive (*"Oops! Your local nameservers don't return IP addresses (glue) ... You can fix this by adding A records for each of the nameservers listed above."*). Every footer echoes **"Your IP address is: …"**, which is why every capture leaks the Wayback crawler's IP.

## Monetization, limits & abuse controls

No per-tool quota is documented on the free web tools, and we did not test one. The **API Terms of Service** has a "Usage Limits" clause but **publishes no number**: limits "may" apply, may be imposed or changed at any time, "contact ViewDNS.info with any inquiries". The same ToS bars you from selling, sublicensing, redistributing or **syndicating access to the APIs**, which rules out fronting their data from a public corpberry tool, and disclaims accuracy and availability outright. Paid access is metered purely by **query count**, one pool, monthly or prepaid.

Abuse control is blunt & total: **Cloudflare challenge on 100% of the `viewdns.info` origin**, verified firsthand on `/`, `/robots.txt`, `/portscan/?host=…` & `/.well-known/security.txt`, all 403 (`www.` 301s into the same wall). The API host is deliberately exempt, key-metered instead. Note how badly the crawlable-GET-result-URL decision has aged: a CDX query on 2026-09-15 showed the Wayback index for `/portscan/?host=…` saturated w/ injected casino-spam strings in the `host` param (CDX was down on 2026-09-16, so that one is unreconfirmed). Public GET result URLs on a high-authority domain become an SEO-spam target.

## Ideas worth stealing

- **Diff against authoritative truth, not against each other.** Resolve the answer from the delegation chain once, then render every resolver row as `ok` / `mismatch` against it. In Go that is one authoritative query + N concurrent resolver queries + a set compare, & it turns a wall of IPs into a single verdict. Add the anycast escape hatch my `dig` run exposed: if the authoritative NS is a known CDN, compare **ASN/owner** rather than exact IP set.
- **Two-vocabulary check rows.** `INFO` / `OK` / `WARNING` / `FAIL` in a narrow Status column for scanning & sorting, plain-English verdict + fix instructions in the wide cell, RFC cited inline. Renders as a plain HTML table, zero JS, & htmx can stream sections in as each check group finishes.
- **Split "does the parent agree with the child".** Parent-vs-local is their strongest section & the thing plain `dig` users never check: glue present at parent, same glue at both, NS sets identical both ways, SOA MNAME listed at parent.
- **Name the server that answered.** "This information was kindly provided by `z.nsset.be`" is a one-line credibility multiplier. Print which parent/TLD server & which authoritative NS produced each fact.
- **Cheap checks nobody else surfaces,** all a few `net`/`miekg-dns` calls, all actionable: NS on different `/24`s, NS reachable over **TCP/53**, MX IPs have PTR records, duplicate MX A records.
- **JSON tab next to every HTML result.** We have no paywall, so show the *whole* payload plus the `curl` line that returns it. Our content-negotiation architecture (CLAUDE.md rule #2) already produces both representations from one domain call, so this costs one template.
- **Tool grid w/ a verb per card.** Each homepage card is `Name / one-line description / verb button` ("Lookup", "Generate Report", "Discover Subdomains"). Better than a list of links for a tools index.
- **Anti-patterns to avoid:** do not let arbitrary user input into a crawlable GET result URL without `noindex` on result pages (their portscan URLs are a spam dump); and do not emit placeholder rows that imply data you do not have.

## Gaps & what it does not do

No resolver/NS selection, no delegation trace, no DNSSEC **validation**, no record-type control anywhere in the free UI, no humanized TTL, no SPF/DKIM/DMARC/MTA-STS/BIMI parsing (only a generic spam-blacklist check), no monitoring or change alerts, no bulk lookup, no webhooks, no OpenAPI spec, no published rate-limit number, no SLA or status page, no stated data sources, no named humans. The DNS Report, DNSSEC Test & ASN Lookup are unautomatable by design. The free tier is 250 queries with no stated renewal, so it cannot back a hobby integration, and the ToS forbids redistributing API output anyway.

## Verified firsthand vs inferred

**Verified firsthand (2026-09-15/16, curl/dig/RDAP from this machine):** whole-origin Cloudflare challenge incl. `robots.txt` & `.well-known/security.txt`, `cf-mitigated: challenge`; `api.viewdns.info` reachable & unchallenged; every key rejected w/ `{"success":false,"error":{"code":401,"message":"Invalid API key."}}`, **including the `apikey=demo` value printed in their own "Live Demo!" blocks**, and a request w/ no `apikey` at all returns the same 401; **`output=xml` is ignored on error paths**, errors are always JSON; unknown endpoints return an Apache default HTML 404 (`text/html; charset=iso-8859-1`), not JSON; **no `Access-Control-Allow-Origin` header on any response we could see** (all of which were 401s) and an `OPTIONS` preflight returns **200 w/ an empty-valued JSON envelope and still no CORS headers**, so browser-side `fetch` is blocked either way & a server-side proxy is mandatory; **MCP `initialize` succeeds unauthenticated** (`"ViewDNS MCP Gateway"` v1.0, protocol `2025-06-18`, `capabilities.tools.listChanged`) while `tools/list` returns `-32604 Missing or invalid Bearer token`, so the agent-facing tool list is still unenumerated; RDAP registration/expiry/NS/locks; the `dig` propagation reproduction & Cloudflare geo-steering false-mismatch; the `dig` check showing the teaser domain has only a CNAME; RFC 2182 §5 text; `electrologue/viewdns` latest version & date via the Go module proxy.

**Read from Wayback captures of their own pages, not observed live:** the 26-tool list & descriptions (2026-09-08), pricing (2026-06-05), every API parameter list & sample response (2025-12-10 to 2026-09-14), DNS Report check catalogue & wording (2025-09-17), the redacted-JSON teaser (2026-09-08), the record-lookup form markup (2026-08-14), propagation locations (2024-09-16 + 2026-08-19), MCP setup page (2026-09-08), integrations page (2026-08-18), API ToS (2026-09-09), DNSSEC output format (**2019-09-19, six years stale**), about/research/data pages (Aug-Sep 2026).

**Still unproven:** whether free web tools carry any quota (no documentation, not tested; the ToS usage-limits clause covers the API only and names no number); whether current DNSSEC output still matches the 2019 capture (2026 captures show the empty form only); "over 30 spam blacklists" & the reverse-IP corpus size, both vendor copy w/ no published list; the corpus refresh cadence beyond `last_resolved`; whether `recordtype` accepts types outside the docs' `A,AAAA,MX,TXT,ANY` example; the Account API & Error Messages content (paths known, pages never archived); the portscan SEO-spam observation (CDX unavailable on re-check).

## Open source / reusable

Nothing from the vendor: no public repo, no OpenAPI spec, no official client. Reference implementations that do exist, all thin REST shims: **`github.com/electrologue/viewdns`** (Go, MIT, latest **v0.1.1 dated 2023-02-09**, so it predates `/whois/v2`, `/ping/v2/`, `/subdomains/` & `/nrd/` and still wraps a dead Google PageRank endpoint), SpiderFoot's **`modules/sfp_viewdns.py`** (builds `https://api.viewdns.info/{querytype}/?{params}` w/ an `apikey`, the clearest short worked example of the call shape), Metasploit modules, and RapidAPI/Pipedream/Make.com connectors. None is worth a dependency: the whole client is `http.Get` + `encoding/json`. The **ideas** are the reusable asset, not the code.

## Sources

- **Site pages (Wayback):** [homepage / 26-tool inventory, 2026-09-08](https://web.archive.org/web/20260908101152/https://viewdns.info/) · [about-us, 2026-09-10](https://web.archive.org/web/20260910114509/https://viewdns.info/about-us/) · [research, 2026-08-18](https://web.archive.org/web/20260818080855/https://viewdns.info/research/) · [data / "over a thousand supported TLDs", 2026-08-21](https://web.archive.org/web/20260821230457/https://viewdns.info/data/) · [integrations / SpiderFoot, Make.com, Metasploit, 2026-08-18](https://web.archive.org/web/20260818190137/https://viewdns.info/api/integrations/)
- **Commercial terms (Wayback):** [API pricing plans, 2026-06-05](https://web.archive.org/web/20260605142658/https://viewdns.info/api/pricing/) · [API Terms of Service, usage-limits & no-redistribution clauses, 2026-09-09](https://web.archive.org/web/20260909220358/https://viewdns.info/api/terms/)
- **API docs, params & sample responses (Wayback):** [documentation index incl. Account API & Error Messages targets, 2026-06-05](https://web.archive.org/web/20260605142707/https://viewdns.info/api/documentation/) · [dns-record-lookup / `recordtype` "e.g." list, 2026-01-09](https://web.archive.org/web/20260109084221/https://viewdns.info/api/dns-record-lookup/) · [dns-propagation-checker, 2026-08-19](https://web.archive.org/web/20260819030355/https://viewdns.info/api/dns-propagation-checker/) · [reverse-ip-lookup / paging, `domain_count`, `last_resolved`, 2026-09-14](https://web.archive.org/web/20260914180550/https://viewdns.info/api/reverse-ip-lookup/) · [ping / `/ping/v2/` regional grouping, 2026-09-03](https://web.archive.org/web/20260903120311/https://viewdns.info/api/ping/) · [iran-firewall-test / the `siteurl` outlier, 2026-09-11](https://web.archive.org/web/20260911020354/https://viewdns.info/api/iran-firewall-test/) · [newly-registered-domains / `date`+`type`, `.gz` response, 2026-09-09](https://web.archive.org/web/20260909220358/https://viewdns.info/api/newly-registered-domains/) · [MCP Server setup, endpoint & Bearer auth, 2026-09-08](https://web.archive.org/web/20260908170949/https://viewdns.info/api/mcp-server/)
- **Rendered tool pages (Wayback):** [DNS Report result, full check catalogue & status vocabulary, 2025-09-17](https://web.archive.org/web/20250917103655/https://viewdns.info/dnsreport/?domain=www.wotter.be) · [DNS Record Lookup form, no record-type select, 2026-08-14](https://web.archive.org/web/20260814142710/https://viewdns.info/dnsrecord/) · [DNS Record Lookup result, HTML/JSON tabs & redacted-JSON teaser, 2026-09-08](https://web.archive.org/web/20260908133015/https://viewdns.info/dnsrecord/?domain=zerocostbacklinks.blogspot.com) · [propagation result, "direct from the root servers", 2024-09-16](https://web.archive.org/web/20240916010615/https://viewdns.info/propagation/?domain=www.reliable-solutionsllc.com) · [DNSSEC Test, current form only, 2026-08-28](https://web.archive.org/web/20260828172319/https://viewdns.info/dnssec/) · [DNSSEC Test result, RRSIG dump format, 2019-09-19](https://web.archive.org/web/20190919205758/https://viewdns.info/dnssec/?domain=www.xironics.nl)
- **Standards:** [RFC 2182 §5 "How many secondaries?", the rule their report miscites as "RFC218 section 2.5"](https://www.rfc-editor.org/rfc/rfc2182) · [RFC 1912 §2.4, CNAME rules cited inline by DNS Report](https://www.rfc-editor.org/rfc/rfc1912)
- **Third-party clients:** [`github.com/electrologue/viewdns`, Go, MIT, v0.1.1](https://pkg.go.dev/github.com/electrologue/viewdns) · [SpiderFoot `modules/sfp_viewdns.py`](https://raw.githubusercontent.com/smicallef/spiderfoot/master/modules/sfp_viewdns.py)
