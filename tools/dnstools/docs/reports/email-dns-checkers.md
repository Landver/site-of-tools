# Email DNS checkers (dmarcian · EasyDMARC · LearnDMARC · Postmark/DMARC Digests · Mailhardener)

Five services that treat DNS not as "print the RRset" but as **email-auth policy evaluation**: fetch `TXT`/`MX`/`CNAME`, parse the record grammar (SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT, DANE), then judge it against RFC. Four are SaaS lead-gen front doors for paid DMARC-report platforms; one (LearnDMARC) is pure teaching. For a DNS-lookup tool this is the highest-value adjacent territory: it's where a plain `dig` wrapper stops being a `dig` wrapper, and it's mostly **parsing + explaining**, which is cheap in Go & needs zero third-party data feed.

- **URLs:** [dmarcian.com/dmarc-tools](https://dmarcian.com/dmarc-tools/) · [easydmarc.com/tools](https://easydmarc.com/tools) · [learndmarc.com](https://www.learndmarc.com/) · [dmarc.postmarkapp.com](https://dmarc.postmarkapp.com/) · [mailhardener.com/tools](https://www.mailhardener.com/tools/)
- **Category:** server-side record validators + record builders + (LearnDMARC) live SMTP teaching console · **Registration:** none for any lookup tool; account only for report platforms & EasyDMARC's EasySPF · **Pricing:** tools free; platforms €0–$600/mo (below, checked **2026-09-15/16**) · **API:** Mailhardener & Postmark yes, dmarcian no, EasyDMARC only at Enterprise.
- **Firsthand check (2026-09-15, re-verified 2026-09-16):** `curl`'d all five roots. Ran `dig` for SPF/`_dmarc`/`_mta-sts`/`_smtp._tls`/`default._bimi`/TLSA on vendor & test domains. Pulled EasyDMARC's undocumented fragment endpoint `/tools/<tool>/content?domain=…` + `embedjs`. Called **Mailhardener's unauthenticated JSON API** `api.mailhardener.com/v1/inspect/{spf,dmarc,dkim,mx,mtasts,tlsrpt,bimi,dane}` & dumped the response schemas (**incl. dkim**, resolved this pass). Read dmarcian's `api.js` + `tools.js`, enumerated its AJAX actions, and **confirmed the nonce gate by POSTing one without a nonce** (`HTTP 403`, body `-1`). Hit LearnDMARC `/getAddress` (got a real one-time address) & `/quiz` (got the whole question bank). Read RFC 9989/9990/9991 off rfc-editor. Postmark's API is from **their own docs, never called** (calling `POST /records` creates a record).

## What it is

| Service | Runs it | Role of the free tools |
|---|---|---|
| **dmarcian** | dmarcian (US, founded by Tim Draegen, a DMARC spec co-author) | 9 free tools on one index, WordPress + Vue front end on an internal API; funnels to the DMARC platform |
| **EasyDMARC** | EasyDMARC Inc (US/Armenia) | Widest catalogue of the five (**38 tool pages** in `/tools/sitemap.xml`); aggressive SEO + email-capture funnel |
| **LearnDMARC** | Leeman Kuiper, **sponsored by URIports** (MX → `uriports.com`, `_dmarc` rua → `dmarc@leemankuiper.uriports.com` — dug firsthand) | Not a checker. A **live SMTP theatre**: you send it mail, it animates the receiving server's SPF/DKIM/DMARC decision |
| **Postmark DMARC / DMARC Digests** | ActiveCampaign's Postmark team; the product has moved to `dmarcdigests.com` | Not a lookup tool at all: a **DMARC aggregate-report mailbox + digest**. Included because its free tier & public REST API are the reference design for "report ingestion" |
| **Mailhardener** | Mailhardener (NL) | Deepest technical validators of the five, incl. DANE/TLSA & MTA-STS policy fetch; free tier is a real product |

## Registration, access & pricing

No lookup tool on any of the five asks for an account. dmarcian states it plainly on `/dmarc-tools/`: "Use any of them for free, no registration required!" and "Any information you provide is used only to run the tool itself, never shared, and never used for marketing purposes" (quotes confirmed present; the truth of the retention promise is unverifiable from outside). The one exception is EasyDMARC's **EasySPF**, which is a managed service and does require registration. Paid platform tiers (checked **2026-09-15/16** via vendor pricing pages; **not transacted**):

| | Free | Next tier | Top published |
|---|---|---|---|
| **dmarcian** | Personal $0 — 2 domains, 1 user, **1,250** DMARC-capable msgs/mo, 1 mo history, non-business only | Basic $24/mo ($19.99 annual) — 2 domains, 100k msgs | Enterprise $600/mo ($499 annual) — 15 domains, 5M msgs, unlimited history (+ Custom on request) |
| **EasyDMARC** | €0 — 1 domain, **1,000** emails/mo, 14 days history | Plus €44.99/mo (€35.99 annual) — 2 domains, 3 mo | Premium €89.99/mo (€71.99 annual) — 4 domains, 1 yr. **API is *not* here: it's Enterprise-only** (custom price, unlimited domains, 3 yr) |
| **Mailhardener** | €0 — **1 domain, 1 month retention**, personal/evaluation use only | Standard €19/mo (€199/yr) — ≤10 domains, 3 mo, MTA-STS + BIMI hosting | Large €99/mo (€999/yr) — 100 domains, 1 yr (+ Enterprise on quote: unlimited domains, no retention cap) |
| **Postmark / DMARC Digests** | $0 — weekly email only, **top 10 sources × 5 IPs**, 7-day history, **no dashboard** | $14/mo per domain — all sources, 60-day history, dashboard, weekly + monthly, 14-day trial | — |
| **LearnDMARC** | free, unlimited, no account | — | — |

Postmark's free tier is the sharpest freemium cut here: the *data* is free, the *aggregation depth* (top-10 truncation) and the *UI* are what you pay for.

## Features — complete inventory

### Record lookup & validation

| Capability | dmarcian | EasyDMARC | Mailhardener | LearnDMARC |
|---|---|---|---|---|
| DMARC record lookup + tag-by-tag parse | DMARC Inspector | `/tools/dmarc-lookup` | `/tools/dmarc-validator` | in-flow |
| SPF record lookup + recursive expansion | SPF Surveyor | `/tools/spf-lookup` | `/tools/spf-validator` | in-flow |
| DKIM lookup by selector | DKIM Inspector | `/tools/dkim-lookup` | `/tools/dkim-validator` | in-flow (reads selector off the signature) |
| DKIM validation of a **pasted key** (pre-publish, no DNS) | DKIM Validator | — | — | — |
| SPF validation of a **pasted record** | — | `/tools/spf-record-raw-check-validate` | — | — |
| BIMI record lookup + logo/VMC verification | BIMI Tooling (`/bimi-lookup`) | `/tools/bimi-lookup` | `/tools/bimi-validator` | — |
| MTA-STS record **and** policy-file check | — | `/tools/mta-sts-check` | `/tools/mta-sts-validator` | — |
| TLS-RPT record check | — | `/tools/tls-rpt-check` | `/tools/tlsrpt-validator` | — |
| DANE / TLSA check for inbound SMTP | — | — | `/tools/dane-validator` | — |
| MX inspection (priority, null-MX/RFC 7505, hostname validity) | — | `/tools/mx-lookup` | `/tools/mx-inspector` | — |
| Generic RR lookup | — | exactly **8** `/tools/*-lookup` pages (a, aaaa, cname, mx, ns, ptr, soa, txt) + `/tools/dns-record-checker` | — | — |
| One-shot "all three at once" domain audit | Domain Checker (batched) | `/tools/domain-scanner` | dashboard | — |

### Record builders / wizards

dmarcian **DMARC Record Wizard** (step-by-step, emits the TXT) · dmarcian **BIMI builder + SVG validator** (file upload) · EasyDMARC generators for DMARC, SPF, DKIM, BIMI, MTA-STS, TLS-RPT · EasyDMARC **BIMI SVG logo converter** (raster/SVG → SVG Tiny-PS) · EasyDMARC **EasySPF**, a managed **SPF flattening** service that swaps `include:`s for literal IPs to duck the 10-lookup ceiling (account required; the commercial answer to the counter below) · Mailhardener DKIM & DMARC generators · Mailhardener **DNS record splitter** (chops a >255-octet TXT into quoted 255-char strings — the single most useful "boring" utility in the whole set). dmarcian has **no** SPF record builder: `/create-spf-record/` is a how-to article ("How to Create and Add an SPF Record"), not a tool.

### Report ingestion, parsing & monitoring

dmarcian **XML-to-human Converter** (`/xml-to-human-converter/`, paste/upload a DMARC aggregate XML, get prose) · dmarcian **Data Providers** (who sent DMARC XML in the past week) · dmarcian **DMARC Detail Viewer** (live page, but not listed on the free-tools index) · EasyDMARC **DMARC Report Analyzer**, **Failure reports**, **Report GeoMaps** · EasyDMARC **Email Header Analyzer**, **Alert Manager**, **Reputation Monitoring**, **Email Deliverability Test**, **IP/Domain Reputation Checker**, **Phishing URL checker** · Postmark **weekly/monthly digest email** + dashboard · Mailhardener DMARC + **SMTP TLS aggregation**, **DNS monitoring** (alerts on record change), MTA-STS & BIMI **asset hosting**.

### Teaching surface (LearnDMARC, unique)

Live email test (`/getAddress` hands out a one-time `ld-<10 hex>@learndmarc.com`, firsthand: `ld-f3896b2980@learndmarc.com`) · **animated SMTP-conversation replay** w/ `Restart` & `Fast Forward >>` · panels for Connection parameters (source IP, hostname, sender, recipient), SPF (domain, identity, auth result, **DMARC alignment**), DKIM (domain, selector, algorithm, auth result, alignment, *"Show other DKIM signatures"*), DMARC (RFC5322.From domain, `p=`, SPF, DKIM, result, **final verdict**) · **paste-your-headers** mode (`/processHeaders`) giving the same visualization w/o sending mail · a quiz of **10 items, 7 of them questions** w/ per-answer explanations, already rewritten for **DMARCbis** (it asks about the DNS Tree Walk and `psd=y|n`) · **Anonymize results** toggle before sharing · Share / Copy / Print · explicit "view on desktop for the full visual" gate.

### APIs

**Mailhardener — public, unauthenticated, undocumented-on-the-tools-page.** `GET https://api.mailhardener.com/v1/inspect/{spf|dmarc|dkim|bimi|mtasts|tlsrpt|dane|mx}?domain=<d>`. There is **no `selector=` parameter**: for DKIM you pass the full DNS address (`domain=google._domainkey.paypal.com`) and the API splits it back into `selector` + `domain` in the response; a bare `domain=<d>` returns `error: 10`, "A DKIM record must be placed at address [selector]._domainkey.[domain]". BIMI takes a bare domain and defaults to `default._bimi.<d>`; a `selector=` query param is silently ignored. Returns `{"result":"success","data":{…}}`. **CORS is pinned to `https://www.mailhardener.com`** (it returned that value even under `Origin: https://example.com`, w/ `allow-credentials: true`), so a browser can't call it cross-origin, but any server can. No key, no rate-limit header observed — ~20 calls, ceiling not probed.

**Postmark DMARC** — public REST, `X-Api-Token` on the authenticated half: `POST /records` (no auth, body `email` + `domain`), `GET|PATCH|DELETE /records/my`, `GET /records/my/dns`, `POST /records/my/verify`, `GET /records/my/reports` (`from_date`, `to_date`, `limit` default 30 max 50, `after`, `before`, `reverse`), `GET /records/my/reports/:id` (content-negotiates **JSON or the original DMARC XML** via `Accept`), `POST /tokens/recover`, `POST /records/my/token/rotate`. Docs mention no rate limit. **Read from docs, never called** — `POST /records` has a side effect.

**dmarcian** — no public API. WordPress `admin-ajax.php`, WP-nonce on every request (**confirmed**: bare POST → `HTTP 403`, body `-1`), **10** actions: `dm_integration_inspect_{dmarc,spf,dkim,bimi}`, `_validate_dkim`, `_validate_bimi_svg`, `_create_dmarc`, `_build_bimi`, `_batch_inspect`, `_save_roi_calculator_submission`. Response shapes unknown.

**EasyDMARC** — no public API below Enterprise, but every tool result is an **HTML fragment** at `GET /tools/<tool>/content?domain=<d>&is_embed=false`, served `Access-Control-Allow-Origin: *`. Confirmed 200 for `dmarc-lookup`, `spf-lookup`, `dns-record-checker`, `mx-lookup`, `ip-domain-reputation-check`; `dkim-lookup`/`bimi-lookup`/`mta-sts-check`/`tls-rpt-check` 404 on a `?domain=` guess (different param shape, not proof they're absent). Cloudflare **UA-gates** the fragment: a default `curl` UA gets `403` on every path, a browser UA gets the real answer. Plus `/tools/embedjs` — a 3,132-byte loader that reads `data-*` off `document.currentScript`, injects an `<iframe>`, and resizes it from an `addEventListener('message')` handler carrying a height.

## Record types & query options supported

RR types touched: **TXT** (SPF/DMARC/BIMI/MTA-STS/TLS-RPT), **MX**, **CNAME** (all of them resolve & report the CNAME chain: EasyDMARC's own `_dmarc` is a CNAME to `easydmarc.pro`, and both tools surfaced that), **A/AAAA** (MX host validation, MTA-STS policy host), **TLSA** (Mailhardener only), **NS/SOA/PTR** (EasyDMARC's generic lookups). Nobody offers SRV, CAA-as-a-lookup, NAPTR, or DS/DNSKEY browsing.

**Protocol currency matters more than it looks.** DMARC was re-issued in **May 2026** as **RFC 9989** (core, obsoletes 7489 *and* 9091), **RFC 9990** (aggregate reporting) and **RFC 9991** (failure reporting) — all three read firsthand off rfc-editor. The change that bites a parser: the Organizational Domain is now found by a **DNS Tree Walk** up the name, not by a Public Suffix List lookup, and `psd=y|n` marks a public-suffix operator and stops the walk. Anything built to RFC 7489 semantics ships obsolete. Of the five, only LearnDMARC's quiz visibly reflects this; the others' copy still reads RFC 7489-shaped, though their parsers were not inspected.

Query knobs are **deliberately absent**. None of the five lets you pick a resolver, choose an authoritative NS, force TCP, set EDNS/ECS, or see the raw wire response. The one exception is Mailhardener, which doesn't let you *choose* but does **report** what it used: every response object carries `used_ns` (e.g. `ns-1707.awsdns-21.co.uk.`) and `record_ttl`, and the DANE response carries `has_dnssec`. That's the whole trade. These tools give up dig's knobs and spend the space on interpretation.

## How it works

All server-side. Mailhardener's page JS is a thin client that `fetch`es its own `api.mailhardener.com`; dmarcian's is Vue posting to WordPress; EasyDMARC renders the answer server-side and ships HTML. Mailhardener names an authoritative NS per record and different records in one answer report different `used_ns`, which is **consistent with** resolving from authoritative rather than from a recursive cache, and would explain the trustworthy `record_ttl` — inferred from the output, not observed on the wire.

Two of the checks leave DNS entirely. Mailhardener's **MTA-STS validator** does the full RFC 8461 dance: resolve `_mta-sts.<d>` TXT, then `GET https://mta-sts.<d>/.well-known/mta-sts.txt`, and report `policy_http_code`, `policy_uri`, `policy_headers` (the actual response headers), `policy_body`, the parsed `policy` object, `tls_result` + `tls_result_desc` + `tls_certificate_expiry` ("expires in 46 days and 23 hours"), `server` (the CNAME→A→AAAA chain of the policy host), `max_age_desc` ("1 day"), `mode_desc` (a paragraph of English), per-MX `in_policy`/`is_rfc7505`/`valid_hostname`, and **`line_ending_style`** (`"<CRLF>"` on google.com) — because an MTA-STS policy file is CRLF-delimited and half the internet serves LF. All field names above dumped firsthand. Its **BIMI validator** goes further: fetches the SVG *and* the VMC, parses the X.509 (`subjectAltNames`, `serial`, `notBefore`/`notAfter`, `trusted`, `chain_valid`, `hasCT`, trademark registration), then checks the SVG against the cert's logotype digest (`hasLogotypeExtension`, `logoDigest`, `"logoDigestValid": true`, `hash_method: "sha1"`) and checks the SVG is `profile: "tiny-ps"` — and separately re-inspects DMARC, because BIMI is void unless the policy is quarantine/reject (`dmarc_effective_policy` ships in the BIMI response).

LearnDMARC is the odd one: it runs a real MTA (`MX learndmarc.com → uriports.com`), captures your message, and replays the receiving server's decision as an animation. Its client bundle talks to `/getAddress`, `/getEmailData`, `/processor?email=`, `/processHeaders`, `/quiz`.

## Output & UX

**The SPF tree is the centrepiece of the category.** Both dmarcian's SPF Surveyor and EasyDMARC's "SPF Lookup Tree" render the record as an expandable tree, one node per mechanism, nested includes as children, w/ Expand All / Collapse All. (dmarcian's is Vue-rendered client-side and my `curl` returned only the component shell — `<spf-inspection>`, `<spf-query-count>`, `<spf-record-level>`, `<spf-result>` — so its *layout* is from dmarcian's own copy and secondhand write-ups; the EasyDMARC tree below is firsthand.) On `github.com` EasyDMARC's header reads **`10 LOOKUPS (8 main, 2 nested)`** — and that split is correct: 8 top-level `include:`s, plus `sendgrid.net`'s own `include:ab.sendgrid.net` and `_spf.salesforce.com`'s `exists:%{i}._spf.mta.salesforce.com`. Mailhardener's JSON independently agrees (`queries: 10`, and per-term `queries: 2` on exactly those two includes). github.com is sitting *exactly* on the RFC 7208 §4.6.4 limit of 10. Every `ip4:`/`ip6:` leaf is annotated inline w/ its expanded range (`192.30.252.0/22` → `(192.30.252.0 - 192.30.255.255)`), including full IPv6 expansion.

Mailhardener returns the same tree as **recursive JSON**: each `include` term carries a `nested` object w/ its own `record`, `terms`, `used_ns` and error state, plus a per-term `desc` written as a finished English sentence with the value interpolated (`"Pass senders with an IP address in range from <code>192.30.252.0</code> to <code>192.30.255.255</code>"`). It also totals `ip_addresses: {"ipv4":"911364","ipv6":"29712752120897178112958136320"}` — how many addresses the record actually authorises, as decimal strings, because the IPv6 count overflows a float. The v4 total is **live, not stable**: two calls minutes apart returned `911364` and `932421`, because the Microsoft/Google netblocks underneath change.

Errors are numeric + three-part everywhere in Mailhardener: `error` (code), `error_msg` (what), `error_hint` (what to do, w/ an inline link to its own blog post arguing `~all` over `-all`). dmarcian's client-side `recursiveMessageCount` walker (in `tools.js`) sums a `messages` array wherever it appears in the response tree, so its summary badge is derived, never separately maintained; the per-node message shape itself is nonce-gated and was **not** observed.

Result URLs are shareable: dmarcian's `addParamsToCurrentUrl` (also `tools.js`) rewrites the query string from a params object. EasyDMARC accepts `?domain=` on both the page and the fragment. LearnDMARC has Share, Copy to clipboard, Print, and an **Anonymize results** switch.

Export: Postmark alone offers the raw artifact back (`Accept: application/xml` on a report id). Nobody does CSV or a downloadable zone snippet.

## Monetization, limits & abuse controls

The tools are the funnel; the platform is the product. EasyDMARC's mechanic is the most direct and is visible in the fragment HTML itself: below the parsed record sits **"Get Your Full Domain Health Report / Enter your email to access the analysis"**, work-email-only ("Please enter your work email address"), w/ a human-validation step. Worth copying carefully: the fragment ships the **entire decision table** as static copy (Valid / Invalid / No Record / Warning; None / Quarantine / Reject; "add our RUA tag to start receiving reports") and selects the branch client-side. The upsell is keyed to your record, but it is branch selection, not prose generated from your DNS. dmarcian's equivalent is softer: a ROI-calculator AJAX action and an account CTA. Mailhardener sells hosting of the things its own validators check (MTA-STS policy, BIMI assets, TLS-RPT collection). EasyDMARC sells EasySPF, i.e. the fix for the problem its own SPF counter surfaces. Postmark sells the top-10 truncation away.

Abuse controls are thin and mostly invisible: Cloudflare + UA gating in front of EasyDMARC, WP nonces on dmarcian's AJAX (403 without one), CORS origin-pinning on Mailhardener's API. No rate-limit headers seen and no ceiling probed on any of the five.

## Ideas worth stealing

- **The SPF lookup counter, done properly.** A counter that says `10 / 10, 8 direct, 2 nested` is the single highest-value thing in this report, and it's pure Go: recursively resolve `include:`, `a:`, `mx:`, `ptr:`, `exists:` and the `redirect=` modifier, count **queries not records**, stop at 10, `permerror` past it (RFC 7208 §4.6.4). Track the two sub-limits separately (evaluating `mx` must not query >10 address records; `ptr` the same) and the **void-lookup** budget of 2. Rendering the count as `N/10` w/ the direct-vs-nested split is what makes it actionable — it tells you *whose* include to fix.
- **Parse DMARC to RFC 9989, not 7489.** Implement the **DNS Tree Walk** for the Organizational Domain and honour `psd=`, and you are correct where most of this category's copy is stale. It also deletes the Public Suffix List dependency, which is the single ugliest asset a DMARC parser otherwise has to ship and keep fresh.
- **Per-term `defined` vs `value`.** Mailhardener's DMARC response gives each tag both what's literally in the record and the **effective** value after defaults and inheritance. Two columns, "as written" and "as it will behave", kills the biggest class of DMARC misreading for near-zero code.
- **A templated English sentence per tag, w/ the domain interpolated.** This is a `map[tag]template.Template` in a domain package, exactly the pure-Go-returns-structs layer CLAUDE.md §1 wants, and it serves HTML & JSON identically.
- **Report `used_ns` and `record_ttl` per record.** Cheap, and it converts "trust me" into "here's who told me and how long it's good for". Fits a tool whose whole pitch is transparency.
- **Expand every CIDR inline, and total the address count.** `192.30.252.0/22 → (192.30.252.0 – 192.30.255.255)` next to the mechanism, and an address total at the top. `net/netip` + `math/big` for the v6 count. This repo already has CIDR math in `tools/iptools`. Show the total as *of this moment*, since it moves with the includes.
- **The `~all` vs `-all` opinion, surfaced as a hint not an error.** Three-field errors (`code` / `msg` / `hint`) where the hint can link to your own writeup is a good shape, and this repo already has a blog to link into.
- **The DNS record splitter.** Twenty lines of Go: take a >255-octet TXT value, emit `"chunk1" "chunk2"` properly quoted. Trivially the most-used utility on Mailhardener's list and nobody else bothers.
- **Paste-a-record mode alongside lookup-a-domain.** dmarcian's DKIM Validator and EasyDMARC's raw SPF check validate text you haven't published yet. Same parser, second entry point, no DNS round-trip, and it makes the tool useful *before* you can test it.
- **`?domain=` on both the page and the htmx fragment.** EasyDMARC's `/tools/<tool>/content?domain=…` is literally the Golden-Rule-#2 shape: one domain service, one handler, HTML page for browsers and the same fragment for htmx. Steal the URL layout wholesale.
- **Take the full DNS address, not a domain + selector pair.** Mailhardener's DKIM endpoint accepts `google._domainkey.paypal.com` and splits it itself. One text input instead of two, and it round-trips whatever the user copied out of a header.
- **The embed loader.** ~3 KB of JS: read `data-*` off `document.currentScript`, inject an `<iframe>`, listen for a `message` carrying height, resize. That's a distribution channel a hobby tool can actually ship, and it costs one extra route.
- **A "final verdict" line.** LearnDMARC ends w/ one sentence of plain outcome after all the panels. Every other tool buries the answer in the detail.
- **Cross-protocol dependency checks.** BIMI is worthless without `p=quarantine|reject`; DMARC alignment depends on the SPF/DKIM domains. Mailhardener's BIMI response carries the DMARC verdict. Checking one record *against another* is the cheapest way to look smarter than `dig`.

## Gaps & what it does not do

No resolver choice, no authoritative-vs-recursive toggle, no delegation trace, no TCP/EDNS/ECS controls, no raw wire output, no DNSSEC chain validation (Mailhardener reports a `has_dnssec` boolean on DANE only), no propagation-across-resolvers view (that's DNSChecker's territory), no reverse/passive DNS, no history or diff of a record over time outside the paid dashboards, no bulk/multi-domain input, no CSV export, no dark mode worth copying. LearnDMARC's quiz ships `correct: true` in the JSON to the client, so it's honour-system. And none of them will tell you what a *receiving* MTA at a given IP will actually do — SPF `exists:%{i}` macros can only be evaluated against a specific connecting IP, which none of these tools ask for.

## Verified firsthand vs inferred

**Verified:** every HTTP status; all the `dig` output; Mailhardener's API paths, unauthenticated access, `Access-Control-Allow-Origin: https://www.mailhardener.com` under a foreign `Origin`, the **DKIM endpoint's real address-splitting parameter shape**, BIMI's ignored `selector=`, and full response schemas for spf/dmarc/dkim/mx/mtasts/tlsrpt/bimi/dane incl. every field named above; EasyDMARC's `/content` fragment, its `ACAO: *`, its Cloudflare UA gate, its email gate & decision-table copy, the `10 LOOKUPS (8 main, 2 nested)` figure and inline CIDR expansion; the github.com SPF chain arithmetic (cross-checked `dig` vs Mailhardener JSON); the EasyDMARC `/tools/sitemap.xml` inventory (38 pages) and the dmarcian free-tools index (9 tools); dmarcian's 10 AJAX action names, its 403+`-1` nonce gate, `addParamsToCurrentUrl` & `recursiveMessageCount` in `tools.js`, and the `<spf-query-count>`/`<spf-inspection>`/`<dmarc-record-tags>` custom elements; LearnDMARC's `/getAddress` response, its 10-item/7-question `/quiz` payload, and `MX learndmarc.com → uriports.com`; RFC 9989/9990/9991 text; the MIT licenses of go-msgauth and mox.

**Not verified / inferred:** all pricing and free-tier limits (vendor pricing pages via WebFetch, **2026-09-15/16**, not transacted) — this includes Postmark's free-digest contents. Postmark's whole API surface (docs only; `POST /records` has a side effect so it was not called). dmarcian's response shapes, per-node `{level}` message objects, and SPF Surveyor's rendered layout (nonce-gated + client-rendered; layout leans on dmarcian's own copy). dmarcian's "no registration" and data-retention promises (their copy is quoted verbatim, the promise itself is untestable). EasyDMARC's four 404'ing fragment endpoints: param shape probably differs, absence unproven; `spf-record-raw-check-validate` existence confirmed from the sitemap, interface not. Mailhardener resolving from authoritative NS (inferred from `used_ns` varying per record). Rate limits everywhere: not probed, ~30 requests total across all five.

## Open source / reusable

None of the five publishes its validator. What's reusable is the spec plus Go libraries that already implement the hard parts: [`emersion/go-msgauth`](https://github.com/emersion/go-msgauth) (**MIT**; `dmarc` package fetches & parses DMARC records, plus `dkim`, `authres`), and [`mjl-/mox`](https://pkg.go.dev/github.com/mjl-/mox/dmarc) (**MIT**), whose `spf`, `dkim` and `dmarc` packages are a full production implementation w/ the lookup-limit accounting already written. Check both against RFC 9989 before trusting their Organizational-Domain logic. Mailhardener's JSON responses double as a free schema to model a domain struct against.

## Sources

- [RFC 7208 §4.6.4 — SPF DNS lookup limits, void lookups, permerror](https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4)
- [RFC 9989 — DMARC (May 2026, obsoletes 7489 & 9091)](https://www.rfc-editor.org/rfc/rfc9989.txt) · [RFC 9990 — aggregate reporting](https://www.rfc-editor.org/rfc/rfc9990.txt) · [RFC 9991 — failure reporting](https://www.rfc-editor.org/rfc/rfc9991.txt)
- [RFC 8461 — MTA-STS](https://www.rfc-editor.org/rfc/rfc8461) · [RFC 7505 — null MX](https://www.rfc-editor.org/rfc/rfc7505)
- [Mailhardener tools index](https://www.mailhardener.com/tools/) · [Mailhardener pricing](https://www.mailhardener.com/pricing)
- [Mailhardener SPF inspect API (observed)](https://api.mailhardener.com/v1/inspect/spf?domain=github.com) · [DKIM inspect, full-address form (observed)](https://api.mailhardener.com/v1/inspect/dkim?domain=google._domainkey.paypal.com) · [BIMI inspect (observed)](https://api.mailhardener.com/v1/inspect/bimi?domain=cnn.com)
- [EasyDMARC tools sitemap (observed, 38 pages)](https://easydmarc.com/tools/sitemap.xml) · [EasyDMARC pricing](https://easydmarc.com/pricing) · [EasySPF](https://easydmarc.com/tools/easy-spf)
- [EasyDMARC SPF lookup fragment (observed; needs a browser UA)](https://easydmarc.com/tools/spf-lookup/content?domain=github.com&is_embed=false)
- [dmarcian DMARC tools index](https://dmarcian.com/dmarc-tools/) · [dmarcian SPF Surveyor](https://dmarcian.com/spf-survey/) · [dmarcian XML-to-human Converter](https://dmarcian.com/xml-to-human-converter/) · [dmarcian pricing](https://dmarcian.com/pricing/)
- [dmarcian `dm-integration` api.js — AJAX action list (observed)](https://dmarcian.com/wp-content/plugins/dm-integration/api/js/api.js?ver=1.1.1)
- [LearnDMARC console](https://www.learndmarc.com/) · [LearnDMARC `/quiz` payload (observed)](https://www.learndmarc.com/quiz)
- [Postmark DMARC Digests landing](https://dmarc.postmarkapp.com/) · [Postmark DMARC API docs](https://dmarc.postmarkapp.com/api/) · [DMARC Digests](https://dmarcdigests.com/)
- [emersion/go-msgauth — MIT](https://github.com/emersion/go-msgauth/blob/master/LICENSE) · [mjl-/mox — MIT](https://github.com/mjl-/mox/blob/main/LICENSE.MIT)
