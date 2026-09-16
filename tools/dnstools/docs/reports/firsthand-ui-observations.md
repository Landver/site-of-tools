# Firsthand UI observations — flagship DNS tools driven live

Companion to the per-service reports. Those were researched via docs + `curl`/`dig`; **this file records
what the pages actually rendered** when driven in a real browser on **2026-09-15**. Where a report and
this file disagree about what a UI shows, this file wins.

- **Test browser:** in-app Claude/Electron browser (`Chrome/148 Electron/…`, macOS), egress IP
  **`89.222.123.96`** (as echoed back by MXToolbox's own footer).
- **Test domain:** `corpberry.com` throughout (Cloudflare-hosted, 2 NS, no MX, Google site-verification
  TXT) — so several "no records" empty states got exercised for free. `cloudflare.com` used for DNSSEC
  (corpberry.com has no chain to show).
- **Method:** navigate → wait → extract rendered text. No automation of forms, no accounts, no repeat hits.

## Per-tool: what rendered

### NsLookup.io — `nslookup.io/domains/corpberry.com/dns-records/`

Cleanest information design in the set. Rendered:

- **Result URL is the query.** Path-shaped permalink (`/domains/<domain>/dns-records/`), no form POST,
  no hash, shareable & crawlable. Biggest single UX idea here.
- **"Overall result" header names the DNS provider** — printed `Cloudflare` + `Other`. Provider
  attribution from NS records, surfaced *above* the raw data.
- **TTL rendered as "Revalidate in 5m"**, not `300`. Reframes TTL from protocol trivia into "when does
  this answer go stale," w/ a sentence explaining that the resolver re-asks an authoritative NS after.
- **TXT records semantically classified.** Our Google verification TXT was labelled
  **"Site ownership verification · Google"** rather than dumped as an opaque string.
- **Honest empty states as first-class rows:** "No CNAME record found.", "No mail servers found."
  Absence is an answer, presented as one.
- **SOA decoded field-by-field** (Start of authority, Email w/ `dns@cloudflare.com` de-obfuscated from
  `dns.cloudflare.com`, Serial, Refresh `2h 46m 40s`, Retry `40m`, Expire `168h`, **Negative cache TTL**).
  Every numeric field given a human duration.
- Records grouped A / AAAA / CNAME / TXT / NS / MX / **Other records** w/ an "Additional record type"
  affordance — common types eagerly, long tail on demand.
- Inline monetization: "Want to monitor this domain? Track DNS changes, SSL expiration, uptime."
  Monitoring is the upsell, lookup is the free hook.

### intoDNS — `intodns.com/corpberry.com`

The zone-health test catalogue, fully exposed. `Category | Status | Test name | Information` table,
**processed in 0.430s**, domain in the URL path. Categories & checks observed live:

| Category | Checks that ran |
|---|---|
| **Parent** | Domain NS records (named the actual parent server: *"b.gtld-servers.net was kind enough to give us that information"*), TLD parent check, nameservers listed at parent, **parent sent glue**, NS A records exist |
| **NS** | NS records from your nameservers, **recursive queries refused**, same glue parent-vs-child, glue for NS records, mismatched NS records, all NS responded, NS names valid, multiple nameservers (cites RFC 2182 §5), **lame nameservers**, missing NS at parent, missing NS at child, domain CNAMEs (RFC 1912 2.4 / RFC 2181 10.3), NS CNAME check, **different subnets**, NS IPs public, **NS allow TCP**, **different autonomous systems**, stealth NS records |
| **SOA** | SOA record dump, all NS agree on serial, MNAME listed at parent, serial sanity, REFRESH / RETRY / EXPIRE / MINIMUM-TTL each range-checked (MINIMUM explained as negative-caching TTL, RFC 2308 "1-3 hours recommended") |
| **MX** | MX records — our no-MX domain got the conversational *"Oh well, I did not detect any MX records so you probably don't have any…"* |
| **WWW** | `www` A record, IPs public, WWW CNAME |

Ideas that stand out: **every verdict cites the RFC it comes from**; failures explain the consequence,
not just the rule ("this is a must if you want to be found"); `INFO`-level findings sit between pass and
fail (our zone got one: no glue when the child NS are asked directly, w/ the two IPs listed and a
concrete fix). Footer admits the stack (Python/Django/jQuery) and that it's a hosting company's lead gen.

### MXToolbox SuperTool — `mxtoolbox.com/SuperTool.aspx?action=dns:corpberry.com`

**Command-prefix input** is the whole product: one box, typed prefix picks the tool. Full list rendered
on the page: `a: aaaa: arin: asn: bimi: blacklist: cname: dkim: dmarc: dns: http: https: mta-sts: mx:
ping: ptr: smtp: soa: spf: tcp: tlsrpt: trace: txt: whois:` (`mta-sts:` and `tlsrpt:` badged **New!**).

The `dns:` result itself:

- NS rows annotated w/ **resolved IP + owning org & ASN** (`108.162.193.156 · Cloudflare, Inc. (AS13335)`)
  and columns `TTL | Status | Time (ms) | Auth | Parent | Local`, i.e. **parent-vs-local agreement shown
  as columns**, per-server latency in ms.
- Findings list mixes problems and passes in one scannable column: **"SOA Serial Number Format is
  Invalid — Serial year was 2413 which is in the future"** and **"SOA Expire Value out of recommended
  range — recommended between 1209600 and 2419200"** (both fired on Cloudflare's own defaults, a useful
  reminder that these heuristics produce false alarms), then ~14 green checks (no bad glue, ≥2 NS, all
  responding, all authoritative, local matches parent, dispersed, public IPs, serials match, primary
  listed at parent, refresh/retry/minimum in range, **no open recursive NS**).
- Each finding carries a **"More Info"** link → its own explainer page. Cheap, huge perceived depth.
- **"Your DNS hosting provider is Cloudflare"** + a bulk-data upsell right there.
- Footer: *"Reported by dion.ns.cloudflare.com on 9/15/2026 at 3:01:57 PM (UTC -5), just for you."*
  Names the answering server + timestamps the result. **Transcript** link exposes the raw query log.
- Cross-tool chips under the result: `dns lookup · mx lookup · dmarc lookup · spf lookup · dns propagation`.
- Echoes visitor IP in footer (`Your IP is: 89.222.123.96`).

### DigWebInterface — `digwebinterface.com`

Raw `dig` as a web form; the **option matrix** is the differentiator. Rendered controls:

- **44 record types** in the full selector: A AAAA AFSDB ANY APL AXFR CAA CDNSKEY CDS CERT CNAME CSYNC
  DHCID DLV DNAME DNSKEY DS EUI48 EUI64 HINFO HIP **HTTPS** IPSECKEY KEY KX LOC MX NAPTR NS NSEC NSEC3
  NSEC3PARAM OPENPGPKEY PTR RP RRSIG SIG SMIMEA SOA SRV SSHFP **SVCB** TA TKEY TLSA TSIG TXT URI ZONEMD
  (plus a short "common types" list above it, and a `Reverse` shortcut).
- **Option checkboxes:** Show command · Colorize output · Stats · Request NSID · **Trace** · Sort
  alphabetically · Short · **No recursive** · Only first nameserver · **Compare output** · Save to file ·
  **DNSSEC**.
- **Resolver picker w/ named public resolvers + country tags:** Cloudflare, AdGuard (CY), AT&T (US),
  Comodo (US), Google, HiNet (TW), OpenDNS, Quad9, Verisign (US), Yandex (RU) — plus radio modes
  **All / Authoritative / NIC / Specify myself**.
- Output is monospaced dig text, labelled w/ the resolver used: `corpberry.com@8.8.8.8 (Google):`.
- **Every option is in the query string** (`?hostnames=…&type=A&ns=resolver&useresolver=8.8.8.8`), so any
  configuration is a link. Same permalink idea as NsLookup.io, applied to a power-user tool.
- Funded by donations; CMP cookie wall w/ "1737 partners" appears before content.

### Google Admin Toolbox Dig — `toolbox.googleapps.com/apps/dig`

Minimal by comparison, and deliberately so. `#A/corpberry.com` **hash routing** (record type + name in
the fragment), TTL printed as **"5 minutes"** not `300`, a **Raw View** toggle to drop back to dig text,
and the UI localized into **27 languages**. Nothing else: no health checks, no provider attribution.

### DNSChecker.org — `dnschecker.org/#A/corpberry.com`

Propagation grid. Hash routing again (`#A/corpberry.com`). Rendered:

- **12 record types** in the tab strip: A AAAA CNAME MX NS PTR SRV SOA TXT CAA DS DNSKEY.
- **~35 resolvers visible in the default grid**, each labelled **city + country + operator**
  (San Francisco/OpenDNS, Mountain View/Google, Berkeley/Quad9, Cambridge/Akamai, Saint Petersburg/PJSC
  MegaFon, Cullinan/Liquid Telecom, Innsbruck/nemox.net, Bengaluru/"BHARAT PUBLIC DNS (1.10.10.10)",
  Dhaka/ARK Network, …). Marketing copy claims **100+ servers** total. Rows load individually w/ a
  per-row **Load** state — async fill, no blocking wait.
- **ADD A CUSTOM DNS SERVER**, plus filters: IPv4/IPv6 lists, 6 continents, 28 countries, and a
  **Refresh every N sec** auto-repoll.
- Honest caveat printed under the grid: *"Complete DNS Resolution may take up to 48 hours."*
- Long SEO explainer below the fold defining each record type, each linking to that record's own tool page.

### DNSViz — `dnsviz.net/d/cloudflare.com/dnssec/`

- **Analyses are cached artifacts w/ history**, not live runs: *"Updated: 2026-09-15 15:42:34 UTC (about 4
  hours ago)"* + **Update now** button + **« Previous analysis | Next analysis »** navigation. Someone
  else's recent run answers your question instantly, and you can diff over time.
- Tabs **DNSSEC · Responses · Servers · Analyze**; a **DNSSEC options** disclosure; a **Notices** block for
  warnings/errors; **DNSKEY legend** (SEP bit set, Revoke bit set, Trust anchor) + full legend.
- Graph **downloadable as PNG or SVG**; source on GitHub; explicitly cross-links the
  **Verisign Labs DNSSEC Debugger** as a second opinion.
- Domain in the URL path (`/d/<domain>/dnssec/`) — permalink again.

### DNSDumpster — `dnsdumpster.com`

Landing page only (search is a POST). Positions itself as **OSINT recon**, not admin diagnostics: "map an
organization's attack surface", Attack / Defend / Learn framing, and discloses it is a **HackerTarget**
project. Confirms the recon category is a separate audience w/ separate vocabulary.

### whatsmydns.net — blocked

**Did not render.** Cloudflare interstitial: *"Performing security verification … protect against
malicious bots"*, and it never cleared for our Electron browser. Recorded as a datapoint, not a verdict on
the service: the most-cited propagation checker is **behind bot protection**, so its UI could not be
observed firsthand here, and its report rests on docs + secondhand sources. (Also a reminder for our own
build: tools like this attract enough automated abuse to justify a challenge layer.)

## Patterns that repeat across the set

1. **The query belongs in the URL.** Path (`nslookup.io/domains/<d>/dns-records/`, `intodns.com/<d>`,
   `dnsviz.net/d/<d>/dnssec/`), hash (`#A/<d>` at Google and DNSChecker), or full query string
   (DigWebInterface). Nobody makes you re-type to share a result. Cheap for us: a `GET`-shaped form.
2. **TTL is shown as time, not an integer** (NsLookup.io "Revalidate in 5m", Google "5 minutes",
   MXToolbox "24 hrs"). Only the raw-dig tools print seconds.
3. **Name the server that answered.** intoDNS names the parent (`b.gtld-servers.net`), MXToolbox names the
   responding NS + timestamp, DigWebInterface labels output w/ the resolver. Shows the work, and makes the
   result falsifiable.
4. **Absence is rendered as a row**, not an empty section ("No CNAME record found", "No mail servers found",
   intoDNS's conversational no-MX line).
5. **Findings link to an explainer.** MXToolbox "More Info" per finding, intoDNS inline RFC citations,
   DNSChecker's per-record-type sections. Education is the retention mechanic in this category.
6. **Provider attribution is a headline feature** (NsLookup.io "Cloudflare", MXToolbox "Your DNS hosting
   provider is Cloudflare", and MXToolbox annotating NS IPs w/ org + ASN). We already have the ASN/org half
   of this shipped in [`iptools`](../../../../tools/iptools/docs/README.md).
7. **Health heuristics produce false alarms and ship anyway.** MXToolbox flagged Cloudflare's own SOA serial
   and Expire. Worth copying the *format* (range-checked fields w/ named thresholds) while being more careful
   about the thresholds, or labelling them as conventions rather than errors.
8. **Async, per-row result filling** (DNSChecker's `Load` states) rather than one blocking request — a
   natural htmx fit.
9. **The free tool is the funnel.** Monitoring/alerting upsell (NsLookup.io, MXToolbox, DNSChecker), hosting
   company (intoDNS/Hosterion), donations (DigWebInterface), ad/CMP walls (DigWebInterface, MXToolbox,
   DNSChecker). None of them monetize the lookup itself.

## Not observed firsthand

whatsmydns.net (bot-blocked), and every search/POST-driven flow behind these landing pages: DNSDumpster
results, MXToolbox tools other than `dns:`, DNSChecker's non-A record tabs, NsLookup.io's "additional record
type" long tail, DNSViz's Responses/Servers/Analyze tabs. Pricing, API behaviour and free-tier limits were
**not** tested here at all — see the per-service reports for those.
