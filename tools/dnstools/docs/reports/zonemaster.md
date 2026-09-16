# Zonemaster

Joint open-source project of **AFNIC** (.fr registry) & **The Swedish Internet Foundation / IIS** (.se, .nu), built as the successor to AFNIC's Zonecheck + IIS's DNSCheck. Not a record-lookup tool: it is a **zone delegation validator** that runs a fixed catalogue of 73 named test cases against a zone & emits severity-graded findings. For someone building a DNS lookup tool its value is less the UI (which I could not observe) than the **spec**: Zonemaster's test-case catalogue is the richest publicly-documented, RFC-referenced enumeration of "what can be wrong with a DNS zone" that exists, and its message-tag table is a ready-made severity rubric you can copy verbatim.

- **URL:** https://zonemaster.net · **Category:** open-source zone/delegation validator + public instance · **Registration:** none for the web UI or the public JSON-RPC API · **Pricing:** free, no tiers, no keys (2026-09-16) · **API:** JSON-RPC 2.0 at `https://zonemaster.net/api`, **CORS `*`**, no auth
- **Firsthand check:** ~25 curl calls against `zonemaster.net/api` plus `dig` probes, 2026-09-15 & 2026-09-16. Confirmed live: `version_info` -> `{ldns 5.1.0, engine v9.0.0, backend 12.1.1}`; two complete `start_domain_test` -> `test_progress` -> `get_test_results` cycles (`corpberry.com`, 98 rows, worst level WARNING; a non-existent zone, 4 rows, **ERROR + CRITICAL**); the 10-min reuse window on both days; `add_batch_job` **and** `add_api_user` absent on the public instance; the `_url._zonemaster.<tld>` TXT convention. Could **not** observe the rendered result page: the GUI is Astro + Svelte and `curl` returns an 18 KB shell. That shell does carry the static chrome (`Domain name`, `Run test`, **`Show options`**, `Test result`, 8 language links); everything about how results are *displayed* below is read from `zonemaster-gui` source, not from a painted page.

## What it is

Five components, all **2-clause BSD** (copyright The Swedish Internet Foundation + AFNIC), released & versioned separately:

| Component | Role |
|---|---|
| `zonemaster-ldns` | Perl XS binding over NLnet Labs **ldns**, the actual DNS wire layer |
| `zonemaster-engine` | test framework + all test-case implementations + profile system |
| `zonemaster-cli` | `zonemaster-cli`, thin CLI over Engine |
| `zonemaster-backend` | JSON-RPC server + test-agent workers + result DB (MySQL/PostgreSQL/SQLite) |
| `zonemaster-gui` | web front-end (now **Astro + Svelte**; historically Angular) |

The split matters: you can take the Engine alone, the Backend alone, or just the **specifications** (prose + RFC references, language-agnostic). The FAQ makes the modularity an explicit selling point. The umbrella README states the lineage outright: a "major rewrite of Zonecheck and DNSCheck", aiming to "implement the best parts of both".

## Registration, access & pricing

Free, no account, no API key, no published rate limit (checked 2026-09-16). Only throttle documented or observed is the **reuse window** (below); ~25 requests and two fresh test runs across two days tripped nothing, but I did not probe for a limit. `profile_names` on the public instance returns `["default"]` only, so no relaxed/strict profile choice there. `get_language_tags` -> `da, en, es, fi, fr, nb, sl, sv` (8 locales). Privacy stance is unusually explicit & worth noting: per the FAQ, nothing is stored but the domain, test params & result, and **no link between a test and the user who ran it**. Flip side, also stated plainly: every test's history is **public**, so anyone can see who has been testing a domain.

## Features — complete inventory

### The test-case catalogue (the core asset)

**74 test cases defined, 73 implemented.** DNSSEC12 "Algorithm Completeness" is a placeholder: its spec page carries "TBD" for inputs, steps & outcomes and says outright "The Test Case is not yet implemented", and it is the one id missing from `ImplementedTestCases.md`. Each has a Markdown spec w/ purpose, inputs, ordered procedure, outputs & RFC references. Full list:

| Module | Cases | What they cover |
|---|---|---|
| **Basic** (3) | BASIC01-03 | parent zone discovery & child existence; ≥1 working NS; "broken but functional" fallback |
| **Address** (3) | ADDRESS01-03 | NS address globally reachable (rejects RFC1918/documentation/local-use); PTR exists; PTR matches NS name |
| **Delegation** (7) | DELEGATION01-07 | min NS count; distinct IPs; referral not truncated; NS is authoritative; NS not a CNAME; SOA exists; parent glue names present in child |
| **Consistency** (6) | CONSISTENCY01-06 | SOA serial / RNAME / timers / MNAME consistency across all NS; NS RRset consistency; **glue vs authoritative data** consistency |
| **Nameserver** (14) | NAMESERVER01-13, 15 | not a recursor; EDNS0 support; **AXFR open**; same source address; AAAA behaviour; NS resolvable; upward referral; QNAME case **insensitivity** (08) & **sensitivity** (09); undefined EDNS version (10); unknown EDNS OPTION-CODE (11); unknown EDNS flags (12); truncation on EDNS query (13); **revealed software version** via `version.bind` (15) |
| **Connectivity** (4) | CONNECTIVITY01-04 | UDP reachability; TCP reachability; **AS diversity**; **IP prefix diversity** |
| **DNSSEC** (18) | DNSSEC01-18 | DS digest algorithm legality; DS matches a child DNSKEY; NSEC3 params; RRSIG lifetimes too short/long; invalid DNSKEY algorithms; DNSSEC additional processing; signed-zone-vs-DS coherence; RRSIG(DNSKEY) valid; RRSIG(SOA) valid; NSEC/NSEC3 present; DS requires signed zone; *(12 unimplemented)*; all DNSKEY algorithms used to sign; RSA key size; **CDS/CDNSKEY existence (15)**, **validate CDS (16)**, **validate CDNSKEY (17)**, **trust from DS to CDS/CDNSKEY (18)** |
| **Syntax** (8) | SYNTAX01-08 | illegal chars in domain; leading/trailing hyphen; `--` in positions 3-4; NS name a valid hostname; `@` misuse in SOA RNAME; illegal chars in RNAME; illegal chars in MNAME; MX name a valid hostname |
| **Zone** (11) | ZONE01-11 | SOA MNAME fully qualified; `refresh` minimum; `retry` < `refresh`; `retry` ≥ 1h; `expire` minimum; `minimum` maximum; SOA master not an alias; MX not an alias; MX present; **no multiple SOA records**; **SPF policy validation** |

### Severity model

Eight levels, defined normatively: **CRITICAL** (zone so broken it cannot be tested) > **ERROR** (function harmed, zone still resolvable) > **WARNING** (problem under some circumstances) > **NOTICE** (admin should know, may be fine) > **INFO** (no problem) > **DEBUG** > **DEBUG2** (one line per query sent) > **DEBUG3** (full packet dumps). The DEBUG levels look like a CLI affordance: no DEBUG row appeared in either of my runs and the GUI's level map stops at INFO, though I did not confirm where they are filtered. CRITICAL really does abort: my non-existent-zone run returned exactly 4 rows, ending `CRITICAL · System · Not enough data about <domain> was found to be able to run tests.`

Severity attaches to the **message tag**, not the test case. Firsthand, the shipped `share/profile.json` carries **539 tags** across 10 modules (DNSSEC 178, ZONE 60, SYSTEM 55, CONNECTIVITY 53, NAMESERVER 52, DELEGATION 40, BASIC 31, SYNTAX 29, CONSISTENCY 28, ADDRESS 13), distributed ERROR 151 · WARNING 110 · INFO 97 · DEBUG 77 · NOTICE 70 · DEBUG2 19 · CRITICAL 11 · DEBUG3 4. That table is effectively a free, pre-argued severity rubric for every DNS misconfiguration worth naming.

### JSON-RPC API (verified against the live public instance)

| Method | Params | Returns |
|---|---|---|
| `version_info` | — | `{zonemaster_ldns, zonemaster_engine, zonemaster_backend}` |
| `profile_names` | — | array; public instance = `["default"]` |
| `get_language_tags` | — | array of locale tags |
| `get_host_by_name` | `hostname` | array of `{hostname: ip}`, v4 & v6 |
| `get_data_from_parent_zone` | `domain`, `language?` | `{ns_list[], ds_list[]}`. Parent's view, pre-fill for undelegated tests |
| `get_tld_url` | `domain` | `{tld, url?, source?}`, registry's own check page |
| `start_domain_test` | `domain`, `ipv4?`, `ipv6?`, `nameservers[]?`, `ds_info[]?`, `profile?`, `language?`, `client_id?`, `client_version?`, `priority?`, `queue?` | 16-hex `test_id`. Defaults echoed back in the result's `params`: `priority 10`, `queue 0`, `profile "default"`, both IP families on |
| `test_progress` | `test_id` | integer 0-100 |
| `get_test_results` | `id`, `language` | `{hash_id, created_at, params, results[], testcase_descriptions{}}` |
| `get_test_params` | `test_id` | normalized params of the original request |
| `get_test_history` | `frontend_params{domain}`, `offset?` (0), `limit?` (200), `filter? all\|delegated\|undelegated` | `[{id, created_at, undelegated, overall_result}]` |
| `add_batch_job` | `username`, `api_key`, `domains[]`, `test_params?` | `batch_id`. **`-32601 Procedure 'add_batch_job' not found` on zonemaster.net.** Upstream default for `RPCAPI.enable_add_batch_job` is *enabled*, so this is a deliberate deployment choice |
| `batch_status` | `batch_id`, `list_waiting_tests?`, `list_running_tests?`, `list_finished_tests?` | counts + optional id arrays |
| `add_api_user` | `username`, `api_key` | `1`/`0`. Localhost-only, `RPCAPI.enable_add_api_user` **false** by default; also `-32601` on zonemaster.net (verified) |

13 methods, no more: that is the whole surface. Errors follow JSON-RPC codes (`-32700` bad JSON, `-32601` unknown method, `-32602` bad params, `-32603` internal). `-32602` carries a `data[]` of `{path, message}` w/ a **JSON-pointer path**: sending `domain: "not a domain!!"` returned `path: "/domain"`, `message: "Domain name has an ASCII label (\"not a domain!!\") with a character not permitted."`

### CLI conveniences (`zonemaster-cli`, read from `lib/Zonemaster/CLI.pm`)

`--test Module/testcaseNN` (run one case or module) · `--list-tests` · `--level` (report threshold) · `--stop-level` (in source, a numeric comparison: the run aborts on the first message whose level is >= the threshold) · `--show-level` / `--show-module` / `--show-testcase` columns · `--raw` (untranslated tag + args) · `--json`, `--json-stream` (NDJSON as results arrive), `--json-translate` · **`--save` / `--restore`** (in source: `Zonemaster::Engine->save_cache($file)` after the run, `preload_cache($file)` before it, so dump the run's DNS data & replay it offline) · `--hints` (custom root hints) · `--nstimes` (per-NS min/max/avg/median/stddev/total/count, in ms) · `--count`, `--elapsed`, `--time`, `--progress`, `--version` · `--ns name/ip` & `--ds keytag,alg,type,digest` (undelegated) · `--ipv4/--ipv6`, `--sourceaddr4/6` · `--profile`, `--dump-profile` · `--locale`, `--encoding`.

### Convenience: the TLD-URL resolver

`get_tld_url` answers "who is the registry for this TLD, and where is *their* domain-check page". Resolution order, read from `Zonemaster::Backend::TLD_URL`: config override -> **TXT lookup at `_url._zonemaster.<tld>`** -> **IANA RDAP** (`https://rdap.iana.org/domain/<tld>`). Verified the last two branches: `dig TXT _url._zonemaster.se` returns `"https://internetstiftelsen.se/en/domains/?domain=[DOMAIN]"`, and the API substitutes the placeholder (`get_tld_url example.se` -> `…?domain=example.se`, `source: "TXT RECORD"`); `.com` & `.fr` have no such TXT and fell through to RDAP, yielding `verisigninc.com` & `nic.fr` w/ `source: "IANA RDAP"`. A tiny, self-describing federation protocol hiding in a DNS TXT record. Operator knobs: `enable_tld_url` (on), `lookup_timeout` 3 s, `include_source` (on), and a `[TLD URL OVERRIDE]` block that maps a TLD to a URL or to `[BLOCK]` to suppress it. Caveat: the spec says the GUI uses this on result pages, but the current GUI source wraps that button in `zm-u-hide` (`display: none !important`), so it looks switched off in the shipped front-end.

## Record types & query options supported

Zonemaster does **not** expose a "pick an RR type, get an answer" interface. It queries what its test cases need: SOA, NS, A, AAAA, PTR, MX, TXT (for ZONE11/SPF), DS, DNSKEY, RRSIG, NSEC/NSEC3(PARAM), CDS, CDNSKEY, plus an AXFR attempt (NAMESERVER03) and deliberate malformed-EDNS probes (NAMESERVER10-13).

Knobs actually available: **IPv4 / IPv6 on-off** · **undelegated NS set** (`nameservers[]`, name+optional IP) · **unpublished DS set** (`ds_info[]`) · **profile** · **language** · **priority / queue**. CLI adds root-hints override & source-address pinning. Per the query-defaults spec: **RD unset** and **no OPT record at all** on a plain *DNS Query*; an *EDNS Query* adds OPT w/ buffer **512** (deliberately small, so a response never exceeds the non-EDNS limit), a *DNSSEC Query* sets DO & buffer **1232** (IPv6 min MTU 1280 minus headers, per DNS flag day 2020); UDP first, re-query over TCP when TC is set. Engine defaults from `share/profile.json`: `retrans 3`, `retry 2`, `timeout 5`, `fallback true`.

## How it works

Entirely **server-side**. The Backend accepts a job, writes it to the DB, and a pool of **Test Agent** worker processes picks it up (`number_of_processes_for_frontend_testing` default 20, same for batch; `lock_on_queue` pins jobs to agents). The Engine is a real iterative resolver on top of ldns: it starts at the root hints, follows the delegation to the parent, pulls the parent-side NS & DS, then queries **every authoritative NS at every address, v4 and v6 separately**, which is why consistency & diversity tests are possible at all. Firsthand on `corpberry.com`, the run touched the `.com` gTLD servers and both Cloudflare NS across all 12 addresses.

Caching: an optional **Redis** layer for cross-process query caching, off unless configured (profile property `cache` defaults to `{}`; `cache.redis.server` is `host:port`, `cache.redis.expire` defaults to 300 s); result-level dedup is the reuse window. AS/prefix data for CONNECTIVITY03/04 comes from an external ASN source, default **Team Cymru** style via `asnlookup.zonemaster.net` w/ `asn.cymru.com` as backup, RIPE `riswhois.ripe.net` as an alternative style.

Timing observed: progress went 1 -> 8 -> 16 -> 55 -> 100 over roughly 30 s for a 2-NS, 12-address, unsigned zone. `max_zonemaster_execution_time` default 600 s marks a stuck test failed.

## Output & UX

`get_test_results` returns a **flat array of message objects**, each `{level, module, testcase, message, ns}`: no nesting, no scoring. `ns` is `nsname/address` when a finding belongs to one server, the literal `"All"` when it belongs to every one, and absent for zone-level findings; `testcase` is `"Unspecified"` for engine-level messages (module `System`). The corpberry.com run: 98 rows, 48 distinct test cases, **86 INFO / 8 NOTICE / 4 WARNING**, zero ERROR, w/ 36 rows carrying a per-address `ns` (2 NS names × 3 v4 + 3 v6). Alongside it comes `testcase_descriptions`, a **map of every test-case id that appeared to its human title** (48 entries there), so a client can render section headings without shipping its own copy of the catalogue. Messages are pre-translated server-side per the `language` param and are written as full sentences w/ the offending data inline, and several carry the fix, e.g.:

- `WARNING · Connectivity03 · All authoritative nameservers have their IPv4 addresses in the same AS (13335).`
- `NOTICE · Zone02 · SOA 'refresh' value (10000) is less than the recommended one (14400).`
- `NOTICE · Zone11 · No SPF policy was found for corpberry.com.`
- `ERROR · Basic01 · "zzz-no-such-zone-probe-9f2.com" does not exist as a DNS zone. Try to test "com" instead.`

`get_test_history` returns one `overall_result` word per past run (`"warning"` for the corpberry run, `"critical"` for the broken one) plus an `undelegated` boolean, enough to draw a pass/fail timeline per domain. Result permalinks resolve: `https://zonemaster.net/result/<hash_id>` and `/en/result/<hash_id>` both return 200. Since the page is an SPA I saw the URLs answer, not what they paint.

What the page then does w/ that payload is **read from `zonemaster-gui` source, not observed rendering**, and it is richer than the flat API suggests. `groupResult.ts` buckets rows module -> test case, rolls each test case up to its **worst** message level and sorts test cases by descending severity; `System`/`Unspecified` rows float to the top. `ResultModule.svelte` renders each module as a collapsible section w/ per-level count badges, `ResultGroup.svelte` uses `testcase_descriptions` for the heading & shows the bare test-case id as a badge (no link to the case's spec page). Above them sit **severity filter toggles** (ALL/INFO/NOTICE/WARNING/ERROR/CRITICAL, each w/ a count, ALL mutually exclusive w/ the rest), a **free-text filter** over message bodies, expand-all/collapse-all, a share popover, and a **history modal** (paginated 10/page, filter all/delegated/undelegated, links to each past result). `resultIcon.ts` maps level -> a Bootstrap icon (INFO check-circle, NOTICE exclamation-circle, WARNING triangle, ERROR x-circle, CRITICAL x-octagon); DEBUG levels are not in that map at all. And **export exists**, which the API surface hides: `export.ts` builds client-side downloads in **JSON, HTML, CSV & TXT**, named `zonemaster_result_<ascii-domain>_<hash_id>.<ext>`, CSV `;`-separated w/ a `Module;Level;Message` header, HTML a self-contained styled table. Worth reading before copying: its CSV/TXT converter loops `for (let i = 1; …)` and so drops the first result row.

The FAQ documents the **"Show options"** disclosure (confirmed present in the static shell), which reveals undelegated NS, DS records and an IPv4/IPv6/both radio; the profile `<select>` only renders when the instance exposes more than one profile, so zonemaster.net shows none. The FAQ also says the web UI deliberately does **not** show the underlying queries; only the CLI at DEBUG does.

Progressive rendering is polled, not streamed: `test_progress` returns a plain integer and the GUI's default `pollingInterval` is **5000 ms**. Only the CLI has a true stream (`--json-stream`).

## Monetization, limits & abuse controls

None of it is monetized. Controls are structural:

- **10-minute reuse window** (`age_reuse_previous_test`, default 600 s). Verified: re-POSTing identical params returned the **same** `hash_id` `489def008aae1f11` with no new run. The FAQ calls it "protection between consecutive tests".
- **Batch API off** on the public instance (`add_batch_job` -> `-32601`), so no unauthenticated bulk fan-out.
- **`add_api_user` localhost-only and disabled by default** (and `-32601` here too), so accounts exist only where an operator wants them; worker-pool ceiling + 600 s execution cap bound concurrent load.
- Bare `CORS: *` w/ no key: the API is genuinely meant to be called from anyone's browser. A deliberate posture, not an oversight.

## Ideas worth stealing

- **Ship a numbered check catalogue, not a wall of records.** The single highest-value idea. Give every check a stable id (`ZONE02`, `DELEGATION01`), a one-line title, and a permalink to its own explanation page. Your Go domain package returns `[]Finding{ID, Level, Module, Message}`; the handler renders it as HTML sections or JSON unchanged. It fits the layering rule exactly, the ids make results linkable, diffable & bug-reportable, and a per-check `docs/` page citing the RFC clause you are applying (Zonemaster's whole credibility) matches this repo's `tools/<tool>/docs/` layout at near-zero cost.
- **Severity on the message, not the check.** One check emits many tags at different levels (ZONE02 can be INFO or NOTICE depending on the value found). Model findings as tags w/ a level, then let a config map override levels. That is Zonemaster's `test_levels`, and it is why their catalogue survived a decade of "well, actually that's fine for us" arguments. The rubric itself is liftable: `share/profile.json` (BSD, machine-readable) hands you 539 tag->severity decisions already argued out against RFCs, and even a 30-tag subset beats inventing severities yourself.
- **Roll a flat list up to a tree in the client.** The API stays flat; `groupResult.ts` does module -> test case -> messages, each test case inheriting its worst message level, sorted severity-descending. ~40 lines of Go on a `[]Finding`, and it is what turns 98 undifferentiated rows into a page someone can read. Their export set (JSON/HTML/CSV/TXT from the already-loaded payload) is the same trick: one struct, four renderers, which is exactly what `platform.Respond` is for.
- **Return the description map with the results.** `testcase_descriptions` means the client never hardcodes titles and new checks appear in the UI without a front-end change. Cheap to copy: one extra map in the JSON response, and the htmx fragment renders headings from it.
- **`_url._zonemaster.<tld>` TXT -> IANA RDAP fallback.** A delegation-aware way to answer "where do I go to fix this". Free to implement: one TXT query, one RDAP GET, a `[DOMAIN]` substitution. Adding a "your registry's own checker" link at the bottom of a report is a genuinely unusual touch.
- **The 10-minute reuse window as a first-class product behaviour.** Not a rate limiter bolted on, but a documented promise: identical request inside the window returns the identical result id. For a Go tool w/ Mongo already wired, this is a `(domain, params_hash)` unique index plus a TTL, and it doubles as the share-link mechanism.
- **Structured param errors w/ JSON-pointer paths.** `{path: "/domain", message: "…label … with a character not permitted."}` renders straight into an htmx form-error swap next to the offending input, and serves JSON clients identically.
- **AS & prefix diversity as checks.** CONNECTIVITY03/04 turn data the iptools feature already fetches (ASN, prefix) into a *judgement*: "all your nameservers are in AS13335". That is the cheapest high-signal check on this list for this repo specifically, because the ASN lookup already exists.
- **`--save` / `--restore`.** Dump every DNS response a run collected, replay offline. In Go this is a `map[query]response` serialized to JSON, and it gives deterministic, network-free tests, which the repo's `<pkg>/tests/` convention wants anyway. `--stop-level` (abort at a severity) & `--nstimes` (min/max/avg/median/stddev per NS) are two more cheap wins from the same CLI.

## Gaps & what it does not do

- **No general record lookup.** No "give me the TXT records", no dig-style interface, no arbitrary RR type, no choice of resolver. RDAP is used only to find a TLD's registry URL, never for the queried domain itself. If the DNS lookup tool is meant to answer "what is the A record", Zonemaster is a complement, not a model.
- **Zones only, not hostnames.** `www.example.com` is rejected unless it is itself a delegated zone. The FAQ lists this as a top confusion.
- **No propagation view.** It queries authoritative servers, never a panel of public recursives, so it cannot answer "has my change reached 8.8.8.8 yet". That is the single biggest missing feature vs consumer DNS tools.
- **No monitoring, alerting, webhooks or scheduled re-checks**; history is a passive log. No diff between two runs either, despite history being right there.
- **No email-deliverability depth.** ZONE11 validates SPF *syntax/presence*; no DKIM, DMARC, MTA-STS or blocklist checking.
- **Severity, not a score,** and the UI never links a finding to its spec page: no 0-100, no grade, no verdict beyond `get_test_history`'s one-word `overall_result`, and test-case ids appear as bare badges, so the best-documented check catalogue in DNS makes the reader go find the Markdown themselves.
- **Perl.** The catalogue ports cleanly; the implementation does not.

## Verified firsthand vs inferred

**Verified by curl/dig, 2026-09-15 & re-checked 2026-09-16:** component versions; CORS headers & absence of auth; `profile_names`, `get_language_tags`, `get_host_by_name`, `get_data_from_parent_zone`, `get_tld_url`, `start_domain_test`, `test_progress`, `get_test_results`, `get_test_params`, `get_test_history`; the full result payload shape incl. the `ns` field, `"Unspecified"` testcases & the echoed default params; the level/module/testcase distribution of two runs; **ERROR & CRITICAL observed**, and that CRITICAL truncates a run to 4 rows w/ `overall_result: "critical"`; `add_batch_job` & `add_api_user` both `-32601`; the reuse window returning an identical id on both days; the JSON-pointer error shape; `/result/<id>` returning 200 & the static shell's "Show options" / language chrome; the `_url._zonemaster.se` TXT record & the backend's `[DOMAIN]` substitution; RDAP fallback for `.com` & `.fr`; the 539-tag / 10-module contents & resolver defaults of `share/profile.json`; the 74-vs-73 test-case count across `README.md` & `ImplementedTestCases.md`; 2-clause BSD in each component's `LICENSE`; the published `zonemaster/{cli,backend,all-in-one}` Docker images.

**Read from docs/source, not observed running:** severity-level definitions (the five non-DEBUG levels have now all been seen in a payload, DEBUG/2/3 have not); backend defaults (`age_reuse_previous_test` 600 s, `max_zonemaster_execution_time` 600 s, 20 worker processes each for frontend & batch, Redis expire 300 s), documented twice, in the config reference and in the commented-out `share/backend_config.ini`, but only the reuse window was confirmed behaviourally; EDNS 512/1232 & RD-unset query defaults; the TLD_URL config-override branch & `[BLOCK]` policy; batch & `add_api_user` behaviour where enabled; the CLI (option list, `--save`/`--restore` -> `save_cache`/`preload_cache`, `--stop-level`'s numeric comparison & `--nstimes`' statistics all read in `CLI.pm`, but the CLI was never installed or run); **everything about the rendered result page**, which is read from `zonemaster-gui` source: grouping, severity roll-up, filter toggles, text filter, icons, history modal, share popover and the JSON/HTML/CSV/TXT export.

**Not verified at all:** how any of that GUI source actually looks & behaves in a browser. Browser tooling was off-limits for this pass, `curl` gets only the 18 KB shell, and source can be dead code (the TLD-URL button is present but `display: none`). Colour choices, spacing, mobile behaviour & whether the filters are usable are unknown. Also unknown: whether the public instance rate-limits beyond the reuse window (volume was kept to ~25 requests & 2 fresh runs; no limit was probed for).

## Open source / reusable

All components **2-clause BSD** (The Swedish Internet Foundation + AFNIC), `zonemaster-ldns` additionally carrying NLnet Labs ldns terms for the ldns sources it may bundle. Directly reusable without writing Perl:

- `zonemaster/zonemaster` -> `docs/public/specifications/tests/`: the whole catalogue as Markdown, incl. `README.md` (the id->title table), `MasterTestPlan.md`, `SeverityLevelDefinitions.md`, `TestMessages.md` (tag -> test-case map), `DNSQueryAndResponseDefaults.md`, `Methods.md` / `MethodsV2.md` (the delegation-discovery algorithm, spelled out step by step).
- `zonemaster-engine` -> `share/`: **`profile.json`**, the 539-tag severity table, ready to `go:embed`; **`named.root`** (root hints); **`iana-ipv4-special-registry.csv` & `iana-ipv6-special-registry.csv`**, the "globally reachable" table ADDRESS01 applies, already flattened to CSV; `profile.yaml` & `profile_additional_properties.json`; and **7 `.po` catalogues** (da, es, fi, fr, nb, sl, sv; English is the source language, not a catalogue).
- `zonemaster-gui` -> `src/lib/groupResult.ts`, `resultIcon.ts`, `export.ts`: ~250 lines of BSD TypeScript that turn a flat result array into a grouped, filterable, exportable page. Porting the logic to Go templates is an afternoon.
- Operationally: self-hosting the whole stack (`zonemaster/all-in-one`, `zonemaster/backend`, `zonemaster/cli` on Docker Hub, all updated mid-2026) and calling it from Go is a legitimate shortcut, at the cost of a Perl + DB + worker-pool dependency that this one-binary repo explicitly does not want.

## Sources

- [Zonemaster public instance](https://zonemaster.net/)
- [Zonemaster FAQ: reuse window, undelegated tests, privacy, severity levels](https://zonemaster.net/en/faq/)
- [Test Case Specifications index: full id/title table](https://github.com/zonemaster/zonemaster/blob/master/docs/public/specifications/tests/README.md)
- [Master Test Plan](https://doc.zonemaster.net/latest/specifications/tests/MasterTestPlan.html)
- [Severity Level Definitions](https://doc.zonemaster.net/latest/specifications/tests/SeverityLevelDefinitions.html)
- [Implemented Test Cases](https://github.com/zonemaster/zonemaster/blob/master/docs/public/specifications/tests/ImplementedTestCases.md)
- [DNS Query and Response Defaults](https://github.com/zonemaster/zonemaster/blob/master/docs/public/specifications/tests/DNSQueryAndResponseDefaults.md)
- [RPC API reference](https://doc.zonemaster.net/latest/using/backend/rpcapi-reference.html)
- [Backend configuration reference](https://doc.zonemaster.net/latest/configuration/backend.html)
- [`Zonemaster::Engine::Profile` POD: profile properties, logfilter, test_levels](https://github.com/zonemaster/zonemaster-engine/blob/master/lib/Zonemaster/Engine/Profile.pm)
- [Default profile `share/profile.json`](https://github.com/zonemaster/zonemaster-engine/blob/master/share/profile.json)
- [`Zonemaster::Backend::TLD_URL`: TXT then IANA RDAP resolution](https://github.com/zonemaster/zonemaster-backend/blob/master/lib/Zonemaster/Backend/TLD_URL.pm)
- [`Zonemaster::CLI`: full option list](https://github.com/zonemaster/zonemaster-cli/blob/master/lib/Zonemaster/CLI.pm)
- [TLD URL specification: TXT record format, RDAP fallback, blocking policy](https://github.com/zonemaster/zonemaster/blob/master/docs/public/configuration/tld-url-specification.md)
- [Shipped `backend_config.ini`: commented-out defaults](https://github.com/zonemaster/zonemaster-backend/blob/master/share/backend_config.ini)
- [Zonemaster GUI repository (Astro + Svelte, BSD-2)](https://github.com/zonemaster/zonemaster-gui)
- GUI result-page source: [`export.ts`](https://github.com/zonemaster/zonemaster-gui/blob/master/src/lib/export.ts) (JSON/HTML/CSV/TXT), [`groupResult.ts`](https://github.com/zonemaster/zonemaster-gui/blob/master/src/lib/groupResult.ts) (grouping & severity roll-up), [`ResultInfo.svelte`](https://github.com/zonemaster/zonemaster-gui/blob/master/src/lib/components/DomainTest/ResultInfo.svelte) (filters, export, share)
- [Zonemaster on Docker Hub](https://hub.docker.com/u/zonemaster)
- [Zonemaster umbrella repository](https://github.com/zonemaster/zonemaster)
- [AFNIC: Zonemaster release information](https://www.afnic.fr/en/observatory-and-resources/news/zonemaster-release-information/)
