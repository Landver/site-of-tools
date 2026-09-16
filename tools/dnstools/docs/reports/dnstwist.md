# dnstwist / dnstwist.it

Not a DNS lookup tool: a **lookalike-domain discovery engine** that happens to run thousands of DNS lookups as its verification step. Written by **Marcin Ulikowski** (`elceef`), Apache-2.0, Python, **5,738 GitHub stars / 851 forks** (confirmed via GitHub API, 2026-09-16), packaged in Kali/Debian/Fedora/Homebrew and in Arch's **AUR** (`dnstwist` and `dnstwist-git`, both user-maintained — not in Arch's official `extra` repo, confirmed via the AUR RPC search endpoint), and the reflexive r/sysadmin & r/netsec answer to "who is squatting our brand". `dnstwist.it` is the author's free hosted cut of it. Matters to a DNS-tool builder for two reasons: it is the reference implementation of **permutation generation** (16 named fuzzers, all small pure functions, trivially portable to Go), and its real differentiator is what happens *after* resolution: it **fetches the live page at each surviving permutation and fuzzy-hashes it against the real site**, so the output is "this one is an actual clone of you", not "this typo is registered".

- **URL:** https://dnstwist.it · code https://github.com/elceef/dnstwist · **Category:** typosquat / brand-impersonation discovery (permutation + bulk resolution + clone detection) · **Registration:** none, no account, no key, no captcha · **Pricing:** free, both CLI & hosted · **API:** undocumented but fully open JSON API on the hosted app (endpoints below); `dnstwist.run(**kwargs)` as a Python library.
- **Firsthand check (2026-09-15, all via curl/dig from this machine):** `GET https://dnstwist.it/` -> **200**, `server: cloudflare`, `content-disposition: inline; filename=webapp.html` (serving `webapp/webapp.html` from the repo verbatim). Ran one real scan of **corpberry.com**: `POST /api/scans` -> **201**, `{"id":"75053efe-…","total":5679,…}`; polled to completion in **~19 s** (5,679 permutations, so ~300 resolutions/sec server-side); **5 registered** found, incl. `corberry.com` (omission fuzzer, MX at `corberry-com.mail.protection.outlook.com`) and `cropberry.com` (transposition, NS `ns1.afternic.com` = parked/for-sale). Pulled `/domains`, `/csv`, `/json`, `/list` (5,678 lines). Confirmed the **15-char SLD cap** by submitting a 16-char name (400 `"Domain name is too long"`) vs 15-char (201, 11,583 permutations), then `POST …/stop` on that test scan. **No CORS headers on any endpoint** (checked w/ `Origin:` on both `/api/scans` and the JSON export). Source read directly from raw.githubusercontent (`dnstwist.py` 1,626 lines, `webapp/webapp.py` 209 lines). Not verified firsthand: `--lsh`/`--phash`/`--whois`/`--banners`/`--mxcheck`, since those are CLI-only and I did not install the tool; those descriptions come from reading the source, and I say so at each point below.
  **Re-verification pass (2026-09-16):** re-ran the same POST/stop/400-too-long probes and got identical shapes; confirmed line-by-line against `dnstwist.py`/`webapp.py`/`webapp.html` that `DOMAIN_MAXLEN`/`SESSION_TTL`/`SESSION_MAX`/`THREADS` defaults, the NS→A/AAAA→MX resolution order, `is_registered() = len(self) > 2`, the TLSH formula, the `mxcheck` EHLO/MAIL FROM/RCPT TO sequence, the `_homoglyph` double-apply (`result1 | mix(result1)`), the 21-char `latin_to_cyrillic` map, the per-TLD IDN glyph gating, the DoH regex, and the 16-TLD WHOIS server map all match the report's descriptions exactly — still source-read, not executed, but now cross-checked line-for-line rather than paraphrased from memory. Confirmed via GitHub API: 5,738 stars, 851 forks, Apache-2.0, last push 2025-04-15. Confirmed `dnstwister.report` still 301s to `dnstwister.com`. Found and corrected two errors: the fuzzer count was undercounted (15 -> 16, see inventory), and `webapp.html`'s line count was off (282 -> 277). Found one nuance the original pass missed: the default installed dependency for `--lsh` is **`ppdeep`**, not native `ssdeep` (see LSH section).

## What it is

Three stages, cleanly separated in the code: **Fuzzer** (pure string generation, zero I/O) -> **Scanner** (thread pool doing DNS + optional enrichment) -> **Format** (cli/csv/json/list). The library entry point `dnstwist.run(domain=…, registered=True, format='null')` returns a list of dicts, which is why it is embedded in Splunk, XSOAR, SpiderFoot, Maltego, Intel Owl, FortiSOAR, CISA Crossfeed and friends. Version pinned at **20250130** (date-versioned) on PyPI and in Kali (`0~20250130`, 489 KB, Kali page updated 2025-Dec-09); last repo push 2025-04-15.

## Registration, access & pricing

Free everywhere. No account on `dnstwist.it`, no key, no rate-limit headers observed. The hosted app's guardrails are hard-coded in `webapp/webapp.py` (defaults; the live deploy can override via env, and I only verified `DOMAIN_MAXLEN` firsthand):

| Guard | Default | Effect |
|---|---|---|
| `DOMAIN_MAXLEN` | **15** | SLD longer than 15 chars rejected 400. **Verified firsthand.** |
| `SESSION_MAX` | **10** | 10 concurrent *running* scans globally -> 500 `"Too many scan sessions - please retry in a minute"` |
| `SESSION_TTL` | **3600 s** | session (and its results) dropped from an in-process Python list. Not verified firsthand. |
| `THREADS` | `min(32, cores+4)` | scanner threads per session |
| `DOMAIN_BLOCKLIST` | `[]` | substring blocklist, empty in the public code |

No DB. Sessions live in a module-level list swept by a janitor thread, so a shared result URL dies within the hour and results are per-process.

## Features — complete inventory

**Permutation generation (the `Fuzzer`, 16 fuzzer names + `*original`).** Confirmed against `dnstwist.py`: `generate()` runs 14 fuzzers from a hardcoded default list (`addition, bitsquatting, cyrillic, homoglyph, hyphenation, insertion, omission, plural, repetition, replacement, subdomain, transposition, vowel-swap, dictionary`), then unconditionally also runs `tld-swap` and `various` unless `--fuzzers` narrows the set — 16 total, matching every row below. Default set fires all of these; `--fuzzers a,b,c` selects a subset.

| Fuzzer | Mechanic |
|---|---|
| `omission` | drop each char |
| `repetition` | double each char |
| `transposition` | swap each adjacent pair |
| `hyphenation` | insert `-` at each position |
| `subdomain` | insert `.` at each valid position (`corpbe.rry.com`) |
| `vowel-swap` | each vowel -> every other vowel |
| `plural` | insert `s`, or `es` after `s`/`x`/`z` |
| `addition` | append `0-9a-z`; also inject a char between hyphen-separated parts |
| `replacement` | swap char for a keyboard neighbour, across **qwerty + qwertz + azerty** |
| `insertion` | insert a keyboard neighbour before *and* after each char, 3 layouts |
| `bitsquatting` | XOR each char w/ masks 1…128, keep results landing in `[a-z0-9-]` (RAM bit-flip squatting) |
| `homoglyph` | confusable substitution over ASCII lookalikes (`rn`->`m`, `cl`->`d`, `vv`->`w`, `0`->`o`) **plus** a ~500-entry Unicode confusable table; single-char *and* 2-char windows; **applied twice** (`result1 ∪ mix(result1)`) so depth-2 swaps are covered |
| `cyrillic` | whole-name Latin->Cyrillic swap using a 21-char map (`а с е о р ѕ һ і ј…`); returns nothing if no char changed |
| `dictionary` | from `--dictionary FILE`: `word-domain`, `worddomain`, `domain-word`, `domainword`, plus hyphen-part substitution |
| `tld-swap` | from `--tld FILE`: same SLD, every TLD in the file |
| `various` | TLD-shape tricks: collapse `co.uk`->`uk`, fuse `domain+tld` as a new SLD, `domaintld.com`, `domain-tld.com`, subdomain fusion |

**IDN-aware homoglyph table (distinctive).** `glyphs_idn_by_tld` keys the Unicode confusable set **per TLD**, because most registries reject mixed-script labels. `.ad .cz .sk .uk .co.uk .nl .edu .us` map to an **empty** set (registry does not support IDN, so generating those permutations is wasted DNS traffic); `.jp .cn .tw` get their own sets; `.info` gets a Latin-Extended subset (`á ä å ą ć č é ę ł ń ó ö ø ś š …`). Everything else falls back to the full `glyphs_unicode`. This is the single cheapest accuracy win in the whole codebase.

**Bulk resolution.** A, AAAA, NS, MX for every permutation. Order is deliberate: **NS first**, NXDOMAIN short-circuits the rest, A/AAAA only if NS did not NXDOMAIN, MX only if NS answered. `--registered` / `--unregistered` filter output; `-a/--all` prints every record instead of the first.

**Enrichment (all opt-in flags; source-read, not run by me):**
- `-g/--geoip` — country only, geoip2 + `$GEOLITE2_MMDB`, falls back to GeoIP Legacy.
- `-w/--whois` — raw TCP/43. 16 TLDs hard-mapped (`whois.verisign-grs.com` etc.), else `whois.iana.org`, chases `refer:` recursively and **memoizes the discovered server per TLD** for the rest of the run. Extracts exactly two fields, `registrar` & `creation_date`, by regex, brute-forcing 9 datetime formats.
- `-b/--banners` — hand-rolled sockets: `HEAD / HTTP/1.1` to port 80 of the first A record w/ the permutation as `Host:`, returns the `Server:` header; SMTP 220 greeting from port 25. 2 s timeout, 1024-byte read. No 443, no TLS.
- `-m/--mxcheck` — **rogue-MX / mail-intercept probe.** Connects TCP/25 to the permutation's MX and walks `EHLO` / `MAIL FROM: randombob1986@<your-domain>` / `RCPT TO: randomalice1986@<permutation>`; all three 2xx -> `mx_spy: true`, printed as `SPYING-MX:`. The docstring itself warns some servers accept everything to defeat directory harvesting, so treat as a soft signal.
- `--lsh [ssdeep|tlsh]`, `--lsh-url`, `-p/--phash`, `--phash-url`, `--screenshots DIR` — the clone detector, below.

**Output & control:** `-f/--format cli|csv|json|list`, `-o/--output FILE`, `-t/--threads NUM`, `--nameservers LIST`, `--useragent STRING`, `-d/--dictionary FILE`, `--tld FILE`. Bundled dictionaries: `english.dict` / `french.dict` / `polish.dict` (phishing-campaign words: `auth account confirm login secure signin verify www…`), `common_tlds.dict` (~100), `abused_tlds.dict` (~22: `ga gq tk ml cf cc top xyz buzz…`). Tunable via env: `REQUEST_TIMEOUT_DNS` 2.5, `REQUEST_RETRIES_DNS` 2, `REQUEST_TIMEOUT_HTTP` 5, `REQUEST_TIMEOUT_SMTP` 5, `WEBDRIVER_PAGELOAD_TIMEOUT` 12.

**Hosted API (`dnstwist.it`, undocumented, no auth, no CORS — all verified firsthand):**

| Endpoint | Returns |
|---|---|
| `POST /api/scans` `{"url":"…"}` | **201** + `{id, domain, url, timestamp, total, complete, remaining, registered}`; starts the scan immediately |
| `GET /api/scans/<sid>` | same status object; poll it (the UI polls every 250 ms) |
| `GET /api/scans/<sid>/domains` | JSON array of **registered** hits: `{fuzzer, domain, dns_a[], dns_aaaa[], dns_ns[], dns_mx[], geoip}` |
| `GET /api/scans/<sid>/csv` | registered only, `text/csv`, `Content-Disposition: attachment` |
| `GET /api/scans/<sid>/json` | registered only, pretty-printed, sorted keys |
| `GET /api/scans/<sid>/list` | **all** permutations, newline-delimited plain text (5,678 for corpberry.com) |
| `POST /api/scans/<sid>/stop` | halts workers, clears the queue |

Hosted scans run **DNS + GeoIP only** — `webapp.py` sets `option_extdns` and `option_geoip` and nothing else. The clone detection, whois, banners and MX probe are **CLI-exclusive**. Hosted runs use a fixed 28-word phishing dictionary and a fixed 23-TLD swap list baked into `webapp.py`.

## Record types & query options supported

**Only A, AAAA, NS, MX.** No TXT, SOA, CNAME, CAA, PTR, SRV, DNSKEY/DS, no delegation trace, no DNSSEC validation, no reverse/PTR, no zone transfer, no passive DNS. Knobs: `--nameservers` accepts comma-separated IPv4 literals **or DoH URLs**, validated against `^https://[a-z0-9.-]{4,253}/dns-query$` (dnspython 2.x required). Resolver config: `use_edns(payload=1232)`, `rotate=True` across nameservers, `timeout=2.5`, `lifetime=2.5*2`. Without dnspython it degrades to `socket.getaddrinfo()` (A/AAAA only, no NS/MX). TTLs are never surfaced, raw responses are never shown, and results are collapsed to the **first** record unless `-a`.

## How it works

Server-side (or your-side, on CLI) throughout; nothing runs in the browser but jQuery rendering a table. `Scanner` is a `threading.Thread` subclass pulling permutations off a `queue.Queue`, `min(32, cores+4)` of them by default. Recursive resolution only, against the system resolver or whatever you pass to `--nameservers`; it never queries authoritative servers directly and does no caching or TTL handling of its own, which is exactly why the README warns "ensure your DNS server can handle thousands of requests within a short period". **Registration is inferred purely from DNS**, not WHOIS or RDAP: `Permutation.is_registered()` is literally `len(self) > 2`, i.e. "this dict grew a key beyond `fuzzer` and `domain`". Consequence worth knowing: a SERVFAIL writes the sentinel `['!ServFail']` into `dns_ns`, which makes the dict longer, which counts the domain as registered. The hosted UI renders that sentinel as 🚫.

## The distinctive mechanic: live clone detection

Everything above is table stakes; two dozen tools generate permutations. What makes dnstwist different is that `--lsh` closes the loop from "registered" to "actively impersonating you".

For each permutation that resolved, it fetches `full_uri(domain)` — carrying the **scheme and path** from whatever you passed in, so `dnstwist --lsh https://domain.name/owa/` hits `/owa/` on every single permutation — with cert verification **off**, 5 s timeout, `accept-encoding: gzip,identity`. If the body is between 64 and 1024 bytes it regex-extracts a `<meta … url=…>` refresh target and recurses, so meta-refresh cloaking does not hide the payload. Then it **normalizes the HTML**: collapse every whitespace run to one space, blank out the value of every `action=`/`src=`/`href=` attribute, rewrite `url(…)` to `url()`. That normalization is the load-bearing part. A clone's markup is near-identical to yours except for absolute URLs, asset hostnames and cache-busting query strings, all of which live in exactly those attributes; strip them and the fuzzy hash of a clone snaps to the original's.

Similarity then goes through **ssdeep** (`ssdeep.compare()`, 0-100) or **TLSH** (`--lsh tlsh`), with TLSH's distance mapped onto the same scale by `100 - min(diff, 300)/3` (confirmed against source: `int(100 - (min(tlsh.diff(...), 300)/3))`) so both algorithms print as one comparable `SSDEEP: 87%` / `TLSH: 72%` column. Correction: the "ssdeep" name is aspirational, not literal, for anyone installing from `requirements.txt` — the code tries `import ssdeep` (the native C-bound library) first, but that line is commented out in `requirements.txt`; the actually-installed dependency is **`ppdeep`** (a pure-Python ssdeep reimplementation), imported as `import ppdeep as ssdeep` and called through the identical `ssdeep.hash()`/`ssdeep.compare()` API. So a stock `pip install -r requirements.txt` run gets ppdeep's fuzzy hash, not the native library, even though every log line still says `SSDEEP:`. Two guards suppress the obvious false positives: the empty-hash sentinels (`'3::'`, `'TNULL'`) are discarded, and **if the permutation's post-redirect effective URL equals the original's, the hash is skipped entirely** — a defensively-registered typo that 301s to your real site is not a clone and should not score. `--lsh-url` lets you hash a *different* reference page than the one you are fuzzing.

`--phash` is the visual twin: headless Chromium via selenium at 1366×768, `--disable-blink-features=AutomationControlled` plus `excludeSwitches: enable-automation` and a UA override that strips the word "Headless", screenshot -> hash -> compare, `--screenshots DIR` dumps the PNGs as `{thread_id:08x}_{domain}.png`. Implementation detail that matters if you copy it: despite the class name, `pHash` is an **average hash**, not a DCT perceptual hash. Grayscale, LANCZOS-resize to 8×8, each of the 64 pixels compared to the frame mean -> 64-bit string; similarity is `int((1 + e^((64-hamming)/64) - e) × 100)` floored at 0, an exponential curve that rewards near-identical screenshots and collapses fast for moderate differences. 64 bits of aHash is cheap and crude, and it is a strict upgrade over nothing.

## Output & UX

CLI is one dense line per hit: `fuzzer` (blue, padded) · `domain` (punycode-decoded when the terminal is UTF-8) · then only the fields that exist, as `IP/Country`, `NS:`, `MX:` or `SPYING-MX:`, `HTTP:`, `SMTP:`, `REGISTRAR:`, `CREATED:`, `SSDEEP: n%`, `TLSH: n%`, `PHASH: n%`, or a bare `-`. Absent fields print nothing at all, which is why it stays readable at 200 rows.

The hosted UI is ~280 lines of hand-written HTML + jQuery, no build step, a base64 data-URI logo and favicon, one `<style>` block. Worth studying for exactly that reason. Flow: type domain -> `POST /api/scans` -> `<progress>` bar + "Processed 2440 of 5679" -> at 99% it switches the label to "Almost there…" -> on completion, "Scanned 5679 permutations. Found 5 registered: share it or download as CSV JSON". Results stream in: the poller re-fetches `/domains` **only when the `registered` counter increases**, so the table grows during the scan without refetching on every tick. The Scan button becomes a Stop button mid-scan. Result table is 4 columns (PERMUTATION w/ the fuzzer name as a grey `<sup>` underneath and a 🔗 to the live site, IP ADDRESS w/ country as `<sup>`, NAME SERVER, MAIL SERVER). "Share it" copies `location#<session-id>` to the clipboard and `window.onload` re-hydrates from the hash — a share link with no server-side state beyond the in-memory session, and therefore dead within `SESSION_TTL`. Empty state: "↖ You need to type in a domain name first". Error state: "Ups! Something went wrong…". No dark mode; one `@media (max-width: 800px)` rule shrinking fonts to 75%.

## Monetization, limits & abuse controls

None and none. No ads, no tiers, no upsell, no key, no per-IP rate limit in the code. Abuse control is entirely the input cap (15-char SLD), the global 10-concurrent-scan ceiling, the 1-hour session sweep, and an empty-by-default domain blocklist. `robots.txt` is Cloudflare's boilerplate content-signals file, not a crawl policy. Contrast the sibling project **dnstwister.report** (different author, hex-encoded REST API: `/api/fuzz/{hex}`, `/api/ip/{hex}`, `/api/mx/{hex}`, `/api/whois/{hex}`, `/api/parked/{hex}`), whose root now redirects to a commercial `dnstwister.com`.

## Ideas worth stealing

- **Port the fuzzers, not the scanner.** Every generator in the `Fuzzer` class is a pure string->set function with no I/O. `omission`, `transposition`, `repetition`, `hyphenation`, `subdomain`, `vowel-swap`, `plural`, `addition` are each 2-4 lines of Go. Put them in a domain package returning `[]Permutation{Fuzzer, Domain}` and the whole thing is unit-testable with table tests and zero network.
- **Per-TLD homoglyph gating.** Suppress Unicode confusables for registries that reject IDN (`.uk`, `.us`, `.nl`, `.cz`, `.sk`, `.edu`). Cuts thousands of guaranteed-NXDOMAIN lookups per scan for a `map[string][]rune` literal.
- **NS-first resolution as the registration oracle.** Query NS, treat NXDOMAIN as terminal, only then spend A/AAAA/MX. Roughly halves queries on a scan where most permutations are unregistered, which is all of them.
- **Stream results into the table as they land, not at the end.** Exactly the htmx sweet spot per CLAUDE.md rule #4: start the scan, return a fragment w/ `hx-trigger="every 500ms"` polling a `/scan/{id}/rows` endpoint that re-renders the table body. dnstwist's refinement is worth copying too: only re-render when the hit count actually changed, otherwise just move the progress bar.
- **The HTML normalization recipe, on its own.** Whitespace-collapse + blank `href`/`src`/`action` values + `url()` flattening, before any similarity comparison. Three regexes. Go has `ssdeep` and TLSH ports, but even a shingled-token Jaccard over normalized markup would carry most of the value.
- **The self-redirect false-positive guard.** Before scoring similarity, compare post-redirect effective URLs; equal means it is your own defensive registration, so show it as "redirects to you" instead of "98% match". One comparison, kills the most embarrassing class of false positive.
- **Label every row with the fuzzer that produced it.** `transposition`, `homoglyph`, `bitsquatting` as a grey sub-line under the domain. Free provenance, and it teaches the reader the attack class while they read the result.
- **Three-format export off one result set.** `cli` / `csv` / `json` / `list` are four methods on a `Format` type over the same `[]Permutation`. That is the CLAUDE.md rule #2 content-negotiation split with a plain-text list thrown in, and the list endpoint (permutations, no lookups) is the "passive mode" that costs nothing to serve.
- **Bounded input as the only rate limit.** A 15-char SLD cap, a global concurrent-scan ceiling and a TTL sweep is the entire abuse story for a tool that fires thousands of DNS queries per request. Cheap to implement, honest about what it protects.
- **`!ServFail` as a first-class result value** rather than an error or a blank, rendered as its own glyph. Same trichotomy instinct as the port-scanner report: resolved / NXDOMAIN / broken are three different answers.

## Gaps & what it does not do

No TXT/CAA/SOA/CNAME/DNSSEC, no delegation trace, no reverse DNS, no propagation check across resolvers, no monitoring or diffing between runs, no registrar/RDAP data on the hosted app, no certificate-transparency sweep (which would catch squats dnstwist's permutation grammar never generates), no per-permutation HTTP status on the hosted app, no scan history, no share link that outlives an hour. Registration is DNS-inferred, so a registered-but-unresolving domain reads as unregistered and a SERVFAIL reads as registered. The README is candid that exhaustive permutation is impossible for long names and that "attackers' imagination is unlimited". Also observed firsthand: both the original and a Cloudflare-proxied permutation return Cloudflare anycast IPs (`188.114.96.3` for corpberry.com), so the A-record column says nothing about where a suspect site is actually hosted.

## Verified firsthand vs inferred

**Verified (curl/dig, 2026-09-15 and re-run 2026-09-16):** hosted app returns 200 and serves the repo's `webapp.html`; the six API endpoints (`/api/scans`, `/api/scans/<sid>`, `/domains`, `/csv`, `/json`, `/list`, `/stop`), their status codes, content types, `Content-Disposition` headers and payload shapes, confirmed on two independent scans a day apart; a complete 5,679-permutation scan of corpberry.com w/ timings and 5 (then 3, mid-poll on a second, deliberately-stopped scan) registered hits; the 15-char `DOMAIN_MAXLEN` cap and its exact error strings, reproduced twice; the three 400 error bodies; `/list` returning all 5,678 permutations vs `/domains`, `/csv`, `/json` returning registered only; **absence of any `Access-Control-Allow-Origin` header**, reproduced twice; `POST /stop` returning 200; Cloudflare fronting + `dnstwist.it` NS at Cloudflare; PyPI version `20250130`; Kali package `0~20250130`, 489 KB, page dated 2025-Dec-09; repo star (5,738) / fork (851) / license (Apache-2.0) / last-push (2025-04-15) metadata via the GitHub API; `dnstwister.report` -> `dnstwister.com` 301 redirect; Homebrew formula version `20250130`; AUR listing of `dnstwist` + `dnstwist-git` (both user-maintained, confirming this is AUR packaging, not an official Arch repo).

**Source-read but not executed:** every CLI flag and its help text, all 15 fuzzer method implementations, the glyph and keyboard tables, LSH/pHash/whois/banner/mxcheck logic and formulas, env-tunable timeouts, `SESSION_TTL`/`SESSION_MAX`/`THREADS` defaults. All of the above were additionally cross-checked line-by-line against the live `dnstwist.py`/`webapp.py` source on the re-verification pass and matched the report's descriptions — but that is still reading code, not running it. I did not install dnstwist, so **no clone-detection, screenshot, whois, banner or MX-intercept behaviour was observed running**; those sections describe code read in `dnstwist.py` at `master`. The live `dnstwist.it` deploy may override any env-configurable default; only `DOMAIN_MAXLEN` was confirmed against the running service.

**Secondhand:** the integrations list (Splunk/XSOAR/Maltego/etc.) is the README's own claim — confirmed present verbatim in `docs/README.md` (19 products total, of which the report names 7), but still just the README's self-description, not independent confirmation that each product actually embeds dnstwist. Comparisons to URLCrazy/URLInsane/DNSRazzle come from search results, not from running those tools.

## Open source / reusable

`github.com/elceef/dnstwist`, **Apache-2.0**, single-file `dnstwist.py` w/ every dependency optional and guarded by `try: import`. Directly liftable into Go: the `Fuzzer` class (all 15 generators + `glyphs_ascii` + `glyphs_unicode` + `glyphs_idn_by_tld` + the three keyboard layouts + `latin_to_cyrillic`), the `_normalize()` HTML recipe, the TLSH->percentage mapping, the aHash similarity curve, the per-TLD whois server map, and the five bundled `.dict` files. The hosted app (`webapp/webapp.py` + `webapp.html`, 209 + 277 lines, both counts re-verified by `wc -l` on the raw files 2026-09-16) is a complete, readable model of "long-running job + poll + stream partial results + export" with no framework and no build step. Kali/Debian packaging means `apt install dnstwist` is a one-line way to diff a Go port's permutation output against the reference: `dnstwist --format list example.com | sort` vs your own.

## Sources

- [elceef/dnstwist — repository](https://github.com/elceef/dnstwist)
- [dnstwist README (docs/README.md, raw)](https://raw.githubusercontent.com/elceef/dnstwist/master/docs/README.md)
- [dnstwist.py source — fuzzers, Scanner, LSH/pHash, whois, CLI flags](https://raw.githubusercontent.com/elceef/dnstwist/master/dnstwist.py)
- [webapp/webapp.py — hosted API routes, SESSION_MAX / SESSION_TTL / DOMAIN_MAXLEN](https://raw.githubusercontent.com/elceef/dnstwist/master/webapp/webapp.py)
- [webapp/webapp.html — hosted UI, polling and export links](https://raw.githubusercontent.com/elceef/dnstwist/master/webapp/webapp.html)
- [dnstwist.it — hosted service](https://dnstwist.it)
- [Kali Linux tools: dnstwist (packaged version 0~20250130)](https://www.kali.org/tools/dnstwist/)
- [PyPI: dnstwist 20250130](https://pypi.org/project/dnstwist/)
- [requirements.txt — ppdeep/py-tlsh/geoip2/dnspython dependency pins](https://raw.githubusercontent.com/elceef/dnstwist/master/requirements.txt)
- [GitHub REST API: elceef/dnstwist repo metadata (stars/forks/license/pushed_at)](https://api.github.com/repos/elceef/dnstwist)
- [AUR RPC search: dnstwist packages](https://aur.archlinux.org/rpc/v5/search/dnstwist)
- [Homebrew formulae API: dnstwist](https://formulae.brew.sh/api/formula/dnstwist.json)
- [dnstwister.report — redirects to dnstwister.com (confirmed via curl -I, 2026-09-16)](https://dnstwister.report/)
- [dnstwister/dnstwister — separate "permutation as a service" project](https://github.com/dnstwister/dnstwister)
- [Zeltser: Generating domain name variations used in phishing attacks](https://zeltser.com/domain-name-variations-in-phishing)
- [rangertaha/urlinsane — comparable permutation engine, 19 algorithms](https://github.com/rangertaha/urlinsane)
- [Detect FYI: Detecting phishing attempts with dnstwist](https://detect.fyi/detecting-phishing-attempts-with-dnstwist-37c426b3bbb8)
