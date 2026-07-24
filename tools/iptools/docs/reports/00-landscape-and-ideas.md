# Port scanner landscape & ideas to steal
> Every well-known "port scanner" is server-side; our client-side, browser-only design is the differentiator, but the browser only lets us honestly probe the visitor's *own* localhost (and, with a Chrome prompt, their LAN), never arbitrary internet hosts.

This synthesizes ten research reports (see the sibling `.md` files). Each non-obvious
claim is tagged with its source slug. Where reports disagree, the conflict is called out.

## Comparison table

| Tool | Client or Server side | What it scans | Result states shown | Monetization | Standout idea |
|---|---|---|---|---|---|
| **GRC ShieldsUP!** (`grc-shieldsup`) | Server-side (GRC servers send inbound SYN to your public IP) | Your public IP: File Sharing set, Common Ports, All Service Ports (0-1055), custom ≤64 | **Stealth / Closed / Open** + a pass/fail **TruStealth** verdict | One paid product (SpinRite $89) funds free tools; no ads, no logging | Color-coded port grid + one plain-language verdict banner; clickable cells → port-info DB |
| **YouGetSignal** (`yougetsignal`) | Server-side (TCP connect from their server) | Your auto-detected public IP, one chosen port; "scan all common ports" runs a fixed ~20-item list | Binary **open / closed** (green/red flag) | Free, ad-supported personal site; no accounts | Quick-pick common-port chips with service labels; auto-fill visitor's own IP as target |
| **CanYouSeeMe.org** (`canyouseeme`) | Server-side (server connects back inbound to your IP) | Your public IP, one port | **Open vs Error+reason** (timed out / refused / no route) in one first-person sentence | Free, ad-supported; single-purpose | First-person plain-English result sentence that volunteers the interpretation; surfaces the *reason* |
| **BrowserLeaks** (`browserleaks`) | Client JS probes **+** passive server-side observation. **Does NOT port-scan** | Browser fingerprint/leak vectors (Canvas, WebGL, WebRTC, TLS, DNS, ~20+); WebRTC is the only network-address probe | leaked/not-leaked, supported/`n/a (no js)`, hash + **uniqueness %** | Free, no ads, no login; leverage is reputation/authority | Results-first layout; same feature serves HTML + JSON; `n/a (no js)` honesty marker |
| **Shodan / Censys** (`shodan-censys`) | Server-side, continuous internet-wide scan, cached & sold | Whole public IPv4 (+known IPv6): open ports, banners, product+version, CVEs, screenshots | Effectively **open/observed only** (cache of what was found; no live open/closed/filtered) | Freemium credits → gate valuable fields (CVEs, versions, `vuln`/`tag`) + volume; Shodan one-time $49 hook | "Services detected" labels + host-summary-header-then-port-cards; free no-key **InternetDB** per-IP JSON |
| **Web Nmap frontends** (`online-nmap-frontends`) | Server-side (real Nmap on their infra) | Any target, up to all 65,535 ports, UDP/OS/traceroute toggles | **open / closed / filtered** + service, version, OS guess | Freemium/credit tiers; "**payment functions as identification to minimize abuse**" | PORT/STATE/SERVICE table; Light-vs-Deep preset toggle; authorization checkbox on the form |
| **Nmap (concepts)** (`nmap-concepts`) | Server/host-side CLI, raw packets | Any host; `--top-ports` frequency-ranked sets | **Six honest states**: open, closed, filtered, unfiltered, open\|filtered, closed\|filtered | Open-source core; monetize adjacent (Npcap OEM license, the book) | The uncertainty states (`filtered`, `open\|filtered`) — name the "no signal" case, never guess "open"; top-ports ranking |
| **Privacy leak suites** (`privacy-leak-test-suites`) | Client JS + server + hybrid. **Do NOT port-scan** | IP/DNS/WebRTC/timezone/UA leak & mismatch checks | leaked/not-leaked, match/mismatch, whoer's **0-100% anonymity score** | Every one is a VPN's lead funnel (AirVPN, IVPN, Whoer VPN, vpn.ac) | Auto-run single-scroll dashboard with `Pending…` cards; one headline exposure score; fast/thorough mode toggle |
| **Client-side techniques** (`client-side-scan-techniques`) | **Client-side (our model)** | Visitor's own localhost/LAN via fetch/WebSocket/img timing; WebRTC finds the subnet | Inferred **open / closed / filtered** from promise-outcome + timing | Not a business; uses split into anti-fraud SaaS (ThreatMetrix), privacy defense, free dev tools | `no-cors fetch()` to `http://127.0.0.1:<port>` is the cleanest signal; calibrate-then-scan; eBay's ~14-port remote-access preset |
| **Browser constraints 2026** (`browser-constraints-2026`) | Platform limits (not a tool) | Defines what an HTTPS-origin JS scanner *may* reach | "responding / refused / no response" as **inferred** timing states | n/a | Four stacked gates (mixed content, LNA prompt, bad-ports list, mDNS); loopback secure-context exemption is what makes it viable at all |

## Ideas to steal

### UX
- **Auto-fill the visitor's own value as the default target**, near-zero-input first run (`yougetsignal`, `canyouseeme`). Our IP tool already knows the visitor IP; for a client-side scan the natural default target is `localhost`/`127.0.0.1`.
- **Quick-pick common-port chips with service labels** (`22 SSH · 80 HTTP · 443 HTTPS · 3306 MySQL · 6379 Redis · 27017 Mongo`), clicking fills/runs — removes "which number is that service?" friction (`yougetsignal`, `canyouseeme`). Keep the label list as Go data rendered server-side; they are literal class strings so Tailwind is fine.
- **Named scan-mode presets, not raw start/end port boxes** — a "Light vs Deep" headline toggle with granular options in an "Advanced" disclosure (`online-nmap-frontends`), and Zenmap-style named profiles like "Common dev ports / Remote access / Databases" (`nmap-concepts`).
- **Single-scroll, auto-run dashboard with `Pending…` placeholders** that fill in async (`privacy-leak-test-suites`, `browserleaks`) — fits progressive/batch rendering as probes complete.
- **Calibrate-then-scan progress step.** The fetch/WS timing methods need a known-closed control port for a baseline; show "calibrating…" so the numbers feel principled (`client-side-scan-techniques`).
- **Gate slow/side-effectful runs behind an explicit "Activate" button** rather than auto-firing (`privacy-leak-test-suites`); a full-range scan is slow and can trip defenses.
- **Show the underlying operation**, Zenmap-style ("attempting connection to host:port, timeout 2s") so results read as trustworthy (`nmap-concepts`).
- **Tool-suite cross-linking as default chrome** — persistent nav to sibling tools on every page; fits the one-binary/subdomain model (apex + IP tool + botcheck) (`yougetsignal`).

### Result presentation
- **A three-state (or more) honest vocabulary, shown as annotated color rows** — `open` / `closed` / `filtered`, mirroring how BrowserLeaks annotates each row inline (`browserleaks`). GRC's Green/Blue/Red port grid is the most legible port-status UX ever shipped (`grc-shieldsup`).
- **Borrow Nmap's uncertainty states — never guess "open."** Fast refuse → `closed`; successful connect → `open`; **timeout / no signal → `filtered` (or `open|filtered`), never `open`** (`nmap-concepts`). Use Nmap's own framing that a state "describes what the probe could observe," not ground truth.
- **First-person, plain-English result sentence that volunteers the interpretation**, and surfaces the *reason* (timeout = filter/firewall vs refused = nothing listening) (`canyouseeme`).
- **A single plain-language verdict banner above the technical detail** (GRC's TruStealth-style headline) (`grc-shieldsup`); the privacy-suite analog is one **headline exposure score** ("N services reachable") with green/amber/red banding and row-level color (`privacy-leak-test-suites`).
- **"Services detected" framing + host-summary header then port cards** — map each port to a service name, soft product guesses ("443 · HTTPS · nginx?" labeled "likely") from a static client-side table; NOT real `-sV` detection, which is impossible cross-origin (`shodan-censys`, `nmap-concepts`). The PORT / STATE / SERVICE table is the clean template (`online-nmap-frontends`).
- **Facet-style rollup line** above the list: "6 open · 3 filtered · top: HTTPS, SSH" (`shodan-censys`).
- **Clickable port cells → small port-info popover** ("445 = SMB, risky because…") — cheap, high perceived value, educational (`grc-shieldsup`).
- **Results-first layout; `n/a (no js)` honesty marker; short "Background" explainer + disclaimer on the same page** (SEO + legal + teaching) (`browserleaks`, `canyouseeme`).
- **Copyable text / JSON / CSV export** of results — professional for near-zero effort (`grc-shieldsup`, `online-nmap-frontends`).

### Features
- **`no-cors fetch()` to `http://127.0.0.1:<port>/` + `Promise.race` timeout** as the primary localhost probe; classify by fast-resolve vs fast-reject vs slow-timeout (`client-side-scan-techniques`, `browser-constraints-2026`).
- **WebSocket connect-timing as a fallback for non-HTTP ports** (RDP/VNC) — the proven eBay method; expect Chrome socket-pool throttling, so cap concurrency and use small batches (`client-side-scan-techniques`).
- **Curated frequency-ranked port set, not a 1-65535 sweep** — Top 10/100/1000 presets with honest coverage copy; browser probes are slow and throttled (`nmap-concepts`, `online-nmap-frontends`).
- **Ship the fraud-industry ~14-port "remote-access" preset** (3389 RDP, 5900-5903 VNC, etc.) as a fun, legible demo (`client-side-scan-techniques`).
- **Same feature → HTML + JSON** via content negotiation — build the scan once (domain returns structs), serve HTML to browsers/htmx and JSON to everyone else. Directly validates the ARCHITECTURE golden rule (`browserleaks`, `shodan-censys`).
- **WebRTC local-IP disclosure as a companion card** ("here's your local IP; now here's what's reachable") — the one BrowserLeaks/leak-suite vector adjacent to local-network recon (`browserleaks`, `privacy-leak-test-suites`). **Caveat: reliability now disputed — see conflict below.**
- **Optional InternetDB enrichment** (`https://internetdb.shodan.io/<ip>`, free, no key) to label services and surface known `vulns[]`/`tags[]` for the resolved public IP — label it "last known (Shodan), weekly-stale," and **verify browser CORS first** (a proxy would reintroduce server outbound traffic) (`shodan-censys`).
- **"Scan history of your own prior scans"** reusing the IP tool's existing Mongo lookup history; a lightweight "monitor this host (re-run + diff)" echoes Shodan Monitor / Ndiff without infrastructure (`shodan-censys`, `nmap-concepts`).

### Business/monetization
- **Free, reputation-first is the norm for this genre** — GRC (one paid product funds free tools), BrowserLeaks (authority, no ads), YouGetSignal/CanYouSeeMe (ad-supported hobby). A portfolio tool fits cleanly (`grc-shieldsup`, `browserleaks`, `yougetsignal`, `canyouseeme`).
- **The client-side design is itself the marketing hook.** State it in the UI: "this scan runs in *your* browser, from *your* connection — corpberry never sends the packets." None of the server-side tools can say this, and it is why we need no captcha/credit-gating/identity walls to protect our IP reputation (`online-nmap-frontends`, `browser-constraints-2026`).
- **Freemium *mechanics* translate to soft product tiers, not paywalls**: default fast top-100, gate a full deep scan behind an explicit opt-in; offer own-scan history; frame depth/freshness the way Shodan/Censys gate fields (`shodan-censys`).
- **Contextual, soft affiliate as an optional angle** — the leak-suite genre proves a free "you're exposed" diagnostic is an honest funnel to a paid privacy product (VPN/firewall). Keep it first-party-branded and non-fear-mongering if used at all (`privacy-leak-test-suites`).
- **Do NOT copy server-side monetization/abuse machinery.** Captchas, per-IP caps, "payment as identification," authorization checkboxes all exist because server-side scan traffic lands on the *operator's* IP; client-side inverts this entirely (`online-nmap-frontends`).

## Client-side feasibility verdict

Per `browser-constraints-2026`, a JS scanner served from `https://ip.corpberry.com` must clear **four stacked gates**, and the honest boundary is narrow.

**What it CAN probe:**
- **The visitor's own localhost / loopback** (`127.0.0.0/8`, `::1`, `localhost`, `*.localhost`) over **HTTP(S)/WS(S) only**, on **non-blocked ports**, reading **only connect/timing signal** — resolve vs fast-reject vs slow-timeout. This works because loopback is a "potentially trustworthy" secure context, the one mixed-content exemption that keeps a localhost scanner viable (`browser-constraints-2026`, `client-side-scan-techniques`).
- This is genuinely useful: detect a running Postgres 5432, Redis 6379, dev server 3000/8080, Mongo 27017, Docker 2375, etc. (`browser-constraints-2026`).

**What it CANNOT do:**
- **No raw TCP/SYN/UDP/ICMP scan** — no raw sockets in a browser, ever. Only high-level fetch/WebSocket/resource-load. Cannot replicate Nmap or GRC's SYN probing (`browser-constraints-2026`, `nmap-concepts`, `online-nmap-frontends`).
- **No banners, versions, or service detection** — cross-origin responses are opaque (CORS); you get boolean-ish reachability, never a product/version string (`browser-constraints-2026`, `shodan-censys`).
- **Cannot distinguish "stealth" from "closed,"** and cannot probe your own firewall *from outside* — that requires an inbound external probe (GRC/CanYouSeeMe's server-side model), the opposite direction from a browser's outbound-only connections (`grc-shieldsup`, `canyouseeme`).
- **open-non-HTTP vs filtered stays ambiguous** — the browser never hands JS the error type (`ECONNREFUSED` vs `EPROTO`); both a filtered port and an open-but-non-HTTP port look like a hang/timeout. State it as `open|filtered`, don't guess (`client-side-scan-techniques`, `nmap-concepts`).

**localhost vs LAN vs arbitrary public IP — three very different regimes:**
- **localhost/loopback:** viable in **Chrome & Firefox** (mixed content relaxed for loopback). **Safari is a hard stop** — it blocks *all* mixed content including loopback, so Safari visitors can probe nothing over HTTP from our HTTPS page (`browser-constraints-2026`).
- **Local LAN (`192.168.x.x`, `10.x`, `169.254.x`):** **not** auto-exempt from mixed content. Reachable essentially **Chrome-only**, and in **Chrome 142+ (shipped ~28 Oct 2025) only behind the Local Network Access permission prompt** ("Look for and connect to any device on your local network"), requiring a user gesture + HTTPS + a `targetAddressSpace: "local"` annotation. A page cannot scan the LAN silently; without the click it looks like "all filtered." Firefox has only experimental `network.lna.*` prefs; Safari has no LNA implementation (`browser-constraints-2026`, `client-side-scan-techniques`).
- **Arbitrary public internet IPs:** effectively **not meaningfully scannable** — limited to "did port 80/443 answer an HTTP request," unreliable, and looks abusive. Keep the tool pointed at the visitor's own machine/LAN (`browser-constraints-2026`).

**Blocked "bad ports":** browsers flatly refuse `fetch`/WS to a WHATWG Fetch bad-port set (dozens, and growing) — including **22 SSH, 25 SMTP, 53 DNS, 110 POP3, 143 IMAP, 137/139 NetBIOS, 389 LDAP, 5060 SIP, 6000 X11, 6665-6669 IRC**. These can never be probed; strip them from any preset or they error and confuse users. Note **445 SMB is NOT on the list** and is probe-able. **Common dev ports 80, 443, 3000, 3306, 5000, 5432, 6379, 8000, 8080, 8443, 9200, 27017 are NOT blocked** and are probe-able. Re-verify against the spec before shipping; the list moves (`browser-constraints-2026`).

## Recommended scope for corpberry's client-side port scanner
*(Options for the human to choose from, not commands.)*

**MVP candidate (smallest honest, useful thing):**
- A **"what's listening on your machine" localhost/dev-port scanner**: `no-cors fetch()` + timeout against a **curated ~20-40 non-blocked well-known dev/service port list** on `http://127.0.0.1:<port>` (`browser-constraints-2026`, `client-side-scan-techniques`).
- **Three honest inferred states** (responding / refused / no response), labeled plainly as timing-based inference, with service labels from a static table (`nmap-concepts`, `browserleaks`).
- **Results-first UI**: one headline summary line + a PORT/STATE/SERVICE color table, streaming in as probes complete (`browserleaks`, `online-nmap-frontends`).
- **Browser feature-gating**: Chrome/Firefox = works; **Safari = "your browser blocks localhost probing from HTTPS, here's why"** turned into a teaching moment (`browser-constraints-2026`).
- **HTML + JSON** from one domain service (`browserleaks`, ARCHITECTURE rule).
- **The "runs in your browser, we never send packets" trust line** front and center (`online-nmap-frontends`).

**Later / optional:**
- **LAN scan** behind the Chrome 142 LNA prompt, with a pre-prompt explainer and a user-typed subnet (don't rely on WebRTC to auto-discover it — see conflict) (`browser-constraints-2026`).
- **WebSocket-timing mode** for non-HTTP ports (RDP/VNC), with concurrency caps for throttling (`client-side-scan-techniques`).
- **Named presets** beyond localhost-common: "remote-access," "databases," a fun eBay-replica preset (`nmap-concepts`, `client-side-scan-techniques`).
- **InternetDB enrichment** of the resolved public IP (CORS-permitting), labeled weekly-stale (`shodan-censys`).
- **Own-scan history + "re-run & diff"** reusing existing Mongo (`shodan-censys`, `nmap-concepts`).
- **Explicit contrast link to GRC ShieldsUP!** ("want to test your firewall from the *outside*? that needs a server-side tool") — manages expectations, looks credible (`grc-shieldsup`).
- **Soft affiliate CTA** next to a relevant finding, if monetization is ever wanted (`privacy-leak-test-suites`).

## Open questions & risks

- **CONFLICT — WebRTC LAN-IP discovery reliability.** `client-side-scan-techniques` says WebRTC "still commonly reveals the private range" (mDNS obfuscation only "in some contexts"). But `browser-constraints-2026` and `privacy-leak-test-suites` both state mDNS `.local` obfuscation is now **standard across Chrome/Edge/Firefox/Safari (since Chrome M73, 2019)** and that you **cannot** reliably read the real private IP to auto-seed a LAN sweep. **Resolution leans toward the constraints report** (two reports agree, and it's the more recent/platform-focused one): do NOT design around auto-discovering the LAN subnet via WebRTC; have the user type it. Verify empirically before relying on it either way.
- **Browser fork is severe.** Safari = no localhost probing at all; Firefox = partial (LNA experimental, WebSockets bypass); Chrome = full-ish but LNA-prompted for private ranges. A meaningful fraction of visitors will see little or nothing. Decide whether that's acceptable or whether Safari gets a pure-explainer experience (`browser-constraints-2026`).
- **Bad-port list is a moving target** and slightly browser-specific — re-verify against the WHATWG Fetch spec at ship time; a preset that includes a newly-blocked port will silently misreport (`browser-constraints-2026`). *(Note: the constraints report lists 445 as NOT blocked; double-check, since SMB 445 is a common "interesting" port and users will expect it.)*
- **Timing classification is noisy** — proxies, VPNs, CORS preflight latency, `performance.now()` coarsening (~100 µs), Chrome socket-pool throttling, and the repo's own Newark keepalive/proxy quirk can all skew open-vs-filtered. Baseline calibration is mandatory, and accuracy should be under-promised (`client-side-scan-techniques`, `browser-constraints-2026`).
- **Ethics/optics.** This exact technique caused the 2020 eBay/ThreatMetrix backlash (Schneier, The Register, BleepingComputer). The tool must be unmistakably *scan-your-own-machine*, opt-in, and never fire silently on page load — the opposite of what eBay did (`client-side-scan-techniques`).
- **InternetDB CORS + licensing** unverified: free only for non-commercial use and may block browser cross-origin fetches; a server-side proxy would reintroduce the outbound-traffic problem the design avoids (`shodan-censys`).
- **Source-verification gaps flagged in the reports:** GRC's exact color mapping and button labels (server blocks automated fetch); YouGetSignal/CanYouSeeMe exact result strings and ad specifics; whoer.net score bands/pricing; Pentest-Tools trial terms; localportscan.com copy (403'd). Confirm against live runs before copying wording verbatim (`grc-shieldsup`, `yougetsignal`, `canyouseeme`, `privacy-leak-test-suites`, `online-nmap-frontends`, `client-side-scan-techniques`).
- **"Filtered vs closed" framing is contested** — security pros argue GRC overstates the value of "stealth" over "closed." Keep our copy accurate rather than adopting fear-based framing (`grc-shieldsup`, `privacy-leak-test-suites`).
