# Client-side port-scanning techniques & real-world use
> How JS in plain web page probes TCP ports on visitor's `localhost` / LAN w/ zero server involvement, which technique reliable, & 2020 "websites are scanning your ports" scandal that made it famous.

## Overview

Page from any origin can, w/ only client-side JS, attempt TCP connections to `127.0.0.1`, `localhost`, private LAN IPs (`192.168.x.x`, `10.x.x.x`). Browser won't hand page raw socket or response bytes of cross-origin service, but **leaks enough side-channel info** (connection succeed? how long till error? which error class?) to infer port state. Exactly the model our tool wants: scan runs in visitor's browser, so `ip.corpberry.com` server never emits outbound scan traffic.

Four building blocks:
- **(a) `fetch()` / `XHR`** — connect + measure success vs. error & timing.
- **(b) `WebSocket` (`ws://`)** — connect-timing side-channel; technique eBay shipped.
- **(c) `<img>` / `<script>` / `<link>` `onload`/`onerror` + timeout** — oldest trick; mostly *host-alive* detector.
- **(d) WebRTC** — not a port scanner; it's *local-IP discovery* primer telling you which LAN addresses to then scan w/ a-c.

Bottom line: for scanning visitor's **own localhost**, **`no-cors` `fetch()`** (promise-resolves = open HTTP service, fast reject = closed, timeout = filtered/non-HTTP) is cleanest signal; **WebSocket connect-timing** = battle-tested alternative that also reaches non-HTTP ports. WebRTC complements (find subnet), not substitute. All now gated by Chrome's Local Network Access permission prompt (Chrome 142, 2025-26).

## Port scanning / network probing — how it works

All four techniques **100% client-side**. None require origin server to make outbound connections.

### (a) fetch() / XHR — connection success + timing + error class

Issue `fetch("http://127.0.0.1:<port>/", {mode: "no-cors"})`. Same-origin policy hides *body*, but promise outcome & latency observable:

| Outcome | What it means |
|---|---|
| Promise **resolves** (opaque response) quickly | Port **open** and speaking HTTP |
| Promise **rejects** (`TypeError`/`Failed to fetch`) **fast** | Port **closed** — TCP `ECONNREFUSED` from the local stack |
| Promise **rejects/hangs slowly** → timeout | **Filtered**, no host, *or* open-but-non-HTTP (e.g. SSH) — ambiguous |

Key limitation browser deliberately imposes: **fetch never tells JS the specific error type** for cross-origin failure — every network failure = opaque `TypeError` for security. So can't read `ECONNREFUSED` vs `EPROTO` directly; distinguish states by **success-vs-failure of promise plus timing**. Mozilla's bug tracker confirms it works, by-design-adjacent: "the Fetch API allows timing-based port scanning" of localhost, open ports respond faster than closed ports which time out. Their PoC calibrates vs control: on macOS request known-closed port ~10,000× to build baseline, then test candidate ports 200-1,000× & flag ports whose timing exceeds ~30-70% of baseline as open; on Windows simpler rule — any port answering faster than 80% of 250 ms timeout = "open." Mozilla marked **WONTFIX**, deferring to Private Network Access spec to fix whole class rather than fetch specifically. ([bugzilla.mozilla.org 1827173](https://bugzilla.mozilla.org/show_bug.cgi?id=1827173))

Reliability: good for **open-vs-closed HTTP** on localhost (fast, little calibration); weaker at separating *filtered* from *open-non-HTTP* (both look like hang). XHR behaves same as fetch (same underlying stack); 2023 MSc thesis on browser-based scanning notes fetch & XHR functionally equivalent, recommends detecting client OS/browser & picking most effective API per victim. ([cs.ou.nl thesis PDF](https://cs.ou.nl/members/hugo/supervision/2023-bas.vd.louw-msc-thesis.pdf), [github.com/Basvdlouw/port-scanner](https://github.com/Basvdlouw/port-scanner))

### (b) WebSocket (ws://) — connect-timing side-channel (the eBay technique)

`var ws = new WebSocket("ws://127.0.0.1:<port>/")`. WebSockets only speak HTTP(S) for handshake, so unless target is actual WS server connection never completes — but *when* & *how* it fails leaks port state. nullsweep's teardown: "Ports that are open take longer in the browser, because there is a TLS negotiation step." Open port surfaces `onerror` after "Unexpected response code: 200/404" (service answered HTTP upgrade w/ non-101), whereas closed port fails fast w/ `net::ERR_CONNECTION_REFUSED`. ([nullsweep.com](https://nullsweep.com/why-is-this-website-port-scanning-me/))

van de Louw research frames it via `readyState`: new socket starts at `readyState 0`, how quickly it transitions on failure differs for open vs closed ports; WebSockets, not layered on Fetch stack, can expose slightly different error text/timing than fetch/XHR. As w/ fetch, modern browsers **suppress detailed error text from JS**, so reliable signal = **timing** (open = slower handshake, closed = immediate refuse), not message string. ([jlajara.gitlab.io JS-Recon writeup](https://jlajara.gitlab.io/web/2018/10/18/js-recon.html))

Reliability: shipped to millions of eBay visitors, so works in practice — but incolumitas found Chrome's **socket-pool throttling** makes WebSocket timing "very weird and inconsistent" after first few requests, & `performance.now()` coarsened to ~100 µs (Spectre/Meltdown mitigation), degrading fine timing. Reaches **non-HTTP ports** (VNC/RDP) that plain fetch can't cleanly classify, why fraud vendors chose it. ([incolumitas.com](https://incolumitas.com/2021/01/10/browser-based-port-scanning/))

### (c) <img> / <script> / <link> onload/onerror + timeout — the oldest, weakest trick

Inject `<img src="http://<ip>:<port>/">`. Never valid image so `onerror` always fires — but **latency of `onerror`** = signal: fast error = host answered (connection refused or fast non-image HTTP response), slow error/timeout = filtered or no host. defuse.ca's in-browser scanner uses **1500 ms cutoff**: fast = open OR closed-with-RST; slow = stealthed/filtered/host-down — author concedes "more correct to say that it scans for the presence of a host" than true port scanning, & it **fails on well-known-service ports** (SSH/22, POP/110) browsers refuse to connect to, defeated by NoScript's ABE, doesn't run in Tor Browser. ([defuse.ca](https://defuse.ca/in-browser-port-scanning.htm))

Two footnotes:
- `aabeling/portscan` uses img method but README states it **cannot scan localhost** — loopback returns "Failed to connect" *immediately* instead of timing out, so timing side-channel collapses; repo archived May 2021, even its own demo stopped working — sign approach rotted in modern browsers. ([github.com/aabeling/portscan](https://github.com/aabeling/portscan))
- **no-JavaScript** variant exists: Jeremiah Grossman (2006) showed `<link rel=stylesheet>` to intranet IP blocks Firefox's parser till request finishes; comparing generation-time to receive-time (< ~5 s ≈ host up) infers reachability w/ pure HTML + timing. Slow, fragile, needs many iframes for a range — historically important, not practical today. ([blog.jeremiahgrossman.com](https://blog.jeremiahgrossman.com/2006/11/browser-port-scanning-without.html))

### (d) WebRTC — local-IP discovery, not port scanning

WebRTC does **not** probe ports. Leaks **which local IPs visitor has**, so you know subnet to aim techniques a-c at. `new RTCPeerConnection()` + STUN server, listen for `icecandidate` events, read address out of each candidate string. ICE gathers **host candidates** (`192.168.x.x`, `10.x.x.x`, machine's real LAN IPs), **server-reflexive** (public IP per STUN), & relay candidates. ~15 lines of JS, **no permission prompt**, & can even reveal real IP behind VPN because STUN request goes out raw interface, not tunnel. ([whatismylocation.org](https://whatismylocation.org/blog/webrtc-leak-explained), [MDN Local network access](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Local_network_access))

Reliability: high for its actual job (subnet discovery); newer browsers add mDNS `.local` obfuscation of host candidates in some contexts, but technique still commonly reveals private range.

### What each technique can distinguish

| Technique | Open | Closed | Filtered/no-host | Reaches non-HTTP ports? | Localhost reliable? |
|---|---|---|---|---|---|
| `fetch`/XHR no-cors | resolve (fast) | reject fast (ECONNREFUSED, but type hidden) | slow reject / timeout | Weak (open-non-HTTP looks like timeout) | **Yes** |
| `WebSocket` timing | slow onerror (handshake) | fast onerror (refused) | timeout | **Yes** | Yes (throttling caveats) |
| `<img>`/`<link>` timeout | fast onerror | fast onerror | slow/timeout | n/a (host-alive only) | Poor (loopback errors instantly) |
| WebRTC | — finds LAN IPs, no port state — | | | | n/a |

## UX & result presentation

Ideas from tools & coverage rather than single product page:

- **Three-state result vocabulary, not two.** Real scanners report **open / closed / filtered (timeout)**; keep "filtered" distinct because our timeout bucket genuinely can't tell filtered from open-non-HTTP. Be honest about ambiguity in UI copy.
- **Service labels beside ports.** eBay/ThreatMetrix scandal legible precisely because reporters mapped ports to services (3389 → RDP, 5900-5903 → VNC, 7070 → RealAudio/remote access). Results table of `port → guessed service → state` reads far better than bare numbers. ([nullsweep.com](https://nullsweep.com/why-is-this-website-port-scanning-me/))
- **Preset port sets.** eBay probed curated ~14-port "remote-access" set, not 1-65535. Offer presets ("common web dev ports", "remote-access/RDP-VNC", "databases") plus custom list — browser scan of thousands of ports slow & gets throttled.
- **Calibrate-then-scan progress.** fetch/WS timing methods need control baseline (known-closed port) before judging candidates; show as "calibrating…" step so numbers feel principled.
- **localportscan.com** exists as live "scan open ports on localhost" consumer tool — good competitor to study for wording & layout, though page returned HTTP 403 to automated fetch so exact copy *(unverified here)*. ([localportscan.com](https://localportscan.com/))

## Other tools & services offered

Technique report, not single vendor, but notable "products" in this space:

- **ThreatMetrix (LexisNexis Risk Solutions)** — commercial fraud-detection SDK that shipped browser port scanning at scale (`check.js`), to detect malware/remote-access tools on shoppers' machines. *Monetized* form of technique. ([bleepingcomputer.com](https://www.bleepingcomputer.com/news/security/list-of-well-known-web-sites-that-port-scan-their-visitors/))
- **JS-Recon / jsrecon (Attack & Defense Labs)** — HTML5 JS network-reconnaissance tool (port scan + local IP detection) — offensive-research reference impl. ([andlabs.org/tools/jsrecon](http://www.andlabs.org/tools/jsrecon/jsrecon.html))
- **Open-source PoCs** — `SECUREFOREST/websocketScanner` (WS internal port scanner PoC), `Basvdlouw/port-scanner` (fetch+xhr+websocket, backed by MSc thesis), `aabeling/portscan` (img, archived). Good code to read for exact API usage.
- **Port Authority** (Firefox extension) — *defensive* product: blocks scripts attempting local port scans; nullsweep recommends it. ([nullsweep.com](https://nullsweep.com/why-is-this-website-port-scanning-me/))

## Business / monetization model

Technique itself isn't a business; uses cluster into three models:

1. **Anti-fraud SaaS (legitimate, paid).** ThreatMetrix/LexisNexis sell device-risk scoring; port scanning localhost for VNC/RDP/AnyDesk = signal shopper's machine may be remote-controlled by scammer. Banks & retailers (eBay, Citibank, TD Bank, Ameriprise, Chick-fil-A, plus ThreatMetrix customers Netflix, Target, Walmart, ESPN, Ticketmaster, etc.) embedded it in login/checkout flows. Sold as fraud-loss reduction. ([bleepingcomputer.com](https://www.bleepingcomputer.com/news/security/list-of-well-known-web-sites-that-port-scan-their-visitors/))
2. **Privacy-defense tooling.** Browser extensions, VPNs (WebRTC-leak protection), & NoScript/ABE monetize *blocking* same techniques.
3. **Free developer/diagnostic tools** (our lane). "Scan your own localhost" utilities = portfolio/lead-gen pieces, not revenue — exactly the framing that keeps client-side scanner ethical: visitor scans *their own* machine, consensually.

## Ideas to steal (for OUR client-side port scanner)

- **Default to `no-cors` `fetch()` against `http://127.0.0.1:<port>/` for localhost scan.** Cleanest binary-ish signal (promise resolve = open HTTP; fast reject = closed; timeout = filtered/non-HTTP), needs least timing calibration, works from our HTTPS page because **loopback = "potentially trustworthy" secure origin — HTTPS page reaching `http://localhost`/`127.0.0.1` is NOT blocked as mixed content**. ([MDN Mixed content](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Mixed_content), [bugzilla 1827173](https://bugzilla.mozilla.org/show_bug.cgi?id=1827173))
- **Add `WebSocket` timing mode as fallback / for non-HTTP ports.** Proven eBay method, reaches ports fetch can't classify (RDP/VNC). Expect to calibrate vs control port & fight Chrome socket-throttling — cap concurrency, small batches.
- **Use WebRTC once, up front, to discover LAN subnet**, then let user opt into scanning private IP (`192.168.x.x`) w/ same fetch/WS engine. Present as "we found your local IP is X, want to scan the subnet?"
- **Always run control/baseline probe** (port you expect closed) so open/closed thresholds relative, not hard-coded ms values — `performance.now()` coarsened to ~100 µs & absolute timings drift.
- **Report three states + service guesses + presets**, & copy fraud-industry port list as ready-made "remote-access" preset for a fun demo.
- **Single most reliable technique for localhost/LAN scan from a page: `no-cors fetch()` for HTTP services on loopback; `WebSocket` connect-timing where you need non-HTTP ports.** WebRTC = enumerator, `<img>` = legacy — don't lead with it.

## Limitations & caveats

- **Chrome/Edge Local Network Access permission prompt (the big one, 2025-26).** Chrome gates requests from public/HTTPS site to loopback (`127.0.0.0/8`, `::1`), private IPv4 (`192.168/16`, `169.254/16`), & IPv6 local ranges behind **user permission prompt**; opt-in testing landed in **Chrome 138** (`chrome://flags#local-network-access-check`), prompt becomes **on-by-default in Chrome 142**. `fetch({ targetAddressSpace: "local" | "loopback" })` = how page declares intent & clears mixed-content checks for private IPs. Notably, **WebSocket, WebTransport, & WebRTC local connections NOT yet gated** by this permission (per Chrome doc) — temporary edge for those techniques. For our tool arguably fine: user consents to scanning own machine, prompt reinforces that. ([developer.chrome.com/blog/local-network-access](https://developer.chrome.com/blog/local-network-access), [Microsoft Edge LNA docs](https://learn.microsoft.com/en-us/deployedge/ms-edge-local-network-access))
- **Browser-blocked / unsafe ports.** Browsers refuse connections to fixed list of "unsafe" ports (`ERR_UNSAFE_PORT` — e.g. 22, 25, 110, 143, & others), so those can't be probed via fetch/WS/img. Well-known-service ports = exactly where defuse.ca's scanner failed. ([SiteGround ERR_UNSAFE_PORT KB](https://www.siteground.com/kb/err-unsafe-port))
- **Mixed content only lenient for loopback.** `http://localhost` / `http://127.0.0.1` from our HTTPS page fine; **`http://192.168.x.x` is NOT** auto-exempt, needs `targetAddressSpace` + LNA permission. ([MDN Mixed content](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Mixed_content))
- **Error type hidden from JS.** No cross-origin API hands you `ECONNREFUSED` vs `EPROTO` vs timeout as distinct values — infer from promise resolve/reject + latency, why open-non-HTTP vs filtered stays ambiguous.
- **Timing noisy & defended.** `performance.now()` coarsened (~100 µs), Chrome socket-pool throttling makes WS timing "weird and inconsistent," results vary by OS — hence fraud scripts were **Windows-only** (eBay's scan didn't fire on Linux, even w/ spoofed Windows UA). ([incolumitas.com](https://incolumitas.com/2021/01/10/browser-based-port-scanning/), [blog.nem.ec](https://blog.nem.ec/2020/05/24/ebay-port-scanning/))
- **Slow at scale.** Browser concurrency limits + throttling make full 1-65535 sweeps impractical; presets & small batches mandatory.
- **Ethics/optics.** This exact technique caused 2020 public backlash (Schneier, The Register, Forbes, BleepingComputer, Threatpost). Our tool must be unmistakably *scan-your-own-machine*, opt-in, never fire silently on page load — opposite of what eBay did. ([schneier.com](https://www.schneier.com/blog/archives/2020/05/websites_conduc.html))

### Real-world case: the May 2020 "websites are scanning your ports" story

- Discovered independently by **Charlie Belmer (nullsweep)** & **Dan Nemec (nem.ec)**. eBay's sign-in page ran obfuscated `check.js` (re-obfuscated per load) from `src.ebay-us.com/fp/check.js`, launched via service-worker Blob URL. ([blog.nem.ec](https://blog.nem.ec/2020/05/24/ebay-port-scanning/))
- Technique: **WebSocket connect-timing** to `127.0.0.1`, scanning **~14 remote-access ports** — RDP **3389**; VNC **5900-5903**; & **5931 / 5939 / 5944 / 6039 / 6040 / 7070** & similar (Ammy Admin, WinVNC, X11, TrippLite, RealAudio). Results XOR-encrypted & exfiltrated to `*.online-metrix.net` (ThreatMetrix). Windows-only. ([nullsweep.com](https://nullsweep.com/why-is-this-website-port-scanning-me/))
- Not just eBay: BleepingComputer's list named Citibank, TD Bank, Ameriprise, Chick-fil-A, Lendup, BeachBody, Equifax IQ, TIAA-CREF, Sky, GumTree, WePay, plus other ThreatMetrix customers (Netflix, Target, Walmart, ESPN, Ticketmaster, TripAdvisor…). Purpose framed as anti-fraud (detect remote-control malware); vendor didn't comment on legality. ([bleepingcomputer.com](https://www.bleepingcomputer.com/news/security/list-of-well-known-web-sites-that-port-scan-their-visitors/))

## Sources
- nullsweep — Why is This Website Port Scanning me: https://nullsweep.com/why-is-this-website-port-scanning-me/
- nem.ec — eBay is port scanning visitors: https://blog.nem.ec/2020/05/24/ebay-port-scanning/
- BleepingComputer — List of well-known sites that port-scan visitors: https://www.bleepingcomputer.com/news/security/list-of-well-known-web-sites-that-port-scan-their-visitors/
- incolumitas — Browser based Port Scanning with JavaScript: https://incolumitas.com/2021/01/10/browser-based-port-scanning/
- Mozilla Bugzilla 1827173 — Fetch API allows timing-based port scanning: https://bugzilla.mozilla.org/show_bug.cgi?id=1827173
- defuse.ca — Port Scanning Local Network From a Web Browser: https://defuse.ca/in-browser-port-scanning.htm
- Jeremiah Grossman — Browser Port Scanning without JavaScript (2006): https://blog.jeremiahgrossman.com/2006/11/browser-port-scanning-without.html
- github.com/aabeling/portscan (img technique, archived): https://github.com/aabeling/portscan
- github.com/Basvdlouw/port-scanner + MSc thesis: https://github.com/Basvdlouw/port-scanner · https://cs.ou.nl/members/hugo/supervision/2023-bas.vd.louw-msc-thesis.pdf
- github.com/SECUREFOREST/websocketScanner: https://github.com/SECUREFOREST/websocketScanner
- JS-Recon (Attack & Defense Labs): http://www.andlabs.org/tools/jsrecon/jsrecon.html · writeup https://jlajara.gitlab.io/web/2018/10/18/js-recon.html
- Chrome for Developers — Local Network Access permission prompt: https://developer.chrome.com/blog/local-network-access
- Microsoft Edge — Local Network Access: https://learn.microsoft.com/en-us/deployedge/ms-edge-local-network-access
- MDN — Mixed content: https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Mixed_content
- MDN — Local network access: https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Local_network_access
- WebRTC local-IP leak explainer: https://whatismylocation.org/blog/webrtc-leak-explained
- Bruce Schneier — Websites Conducting Port Scans: https://www.schneier.com/blog/archives/2020/05/websites_conduc.html
- The Register — eBay port scans your PC: https://www.theregister.com/2020/05/26/ebay_port_scans_your_pc/
- localportscan.com (live consumer tool; page returned 403 to automated fetch — content unverified): https://localportscan.com/
