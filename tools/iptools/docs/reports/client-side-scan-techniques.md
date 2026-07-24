# Client-side port-scanning techniques & real-world use
> How JavaScript in a plain web page can probe TCP ports on a visitor's `localhost` / LAN with zero server involvement, which technique is actually reliable, and the 2020 "websites are scanning your ports" scandal that made it famous.

## Overview

A page served from any origin can, using only client-side JS, attempt TCP connections to `127.0.0.1`, `localhost`, and private LAN IPs (`192.168.x.x`, `10.x.x.x`). The browser will not hand the page the raw socket or the response bytes of a cross-origin service, but it **leaks enough side-channel information** (does the connection succeed? how long until it errors? which error class?) to infer port state. This is exactly the model our own tool wants: the scan runs in the visitor's browser, so `ip.corpberry.com`'s server never emits outbound scan traffic.

Four building blocks exist:
- **(a) `fetch()` / `XHR`** — connect + measure success vs. error and timing.
- **(b) `WebSocket` (`ws://`)** — connect-timing side-channel; the technique eBay shipped.
- **(c) `<img>` / `<script>` / `<link>` `onload`/`onerror` + timeout** — the oldest trick; mostly a *host-alive* detector.
- **(d) WebRTC** — not a port scanner at all; it's the *local-IP discovery* primer that tells you which LAN addresses to then scan with a-c.

Bottom line up front: for scanning a visitor's **own localhost**, a **`no-cors` `fetch()`** (promise-resolves = open HTTP service, fast reject = closed, timeout = filtered/non-HTTP) is the cleanest signal; **WebSocket connect-timing** is the battle-tested alternative that also reaches non-HTTP ports. WebRTC is a complement (find the subnet), not a substitute. All of it is now gated by Chrome's Local Network Access permission prompt (Chrome 142, 2025-26).

## Port scanning / network probing — how it works

All four techniques are **100% client-side**. None require the origin server to make outbound connections.

### (a) fetch() / XHR — connection success + timing + error class

Issue `fetch("http://127.0.0.1:<port>/", {mode: "no-cors"})`. Same-origin policy hides the *body*, but the promise outcome and its latency are observable:

| Outcome | What it means |
|---|---|
| Promise **resolves** (opaque response) quickly | Port **open** and speaking HTTP |
| Promise **rejects** (`TypeError`/`Failed to fetch`) **fast** | Port **closed** — TCP `ECONNREFUSED` from the local stack |
| Promise **rejects/hangs slowly** → timeout | **Filtered**, no host, *or* open-but-non-HTTP (e.g. SSH) — ambiguous |

The key limitation the browser deliberately imposes: **fetch never tells JS the specific error type** for a cross-origin failure — every network failure is an opaque `TypeError` for security reasons. So you cannot read `ECONNREFUSED` vs `EPROTO` directly; you distinguish states by **success-vs-failure of the promise plus timing**. Mozilla's own bug tracker confirms this works and is by-design-adjacent: "the Fetch API allows timing-based port scanning" of localhost, open ports respond faster than closed ports which time out. Their reported PoC calibrates against a control: on macOS request a known-closed port ~10,000× to build a baseline, then test candidate ports 200-1,000× and flag ports whose timing exceeds ~30-70% of baseline as open; on Windows a simpler rule — any port answering faster than 80% of a 250 ms timeout is "open." Mozilla marked it **WONTFIX**, deferring to the Private Network Access spec to fix the whole class rather than fetch specifically. ([bugzilla.mozilla.org 1827173](https://bugzilla.mozilla.org/show_bug.cgi?id=1827173))

Reliability: good for **open-vs-closed HTTP** on localhost (fast, needs little calibration); weaker at separating *filtered* from *open-non-HTTP* (both look like a hang). XHR behaves the same as fetch (same underlying stack); a 2023 MSc thesis on browser-based scanning notes fetch and XHR are functionally equivalent and recommends detecting the client OS/browser and picking the most effective API per victim. ([cs.ou.nl thesis PDF](https://cs.ou.nl/members/hugo/supervision/2023-bas.vd.louw-msc-thesis.pdf), [github.com/Basvdlouw/port-scanner](https://github.com/Basvdlouw/port-scanner))

### (b) WebSocket (ws://) — connect-timing side-channel (the eBay technique)

`var ws = new WebSocket("ws://127.0.0.1:<port>/")`. WebSockets only speak HTTP(S) for their handshake, so unless the target is an actual WS server the connection never completes — but *when* and *how* it fails leaks the port state. nullsweep's teardown: "Ports that are open take longer in the browser, because there is a TLS negotiation step." An open port surfaces something like an `onerror` after an "Unexpected response code: 200/404" (the service answered the HTTP upgrade with non-101), whereas a closed port fails fast with `net::ERR_CONNECTION_REFUSED`. ([nullsweep.com](https://nullsweep.com/why-is-this-website-port-scanning-me/))

The van de Louw research frames it via `readyState`: a new socket starts at `readyState 0`, and how quickly it transitions on failure differs for open vs closed ports; WebSockets, not being layered on the Fetch stack, can expose slightly different error text/timing than fetch/XHR. As with fetch, modern browsers **suppress the detailed error text from JS**, so the reliable signal is **timing** (open = slower handshake, closed = immediate refuse), not the message string. ([jlajara.gitlab.io JS-Recon writeup](https://jlajara.gitlab.io/web/2018/10/18/js-recon.html))

Reliability: this is the technique that shipped to millions of eBay visitors, so it works in practice — but incolumitas found Chrome's **socket-pool throttling** makes WebSocket timing "very weird and inconsistent" after the first few requests, and `performance.now()` is coarsened to ~100 µs (Spectre/Meltdown mitigation), degrading fine timing. It reaches **non-HTTP ports** (VNC/RDP) that a plain fetch can't cleanly classify, which is why fraud vendors chose it. ([incolumitas.com](https://incolumitas.com/2021/01/10/browser-based-port-scanning/))

### (c) <img> / <script> / <link> onload/onerror + timeout — the oldest, weakest trick

Inject `<img src="http://<ip>:<port>/">`. It will never be a valid image so `onerror` always fires — but the **latency of `onerror`** is the signal: a fast error means the host answered (connection refused or a fast non-image HTTP response), a slow error/timeout means filtered or no host. defuse.ca's in-browser scanner uses a **1500 ms cutoff**: fast = open OR closed-with-RST; slow = stealthed/filtered/host-down — the author concedes it's "more correct to say that it scans for the presence of a host" than true port scanning, and it **fails on well-known-service ports** (SSH/22, POP/110) that browsers refuse to connect to, is defeated by NoScript's ABE, and doesn't run in Tor Browser. ([defuse.ca](https://defuse.ca/in-browser-port-scanning.htm))

Two footnotes:
- `aabeling/portscan` uses the img method but its README states it **cannot scan localhost** — loopback returns "Failed to connect" *immediately* instead of timing out, so the timing side-channel collapses; the repo was archived May 2021 and even its own demo stopped working, a sign the approach rotted in modern browsers. ([github.com/aabeling/portscan](https://github.com/aabeling/portscan))
- A **no-JavaScript** variant exists: Jeremiah Grossman (2006) showed a `<link rel=stylesheet>` to an intranet IP blocks Firefox's parser until the request finishes; comparing generation-time to receive-time (< ~5 s ≈ host up) infers reachability with pure HTML + timing. Slow, fragile, needs many iframes for a range — historically important, not practical today. ([blog.jeremiahgrossman.com](https://blog.jeremiahgrossman.com/2006/11/browser-port-scanning-without.html))

### (d) WebRTC — local-IP discovery, not port scanning

WebRTC does **not** probe ports. It leaks **which local IPs the visitor has**, so you know the subnet to aim techniques a-c at. `new RTCPeerConnection()` + a STUN server, listen for `icecandidate` events, and read the address out of each candidate string. ICE gathers **host candidates** (`192.168.x.x`, `10.x.x.x`, the machine's real LAN IPs), **server-reflexive** (public IP per STUN), and relay candidates. ~15 lines of JS, **no permission prompt**, and it can even reveal the real IP behind a VPN because the STUN request goes out the raw interface, not the tunnel. ([whatismylocation.org](https://whatismylocation.org/blog/webrtc-leak-explained), [MDN Local network access](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Local_network_access))

Reliability: high for its actual job (subnet discovery); newer browsers add mDNS `.local` obfuscation of host candidates in some contexts, but the technique still commonly reveals the private range.

### What each technique can distinguish

| Technique | Open | Closed | Filtered/no-host | Reaches non-HTTP ports? | Localhost reliable? |
|---|---|---|---|---|---|
| `fetch`/XHR no-cors | resolve (fast) | reject fast (ECONNREFUSED, but type hidden) | slow reject / timeout | Weak (open-non-HTTP looks like timeout) | **Yes** |
| `WebSocket` timing | slow onerror (handshake) | fast onerror (refused) | timeout | **Yes** | Yes (throttling caveats) |
| `<img>`/`<link>` timeout | fast onerror | fast onerror | slow/timeout | n/a (host-alive only) | Poor (loopback errors instantly) |
| WebRTC | — finds LAN IPs, no port state — | | | | n/a |

## UX & result presentation

Ideas surfaced from the tools and coverage rather than a single product page:

- **Three-state result vocabulary, not two.** Real scanners report **open / closed / filtered (timeout)**; keep "filtered" distinct because our timeout bucket genuinely can't tell filtered from open-non-HTTP. Be honest about the ambiguity in the UI copy.
- **Service labels beside ports.** The eBay/ThreatMetrix scandal is legible precisely because reporters mapped ports to services (3389 → RDP, 5900-5903 → VNC, 7070 → RealAudio/remote access). A results table of `port → guessed service → state` reads far better than bare numbers. ([nullsweep.com](https://nullsweep.com/why-is-this-website-port-scanning-me/))
- **Preset port sets.** eBay probed a curated ~14-port "remote-access" set, not 1-65535. Offer presets ("common web dev ports", "remote-access/RDP-VNC", "databases") plus a custom list — a browser scan of thousands of ports is slow and gets throttled.
- **Calibrate-then-scan progress.** The fetch/WS timing methods need a control baseline (a known-closed port) before judging candidates; show that as a "calibrating…" step so the numbers feel principled.
- **localportscan.com** exists as a live "scan open ports on localhost" consumer tool — good competitor to study for wording and layout, though its page returned HTTP 403 to automated fetch so its exact copy is *(unverified here)*. ([localportscan.com](https://localportscan.com/))

## Other tools & services offered

This is a technique report, not a single vendor, but the notable "products" in this space:

- **ThreatMetrix (LexisNexis Risk Solutions)** — the commercial fraud-detection SDK that actually shipped browser port scanning at scale (`check.js`), to detect malware/remote-access tools on shoppers' machines. This is the *monetized* form of the technique. ([bleepingcomputer.com](https://www.bleepingcomputer.com/news/security/list-of-well-known-web-sites-that-port-scan-their-visitors/))
- **JS-Recon / jsrecon (Attack & Defense Labs)** — HTML5 JS network-reconnaissance tool (port scan + local IP detection) — an offensive-research reference implementation. ([andlabs.org/tools/jsrecon](http://www.andlabs.org/tools/jsrecon/jsrecon.html))
- **Open-source PoCs** — `SECUREFOREST/websocketScanner` (WS internal port scanner PoC), `Basvdlouw/port-scanner` (fetch+xhr+websocket, backed by an MSc thesis), `aabeling/portscan` (img, archived). Good code to read for exact API usage.
- **Port Authority** (Firefox extension) — the *defensive* product: blocks scripts that attempt local port scans; nullsweep recommends it. ([nullsweep.com](https://nullsweep.com/why-is-this-website-port-scanning-me/))

## Business / monetization model

The technique itself isn't a business; its uses cluster into three models:

1. **Anti-fraud SaaS (legitimate, paid).** ThreatMetrix/LexisNexis sell device-risk scoring; port scanning localhost for VNC/RDP/AnyDesk is a signal that a shopper's machine may be remote-controlled by a scammer. Banks and retailers (eBay, Citibank, TD Bank, Ameriprise, Chick-fil-A, plus ThreatMetrix customers Netflix, Target, Walmart, ESPN, Ticketmaster, etc.) embedded it in login/checkout flows. Sold as fraud-loss reduction. ([bleepingcomputer.com](https://www.bleepingcomputer.com/news/security/list-of-well-known-web-sites-that-port-scan-their-visitors/))
2. **Privacy-defense tooling.** Browser extensions, VPNs (WebRTC-leak protection), and NoScript/ABE monetize *blocking* the same techniques.
3. **Free developer/diagnostic tools** (our lane). "Scan your own localhost" utilities are portfolio/lead-gen pieces, not revenue — which is exactly the framing that keeps a client-side scanner ethical: the visitor scans *their own* machine, consensually.

## Ideas to steal (for OUR client-side port scanner)

- **Default to `no-cors` `fetch()` against `http://127.0.0.1:<port>/` for the localhost scan.** It's the cleanest binary-ish signal (promise resolve = open HTTP; fast reject = closed; timeout = filtered/non-HTTP), needs the least timing calibration, and works from our HTTPS page because **loopback is a "potentially trustworthy" secure origin — an HTTPS page reaching `http://localhost`/`127.0.0.1` is NOT blocked as mixed content**. ([MDN Mixed content](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Mixed_content), [bugzilla 1827173](https://bugzilla.mozilla.org/show_bug.cgi?id=1827173))
- **Add a `WebSocket` timing mode as fallback / for non-HTTP ports.** It's the proven eBay method and reaches ports a fetch can't classify (RDP/VNC). Expect to calibrate against a control port and to fight Chrome socket-throttling — cap concurrency, small batches.
- **Use WebRTC once, up front, to discover the LAN subnet**, then let the user opt into scanning a private IP (`192.168.x.x`) with the same fetch/WS engine. Present it as "we found your local IP is X, want to scan the subnet?"
- **Always run a control/baseline probe** (a port you expect closed) so open/closed thresholds are relative, not hard-coded ms values — `performance.now()` is coarsened to ~100 µs and absolute timings drift.
- **Report three states + service guesses + presets**, and copy the fraud-industry port list as a ready-made "remote-access" preset for a fun demo.
- **Single most reliable technique for a localhost/LAN scan from a page: `no-cors fetch()` for HTTP services on loopback; `WebSocket` connect-timing where you need non-HTTP ports.** WebRTC is the enumerator, `<img>` is legacy — don't lead with it.

## Limitations & caveats

- **Chrome/Edge Local Network Access permission prompt (the big one, 2025-26).** Chrome gates requests from a public/HTTPS site to loopback (`127.0.0.0/8`, `::1`), private IPv4 (`192.168/16`, `169.254/16`), and IPv6 local ranges behind a **user permission prompt**; opt-in testing landed in **Chrome 138** (`chrome://flags#local-network-access-check`), and the prompt becomes **on-by-default in Chrome 142**. `fetch({ targetAddressSpace: "local" | "loopback" })` is how a page declares intent and clears mixed-content checks for private IPs. Notably, **WebSocket, WebTransport, and WebRTC local connections are NOT yet gated** by this permission (as of the Chrome doc) — a temporary edge for those techniques. For our tool this is arguably fine: the user consents to scanning their own machine, and the prompt reinforces that. ([developer.chrome.com/blog/local-network-access](https://developer.chrome.com/blog/local-network-access), [Microsoft Edge LNA docs](https://learn.microsoft.com/en-us/deployedge/ms-edge-local-network-access))
- **Browser-blocked / unsafe ports.** Browsers refuse connections to a fixed list of "unsafe" ports (`ERR_UNSAFE_PORT` — e.g. 22, 25, 110, 143, and others), so those simply can't be probed via fetch/WS/img. Well-known-service ports were exactly where defuse.ca's scanner failed. ([SiteGround ERR_UNSAFE_PORT KB](https://www.siteground.com/kb/err-unsafe-port))
- **Mixed content only lenient for loopback.** `http://localhost` / `http://127.0.0.1` from our HTTPS page is fine; **`http://192.168.x.x` is NOT** auto-exempt and needs `targetAddressSpace` + LNA permission. ([MDN Mixed content](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Mixed_content))
- **Error type is hidden from JS.** No cross-origin API hands you `ECONNREFUSED` vs `EPROTO` vs timeout as distinct values — you infer from promise resolve/reject + latency, which is why open-non-HTTP vs filtered stays ambiguous.
- **Timing is noisy and defended.** `performance.now()` coarsened (~100 µs), Chrome socket-pool throttling makes WS timing "weird and inconsistent," and results vary by OS — hence the fraud scripts were **Windows-only** (eBay's scan didn't fire on Linux, even with a spoofed Windows UA). ([incolumitas.com](https://incolumitas.com/2021/01/10/browser-based-port-scanning/), [blog.nem.ec](https://blog.nem.ec/2020/05/24/ebay-port-scanning/))
- **Slow at scale.** Browser concurrency limits + throttling make full 1-65535 sweeps impractical; presets and small batches are mandatory.
- **Ethics/optics.** This exact technique caused a 2020 public backlash (Schneier, The Register, Forbes, BleepingComputer, Threatpost). Our tool must be unmistakably *scan-your-own-machine*, opt-in, and never fire silently on page load — the opposite of what eBay did. ([schneier.com](https://www.schneier.com/blog/archives/2020/05/websites_conduc.html))

### Real-world case: the May 2020 "websites are scanning your ports" story

- Discovered independently by **Charlie Belmer (nullsweep)** and **Dan Nemec (nem.ec)**. eBay's sign-in page ran obfuscated `check.js` (re-obfuscated per load) from `src.ebay-us.com/fp/check.js`, launched via a service-worker Blob URL. ([blog.nem.ec](https://blog.nem.ec/2020/05/24/ebay-port-scanning/))
- Technique: **WebSocket connect-timing** to `127.0.0.1`, scanning **~14 remote-access ports** — RDP **3389**; VNC **5900-5903**; and **5931 / 5939 / 5944 / 6039 / 6040 / 7070** and similar (Ammy Admin, WinVNC, X11, TrippLite, RealAudio). Results were XOR-encrypted and exfiltrated to `*.online-metrix.net` (ThreatMetrix). Windows-only. ([nullsweep.com](https://nullsweep.com/why-is-this-website-port-scanning-me/))
- Not just eBay: BleepingComputer's list named Citibank, TD Bank, Ameriprise, Chick-fil-A, Lendup, BeachBody, Equifax IQ, TIAA-CREF, Sky, GumTree, WePay, plus other ThreatMetrix customers (Netflix, Target, Walmart, ESPN, Ticketmaster, TripAdvisor…). Purpose framed as anti-fraud (detect remote-control malware); the vendor didn't comment on legality. ([bleepingcomputer.com](https://www.bleepingcomputer.com/news/security/list-of-well-known-web-sites-that-port-scan-their-visitors/))

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
