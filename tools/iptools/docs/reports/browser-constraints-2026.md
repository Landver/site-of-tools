# Browser constraints for an HTTPS-hosted client-side scanner (2026)
> The make-or-break feasibility rules that decide what a JavaScript port scanner served from `https://ip.corpberry.com` can and cannot actually probe in 2025-2026 browsers.

## Overview

This report is not about a competitor tool. It documents the **browser platform limits** that govern any client-side (in-browser JS) port scanner shipped from a **public HTTPS origin**. Four independent mechanisms stack on top of each other, and a scan target must clear *all* of them:

1. **Mixed content** blocking (HTTPS page → `http://` / `ws://` target).
2. **Local Network Access (LNA)** — Chrome's successor to Private Network Access (PNA): a permission prompt gating public→private/loopback requests.
3. The **blocked "bad ports" list** (`ERR_UNSAFE_PORT`) — a few dozen ports `fetch`/WebSocket flatly refuse.
4. **WebRTC mDNS obfuscation** — you can no longer read the visitor's real LAN IP to auto-target their subnet.

Plus a helper rule: **loopback/localhost is treated as a "potentially trustworthy" secure context**, which is the single exception that keeps a localhost scanner viable at all.

Bottom line up front: in 2026 a public HTTPS page can do a **best-effort reachability probe of the visitor's own loopback and (with a permission prompt, Chrome only) their LAN** over HTTP(S)/WS(S) high-level protocols, on non-blocked ports, reading only **connect/timing signal (open vs refused vs filtered)** — never response bodies, banners, or versions. It cannot do a raw TCP/SYN scan, cannot scan arbitrary remote internet hosts meaningfully, and behaves very differently across Chrome / Firefox / Safari.

## Port scanning / network probing — how it works (constraint by constraint)

### 1. Mixed content: the first gate

An HTTPS page loading an `http://` or `ws://` subresource is "mixed content." Modern browsers **block active mixed content** (fetch, XHR, WebSocket, scripts) outright. ([MDN: Mixed content](https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content))

The load-bearing exception: **loopback is exempt.**
- **Chrome** allows mixed content to `http://127.0.0.1/` and `http://localhost/`.
- **Firefox** allows it to `http://127.0.0.1/` (FF55+) and to `http://localhost/` + `http://*.localhost/` (FF84+).
- **Safari allows *no* mixed content at all — not even loopback.** ([MDN: Mixed content](https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content))

Consequence: `fetch("http://localhost:PORT")` from `https://ip.corpberry.com` is permitted in Chrome & Firefox, but is a hard no in Safari.

For **private-IP literals** (`192.168.x.x`) and `.local` names, mixed content is *not* auto-relaxed. It becomes reachable only when **LNA permission is granted** (Chrome), or if you set the request's `targetAddressSpace` (see below). ([MDN: Local network access](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Local_network_access))

`ws://` from an HTTPS page is mixed content too and is blocked; you must use `wss://` — but a local device rarely has a valid public cert, so a `wss://192.168.x.x` handshake fails cert validation anyway. Firefox currently lets **WebSockets bypass** its LNA prefs (`network.lna.websocket.enabled` defaults off). ([Mozilla bug 1996551](https://bugzilla.mozilla.org/show_bug.cgi?id=1996551))

### 2. Private Network Access → Local Network Access (the permission prompt)

This is the biggest 2025-2026 change. **PNA was put on hold and replaced by Local Network Access (LNA).** ([Chrome for Developers: New permission prompt for Local Network Access](https://developer.chrome.com/blog/local-network-access))

**Old PNA model** (for context): starting Chrome 94, requests from a public site to a private IP required a **CORS preflight** carrying `Access-Control-Request-Private-Network: true`, answered by `Access-Control-Allow-Private-Network: true` from the device, with a `targetAddressSpace: "private"` fetch annotation. The non-secure-context deprecation trial kept getting extended (through Chrome 132, ~Feb 4 2025) and the effort stalled — local devices can't easily serve the required headers or HTTPS. ([Chrome for Developers: PNA permission prompt OT ending](https://developer.chrome.com/blog/pna-permission-prompt-ot-end))

**New LNA model:**
- **Chrome 138**: opt-in testing via `chrome://flags/#local-network-access-check` ("Enabled (Blocking)").
- **Chrome 142** (launched ~28 Oct 2025): the **Local Network Access permission prompt** ships. ([Chrome blog](https://developer.chrome.com/blog/local-network-access); [Beyond Identity: Managing the Chrome v141 LNA prompt](https://docs.beyondidentity.com/docs/resources/announcements/chrome-browser))
- **What it gates:** any request from the **public** network to a **local** or **loopback** destination:
  - Local: `192.168.0.0/16`, `169.254.0.0/16` (link-local), `fc00::/7` (IPv6 ULA), `fe80::/10` (IPv6 link-local), plus IPv4-mapped IPv6 to those.
  - Loopback: `127.0.0.0/8`, `::1/128`.
- **The prompt** reads roughly: *"Look for and connect to any device on your local network."* The user must click Allow before the request succeeds.
- **Requires a secure context (HTTPS)** — which `https://ip.corpberry.com` is. Non-secure origins fail all such requests. ([MDN: Local network access](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Local_network_access))
- **What triggers it now:** `fetch()`, subresource loads, subframe navigation. WebSockets/WebTransport/WebRTC were *not* covered at launch, though [WebSocket support is being added](https://groups.google.com/a/chromium.org/g/blink-dev/c/4gx2y5jPGbU). ([Chrome blog](https://developer.chrome.com/blog/local-network-access))
- **`targetAddressSpace`**: annotate a request as `"local"` or `"loopback"` to declare intent and exempt it from mixed-content checks, e.g. `new Request("http://localhost:8888", { targetAddressSpace: "loopback" })`. ([MDN: Local network access](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Local_network_access))

**Cross-browser status (critical):** LNA/PNA is essentially a **Chromium feature**. Firefox has only experimental `network.lna.*` prefs (WebSockets bypass by default). Safari has no documented LNA/PNA implementation and additionally blocks all loopback mixed content. So the scanner's behavior forks hard by browser. ([Mozilla bug 1996551](https://bugzilla.mozilla.org/show_bug.cgi?id=1996551); [Chromium blink-dev Intent to Ship: LNA](https://groups.google.com/a/chromium.org/g/blink-dev/c/cwu_RUmBpzY))

### 3. Blocked "bad ports" (`ERR_UNSAFE_PORT`)

All major browsers refuse to open a `fetch`/XHR/WebSocket connection to a set of "bad ports" (protocol-confusion protection). The request returns a **network error** — you can't probe these ports at all. The authoritative list is the WHATWG Fetch "bad port" set (browser source varies slightly). ([WHATWG Fetch: port blocking](https://fetch.spec.whatwg.org/#port-blocking); [WHATWG issue #1189](https://github.com/whatwg/fetch/issues/1189))

Blocked ports (verified across the Fetch spec + Chromium reproductions):

`1 (tcpmux), 7 (echo), 9 (discard), 11 (systat), 13 (daytime), 15 (netstat), 17 (qotd), 19 (chargen), 20 (ftp-data), 21 (ftp), 22 (ssh), 23 (telnet), 25 (smtp), 37 (time), 42 (name), 43 (nicname), 53 (domain), 69 (tftp), 77 (rje), 79 (finger), 87 (link), 95 (supdup), 101 (hostname), 102 (iso-tsap), 103 (gppitnp), 104 (acr-nema), 109 (pop2), 110 (pop3), 111 (sunrpc), 113 (auth), 115 (sftp), 117 (uucp-path), 119 (nntp), 123 (ntp), 135 (epmap), 137 (netbios-ns), 139 (netbios-ssn), 143 (imap), 161 (snmp), 179 (bgp), 389 (ldap), 427 (svrloc), 465 (submissions), 512 (exec), 513 (login), 514 (shell), 515 (printer), 526 (tempo), 530 (courier), 531 (chat), 532 (netnews), 540 (uucp), 548 (afp), 554 (rtsp), 556 (remotefs), 563 (nntps), 587 (submission), 601 (syslog-conn), 636 (ldaps), 989 (ftps-data), 990 (ftps), 993 (imaps), 995 (pop3s), 1719 (h323gatestat), 1720 (h323hostcall), 1723 (pptp), 2049 (nfs), 3659 (apple-sasl), 4045 (lockd), 4190 (sieve), 5060 (sip), 5061 (sips), 6000 (X11), 6566 (sane-port), 6665-6669 (IRC), 6697 (IRC+TLS), 10080 (amanda)`

Sources for the enumerated list: [WHATWG Fetch spec](https://fetch.spec.whatwg.org/#port-blocking), search-corroborated reproductions ([Medium: Unsafe ports considered by Chrome](https://dheeruthedeployer.medium.com/unsafe-ports-considered-by-chrome-6f447b7e4714); [EventSourcingDB: The Port 6000 Mystery](https://docs.eventsourcingdb.io/blog/2025/10/30/the-port-6000-mystery/)). The list grows over time (recent additions include SIP 5060/5061 and the IRC/X11 range), so treat it as "≈dozens, re-check the spec." ([WHATWG PR #1109](https://github.com/whatwg/fetch/pull/1109))

Note what is **NOT** blocked and therefore probe-able: common dev/service ports like `80, 443, 3000, 3306, 5000, 5432, 6379, 8000, 8080, 8443, 9200, 27017` are all absent from the bad-port list.

### 4. WebRTC mDNS obfuscation (no more LAN IP discovery)

Since Chrome M73 (2019), WebRTC **host ICE candidates are obfuscated** as a random UUID `.local` mDNS hostname instead of the literal `192.168.x.x`. This is now standard in Chrome, Edge, Firefox, and Safari. ([discuss-webrtc PSA](https://groups.google.com/g/discuss-webrtc/c/6stQXi72BEU); [BlogGeek.me: mDNS and .local ICE candidates](https://bloggeek.me/psa-mdns-and-local-ice-candidates-are-coming/))

Implications for a scanner:
- You **cannot** reliably read the visitor's real private IP/subnet to auto-seed a LAN sweep. The old trick (create `RTCPeerConnection`, read candidate IPs, no permission needed) now yields `<uuid>.local`, not a scannable address. ([uBlock Origin wiki](https://github.com/uBlockOrigin/uBlock-issues/wiki/Prevent-WebRTC-from-leaking-local-IP-address))
- mDNS does **not** hide the public (server-reflexive) IP — but that's the visitor's own WAN IP, which the server already sees; useless for LAN targeting.
- A data-channel-only `RTCPeerConnection` still gathers candidates with no user prompt, but they're obfuscated, so this yields little for scanning.

### 5. Secure context / "potentially trustworthy" loopback (the enabling exception)

The W3C Secure Contexts algorithm classifies `127.0.0.0/8`, `::1/128`, and `localhost`/`*.localhost` as **"potentially trustworthy."** ([MDN: Secure contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts); [W3C Secure Contexts](https://www.w3.org/TR/secure-contexts/)) This is *why* Chrome/Firefox relax mixed content for loopback and why a localhost probe is even conceivable. It does **not** extend to `192.168.x.x` literals — those are not automatically trustworthy and remain gated by LNA/mixed-content.

### What "open / closed / filtered" actually means in a browser

There is **no raw socket**; you infer state from a high-level `fetch`/WebSocket/resource-load outcome and its **timing**:
- **Open (reachable):** connection completes fast — an opaque (`no-cors`) response resolves, or you get an HTTP-level/CORS error *after* connecting (the TCP/TLS handshake succeeded). Fast rejection with a CORS/type error = something is listening.
- **Closed (refused):** connection refused returns an error **quickly** (~immediate). Fast failure ≈ port closed.
- **Filtered:** the request **hangs until your own timeout** (no RST, dropped by firewall). Slow failure ≈ filtered.

This is a **timing heuristic**, not a truthful open/closed/filtered like Nmap. You never see banners or version strings (cross-origin responses are opaque; CORS blocks reading bodies). Browsers also add anti-fingerprinting noise, so it is best-effort.

## UX & result presentation

(Constraints report — the concrete UX ideas live in the sibling `client-side-scan-techniques.md` and the competitor reports. What the platform *forces* on the UX:)
- You **must** surface a "grant the permission prompt" explainer before any private-range scan in Chrome 142+, or the scan silently returns errors that look like "all filtered."
- You **must** feature-detect the browser and degrade: Safari = "loopback scanning not supported in this browser" (mixed content fully blocked); Firefox = partial; Chrome = full-ish with prompt.
- Result states should be labeled honestly as **inferred**: "responding / refused / no response (filtered or blocked)", not a confident "open/closed/filtered."

## Other tools & services offered

Not applicable — this target is the browser platform, not a product. (Monetization/product-idea research is in the competitor reports: `shodan-censys.md`, `yougetsignal.md`, `canyouseeme.md`, `online-nmap-frontends.md`, `browserleaks.md`.)

## Business / monetization model

Not applicable (platform constraints, no vendor).

## Ideas to steal (for OUR client-side port scanner)

- **Scope the tool as a "what's listening on *your* machine" localhost/dev-port scanner**, not a general internet port scanner. That is the only thing the browser genuinely supports, and it's a legitimately useful dev toy (detect a running Postgres 5432, Redis 6379, dev server 3000/8080, Docker 2375, etc.).
- **Ship a curated port list, not a range sweep.** Hardcode ~20-40 well-known dev/service ports, and **strip any bad-port** (drop 22, 25, 6000, etc. — they'll always error and confuse users). Tailwind-style literal list, no ranges.
- **Use `fetch(url, { mode: "no-cors" })` + `Promise.race` against a timeout** as the probe primitive; classify by fast-error vs slow-timeout vs resolve. Also try `new Image().src` and `<link>`/`<script>` onload/onerror for a second signal.
- **Detect and explain the Chrome 142 LNA prompt.** Only prompt for private-range scans; keep loopback default. Set `targetAddressSpace: "loopback"`/`"local"` on requests so future Chrome behaves and mixed content is exempted.
- **Feature-gate by browser.** Detect Safari → show "your browser blocks localhost probing from HTTPS; here's why" (great teaching moment, on-brand for an IP-tools site). This turns a limitation into content.
- **Present three honest states** — *responding* / *refused (fast)* / *no response (filtered/blocked)* — and say plainly it's timing-based inference, not a real socket scan. Under-promise.
- **Do the probing entirely client-side** (the whole point): the Go server at `ip.corpberry.com` serves static JS + the port list and never emits scan traffic, so corpberry can't get blocklisted. This is a *selling point* to state in the UI ("this scan runs in your browser; our server never touches your network").
- **Don't lean on WebRTC for LAN discovery** — mDNS killed it. If you want to scan the LAN, ask the user to type their subnet, then scan under the LNA prompt (Chrome only).

## Limitations & caveats

- **No raw sockets, ever.** Only HTTP(S)/WS(S). No SYN/ICMP/UDP, no arbitrary TCP. You cannot replicate Nmap.
- **No banner/version/service detection** cross-origin — CORS makes responses opaque; you get boolean-ish reachability only.
- **Safari is a hard stop** for loopback (no mixed content). A meaningful fraction of visitors will see nothing.
- **Chrome 142+ requires a user gesture + permission** for private/loopback destinations; a page can't scan silently. Good for ethics, but it means "click Allow or it looks broken."
- **Bad-port list is a moving target** and slightly browser-specific; re-verify against the WHATWG spec before shipping the port list.
- **Timing classification is noisy** — proxies, VPNs, slow CORS preflights, and browser anti-fingerprinting jitter all muddy open-vs-filtered. Newark-style keepalive/proxy quirks (see repo incident notes) could also skew timing.
- **`wss://` to a local device fails cert validation** — so WebSocket probing of LAN devices is largely a dead end from HTTPS.
- **Scanning arbitrary *remote* internet hosts** from the browser is effectively limited to "did port 80/443 answer an HTTP request," is unreliable, and looks abusive. Keep the tool pointed at the visitor's own machine/LAN.
- **Cross-origin remote probes still leave the *client's* IP in logs**, not the server's — fine for corpberry's blocklist concern, but worth noting for user privacy messaging.

## Sources

- [MDN — Mixed content](https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content)
- [MDN — Local network access](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Local_network_access)
- [MDN — Secure contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts)
- [Chrome for Developers — New permission prompt for Local Network Access](https://developer.chrome.com/blog/local-network-access)
- [Chrome for Developers — The PNA non-secure-contexts deprecation trial is ending](https://developer.chrome.com/blog/pna-permission-prompt-ot-end)
- [Chromium blink-dev — Intent to Ship: Local network access restrictions](https://groups.google.com/a/chromium.org/g/blink-dev/c/cwu_RUmBpzY)
- [Chromium blink-dev — Ready for Developer Testing: LNA restrictions for WebSockets](https://groups.google.com/a/chromium.org/g/blink-dev/c/4gx2y5jPGbU)
- [Beyond Identity — Managing the Chrome v141/142 Local Network Access prompt](https://docs.beyondidentity.com/docs/resources/announcements/chrome-browser)
- [WHATWG Fetch Standard — Port blocking / bad ports](https://fetch.spec.whatwg.org/#port-blocking)
- [WHATWG Fetch issue #1189 — shifting bad-port list to allowlist](https://github.com/whatwg/fetch/issues/1189)
- [WHATWG Fetch PR #1109 — add SIP ports 5060/5061](https://github.com/whatwg/fetch/pull/1109)
- [Medium — Unsafe ports considered by Chrome (list reproduction)](https://dheeruthedeployer.medium.com/unsafe-ports-considered-by-chrome-6f447b7e4714)
- [EventSourcingDB — The Port 6000 Mystery](https://docs.eventsourcingdb.io/blog/2025/10/30/the-port-6000-mystery/)
- [discuss-webrtc — PSA: Private IPs exposed by WebRTC changing to mDNS hostnames](https://groups.google.com/g/discuss-webrtc/c/6stQXi72BEU)
- [BlogGeek.me — PSA: mDNS and .local ICE candidates are coming](https://bloggeek.me/psa-mdns-and-local-ice-candidates-are-coming/)
- [uBlock Origin wiki — Prevent WebRTC from leaking local IP address](https://github.com/uBlockOrigin/uBlock-issues/wiki/Prevent-WebRTC-from-leaking-local-IP-address)
- [Mozilla bug 1996551 — WebSocket bypasses Local Network Access for localhost](https://bugzilla.mozilla.org/show_bug.cgi?id=1996551)
- [Mozilla bug 903966 — Don't block mixed content from localhost IP addresses](https://bugzilla.mozilla.org/show_bug.cgi?id=903966)
- [W3C — Secure Contexts (TR)](https://www.w3.org/TR/secure-contexts/)
