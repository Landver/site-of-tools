# Browser constraints for an HTTPS-hosted client-side scanner (2026)
> Make-or-break feasibility rules deciding what a JavaScript port scanner served from `https://ip.corpberry.com` can & cannot probe in 2025-2026 browsers.

## Overview

Not about a competitor tool. Documents **browser platform limits** governing any client-side (in-browser JS) port scanner shipped from **public HTTPS origin**. Four independent mechanisms stack; scan target must clear *all*:

1. **Mixed content** blocking (HTTPS page → `http://` / `ws://` target).
2. **Local Network Access (LNA)** — Chrome's successor to Private Network Access (PNA): permission prompt gating public→private/loopback requests.
3. **Blocked "bad ports" list** (`ERR_UNSAFE_PORT`) — few dozen ports `fetch`/WebSocket flatly refuse.
4. **WebRTC mDNS obfuscation** — can no longer read visitor's real LAN IP to auto-target subnet.

Plus helper rule: **loopback/localhost treated as "potentially trustworthy" secure context** — single exception keeping localhost scanner viable at all.

Bottom line: in 2026 public HTTPS page can do **best-effort reachability probe of visitor's own loopback and (w/ permission prompt, Chrome only) their LAN** over HTTP(S)/WS(S) high-level protocols, on non-blocked ports, reading only **connect/timing signal (open vs refused vs filtered)** — never response bodies, banners, or versions. Cannot do raw TCP/SYN scan, cannot scan arbitrary remote internet hosts meaningfully, behaves very differently across Chrome / Firefox / Safari.

## Port scanning / network probing — how it works (constraint by constraint)

### 1. Mixed content: the first gate

HTTPS page loading `http://` or `ws://` subresource = "mixed content." Modern browsers **block active mixed content** (fetch, XHR, WebSocket, scripts) outright. ([MDN: Mixed content](https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content))

Load-bearing exception: **loopback is exempt.**
- **Chrome** allows mixed content to `http://127.0.0.1/` and `http://localhost/`.
- **Firefox** allows it to `http://127.0.0.1/` (FF55+) and `http://localhost/` + `http://*.localhost/` (FF84+).
- **Safari allows *no* mixed content at all — not even loopback.** ([MDN: Mixed content](https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content))

Consequence: `fetch("http://localhost:PORT")` from `https://ip.corpberry.com` permitted in Chrome & Firefox, hard no in Safari.

For **private-IP literals** (`192.168.x.x`) & `.local` names, mixed content *not* auto-relaxed. Reachable only when **LNA permission granted** (Chrome), or if you set request's `targetAddressSpace` (see below). ([MDN: Local network access](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Local_network_access))

`ws://` from HTTPS page is mixed content too & blocked; must use `wss://` — but local device rarely has valid public cert, so `wss://192.168.x.x` handshake fails cert validation anyway. Firefox currently lets **WebSockets bypass** its LNA prefs (`network.lna.websocket.enabled` defaults off). ([Mozilla bug 1996551](https://bugzilla.mozilla.org/show_bug.cgi?id=1996551))

### 2. Private Network Access → Local Network Access (the permission prompt)

Biggest 2025-2026 change. **PNA put on hold & replaced by Local Network Access (LNA).** ([Chrome for Developers: New permission prompt for Local Network Access](https://developer.chrome.com/blog/local-network-access))

**Old PNA model** (context): starting Chrome 94, requests from public site to private IP required **CORS preflight** carrying `Access-Control-Request-Private-Network: true`, answered by `Access-Control-Allow-Private-Network: true` from device, w/ `targetAddressSpace: "private"` fetch annotation. Non-secure-context deprecation trial kept getting extended (through Chrome 132, ~Feb 4 2025), effort stalled — local devices can't easily serve required headers or HTTPS. ([Chrome for Developers: PNA permission prompt OT ending](https://developer.chrome.com/blog/pna-permission-prompt-ot-end))

**New LNA model:**
- **Chrome 138**: opt-in testing via `chrome://flags/#local-network-access-check` ("Enabled (Blocking)").
- **Chrome 142** (launched ~28 Oct 2025): **Local Network Access permission prompt** ships. ([Chrome blog](https://developer.chrome.com/blog/local-network-access); [Beyond Identity: Managing the Chrome v141 LNA prompt](https://docs.beyondidentity.com/docs/resources/announcements/chrome-browser))
- **What it gates:** any request from **public** network to **local** or **loopback** destination:
  - Local: `192.168.0.0/16`, `169.254.0.0/16` (link-local), `fc00::/7` (IPv6 ULA), `fe80::/10` (IPv6 link-local), plus IPv4-mapped IPv6 to those.
  - Loopback: `127.0.0.0/8`, `::1/128`.
- **The prompt** reads roughly: *"Look for and connect to any device on your local network."* User must click Allow before request succeeds.
- **Requires secure context (HTTPS)** — which `https://ip.corpberry.com` is. Non-secure origins fail all such requests. ([MDN: Local network access](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Local_network_access))
- **What triggers it now:** `fetch()`, subresource loads, subframe navigation. WebSockets/WebTransport/WebRTC *not* covered at launch, though [WebSocket support is being added](https://groups.google.com/a/chromium.org/g/blink-dev/c/4gx2y5jPGbU). ([Chrome blog](https://developer.chrome.com/blog/local-network-access))
- **`targetAddressSpace`**: annotate request as `"local"` or `"loopback"` to declare intent & exempt from mixed-content checks, e.g. `new Request("http://localhost:8888", { targetAddressSpace: "loopback" })`. ([MDN: Local network access](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Local_network_access))

**Cross-browser status (critical):** LNA/PNA essentially a **Chromium feature**. Firefox has only experimental `network.lna.*` prefs (WebSockets bypass by default). Safari has no documented LNA/PNA impl & additionally blocks all loopback mixed content. Scanner behavior forks hard by browser. ([Mozilla bug 1996551](https://bugzilla.mozilla.org/show_bug.cgi?id=1996551); [Chromium blink-dev Intent to Ship: LNA](https://groups.google.com/a/chromium.org/g/blink-dev/c/cwu_RUmBpzY))

### 3. Blocked "bad ports" (`ERR_UNSAFE_PORT`)

All major browsers refuse to open `fetch`/XHR/WebSocket connection to a set of "bad ports" (protocol-confusion protection). Request returns **network error** — can't probe these ports at all. Authoritative list = WHATWG Fetch "bad port" set (browser source varies slightly). ([WHATWG Fetch: port blocking](https://fetch.spec.whatwg.org/#port-blocking); [WHATWG issue #1189](https://github.com/whatwg/fetch/issues/1189))

Blocked ports (verified across Fetch spec + Chromium reproductions):

`1 (tcpmux), 7 (echo), 9 (discard), 11 (systat), 13 (daytime), 15 (netstat), 17 (qotd), 19 (chargen), 20 (ftp-data), 21 (ftp), 22 (ssh), 23 (telnet), 25 (smtp), 37 (time), 42 (name), 43 (nicname), 53 (domain), 69 (tftp), 77 (rje), 79 (finger), 87 (link), 95 (supdup), 101 (hostname), 102 (iso-tsap), 103 (gppitnp), 104 (acr-nema), 109 (pop2), 110 (pop3), 111 (sunrpc), 113 (auth), 115 (sftp), 117 (uucp-path), 119 (nntp), 123 (ntp), 135 (epmap), 137 (netbios-ns), 139 (netbios-ssn), 143 (imap), 161 (snmp), 179 (bgp), 389 (ldap), 427 (svrloc), 465 (submissions), 512 (exec), 513 (login), 514 (shell), 515 (printer), 526 (tempo), 530 (courier), 531 (chat), 532 (netnews), 540 (uucp), 548 (afp), 554 (rtsp), 556 (remotefs), 563 (nntps), 587 (submission), 601 (syslog-conn), 636 (ldaps), 989 (ftps-data), 990 (ftps), 993 (imaps), 995 (pop3s), 1719 (h323gatestat), 1720 (h323hostcall), 1723 (pptp), 2049 (nfs), 3659 (apple-sasl), 4045 (lockd), 4190 (sieve), 5060 (sip), 5061 (sips), 6000 (X11), 6566 (sane-port), 6665-6669 (IRC), 6697 (IRC+TLS), 10080 (amanda)`

Sources for enumerated list: [WHATWG Fetch spec](https://fetch.spec.whatwg.org/#port-blocking), search-corroborated reproductions ([Medium: Unsafe ports considered by Chrome](https://dheeruthedeployer.medium.com/unsafe-ports-considered-by-chrome-6f447b7e4714); [EventSourcingDB: The Port 6000 Mystery](https://docs.eventsourcingdb.io/blog/2025/10/30/the-port-6000-mystery/)). List grows over time (recent additions include SIP 5060/5061 & IRC/X11 range), so treat as "≈dozens, re-check the spec." ([WHATWG PR #1109](https://github.com/whatwg/fetch/pull/1109))

Note what is **NOT** blocked & therefore probe-able: common dev/service ports like `80, 443, 3000, 3306, 5000, 5432, 6379, 8000, 8080, 8443, 9200, 27017` all absent from bad-port list.

### 4. WebRTC mDNS obfuscation (no more LAN IP discovery)

Since Chrome M73 (2019), WebRTC **host ICE candidates obfuscated** as random UUID `.local` mDNS hostname instead of literal `192.168.x.x`. Now standard in Chrome, Edge, Firefox, & Safari. ([discuss-webrtc PSA](https://groups.google.com/g/discuss-webrtc/c/6stQXi72BEU); [BlogGeek.me: mDNS and .local ICE candidates](https://bloggeek.me/psa-mdns-and-local-ice-candidates-are-coming/))

Implications for scanner:
- **Cannot** reliably read visitor's real private IP/subnet to auto-seed LAN sweep. Old trick (create `RTCPeerConnection`, read candidate IPs, no permission needed) now yields `<uuid>.local`, not a scannable address. ([uBlock Origin wiki](https://github.com/uBlockOrigin/uBlock-issues/wiki/Prevent-WebRTC-from-leaking-local-IP-address))
- mDNS does **not** hide public (server-reflexive) IP — but that's visitor's own WAN IP, which server already sees; useless for LAN targeting.
- Data-channel-only `RTCPeerConnection` still gathers candidates w/ no user prompt, but obfuscated, so yields little for scanning.

### 5. Secure context / "potentially trustworthy" loopback (the enabling exception)

W3C Secure Contexts algorithm classifies `127.0.0.0/8`, `::1/128`, and `localhost`/`*.localhost` as **"potentially trustworthy."** ([MDN: Secure contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts); [W3C Secure Contexts](https://www.w3.org/TR/secure-contexts/)) *Why* Chrome/Firefox relax mixed content for loopback & why localhost probe is even conceivable. Does **not** extend to `192.168.x.x` literals — not automatically trustworthy, remain gated by LNA/mixed-content.

### What "open / closed / filtered" actually means in a browser

**No raw socket**; infer state from high-level `fetch`/WebSocket/resource-load outcome & its **timing**:
- **Open (reachable):** connection completes fast — opaque (`no-cors`) response resolves, or HTTP-level/CORS error *after* connecting (TCP/TLS handshake succeeded). Fast rejection w/ CORS/type error = something listening.
- **Closed (refused):** connection refused returns error **quickly** (~immediate). Fast failure ≈ port closed.
- **Filtered:** request **hangs until your own timeout** (no RST, dropped by firewall). Slow failure ≈ filtered.

**Timing heuristic**, not truthful open/closed/filtered like Nmap. Never see banners or version strings (cross-origin responses opaque; CORS blocks reading bodies). Browsers also add anti-fingerprinting noise, so best-effort.

## UX & result presentation

(Constraints report — concrete UX ideas live in sibling `client-side-scan-techniques.md` & competitor reports. What platform *forces* on UX:)
- **Must** surface "grant the permission prompt" explainer before any private-range scan in Chrome 142+, or scan silently returns errors looking like "all filtered."
- **Must** feature-detect browser & degrade: Safari = "loopback scanning not supported in this browser" (mixed content fully blocked); Firefox = partial; Chrome = full-ish w/ prompt.
- Result states labeled honestly as **inferred**: "responding / refused / no response (filtered or blocked)", not confident "open/closed/filtered."

## Other tools & services offered

Not applicable — target is browser platform, not a product. (Monetization/product-idea research in competitor reports: `shodan-censys.md`, `yougetsignal.md`, `canyouseeme.md`, `online-nmap-frontends.md`, `browserleaks.md`.)

## Business / monetization model

Not applicable (platform constraints, no vendor).

## Ideas to steal (for OUR client-side port scanner)

- **Scope tool as "what's listening on *your* machine" localhost/dev-port scanner**, not general internet port scanner. Only thing browser genuinely supports, & legit useful dev toy (detect running Postgres 5432, Redis 6379, dev server 3000/8080, Docker 2375, etc.).
- **Ship curated port list, not range sweep.** Hardcode ~20-40 well-known dev/service ports, **strip any bad-port** (drop 22, 25, 6000, etc. — always error & confuse users). Tailwind-style literal list, no ranges.
- **Use `fetch(url, { mode: "no-cors" })` + `Promise.race` against timeout** as probe primitive; classify by fast-error vs slow-timeout vs resolve. Also try `new Image().src` and `<link>`/`<script>` onload/onerror for second signal.
- **Detect & explain Chrome 142 LNA prompt.** Only prompt for private-range scans; keep loopback default. Set `targetAddressSpace: "loopback"`/`"local"` on requests so future Chrome behaves & mixed content exempted.
- **Feature-gate by browser.** Detect Safari → show "your browser blocks localhost probing from HTTPS; here's why" (great teaching moment, on-brand for IP-tools site). Turns limitation into content.
- **Present three honest states** — *responding* / *refused (fast)* / *no response (filtered/blocked)* — & say plainly it's timing-based inference, not real socket scan. Under-promise.
- **Do probing entirely client-side** (whole point): Go server at `ip.corpberry.com` serves static JS + port list & never emits scan traffic, so corpberry can't get blocklisted. *Selling point* to state in UI ("this scan runs in your browser; our server never touches your network").
- **Don't lean on WebRTC for LAN discovery** — mDNS killed it. To scan LAN, ask user to type their subnet, then scan under LNA prompt (Chrome only).

## Limitations & caveats

- **No raw sockets, ever.** Only HTTP(S)/WS(S). No SYN/ICMP/UDP, no arbitrary TCP. Cannot replicate Nmap.
- **No banner/version/service detection** cross-origin — CORS makes responses opaque; boolean-ish reachability only.
- **Safari is a hard stop** for loopback (no mixed content). Meaningful fraction of visitors see nothing.
- **Chrome 142+ requires user gesture + permission** for private/loopback destinations; page can't scan silently. Good for ethics, but means "click Allow or it looks broken."
- **Bad-port list is moving target** & slightly browser-specific; re-verify against WHATWG spec before shipping port list.
- **Timing classification is noisy** — proxies, VPNs, slow CORS preflights, & browser anti-fingerprinting jitter all muddy open-vs-filtered. Newark-style keepalive/proxy quirks (see repo incident notes) could also skew timing.
- **`wss://` to local device fails cert validation** — WebSocket probing of LAN devices largely dead end from HTTPS.
- **Scanning arbitrary *remote* internet hosts** from browser effectively limited to "did port 80/443 answer an HTTP request," unreliable, & looks abusive. Keep tool pointed at visitor's own machine/LAN.
- **Cross-origin remote probes still leave *client's* IP in logs**, not server's — fine for corpberry's blocklist concern, but worth noting for user privacy messaging.

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
