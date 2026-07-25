# Privacy / leak-test suites (ipleak.net, dnsleaktest, whoer)
> "What does the internet know about you?" dashboards fanning out batch of client-side + server-side probes, shown in one scroll. All four funded by, or lead funnel for, a VPN. None port-scan, but their WebRTC local-IP trick & single-scroll "here's everything we detected" UX = parts worth stealing.

## Overview
Four sites, same genre, slightly different emphasis:

- **ipleak.net** — canonical IP/DNS/WebRTC/torrent leak checker. Free public service **developed/funded by AirVPN** (VPN provider), listed among privacy projects AirVPN backs. Auto-runs checks on page load. ([airvpn.org forum](https://airvpn.org/forums/topic/11238-whats-the-deal-with-ipleaknet/))
- **dnsleaktest.com** — single-purpose DNS-leak tool w/ Standard vs Extended mode toggle. Operated by **IVPN Limited** (VPN provider). ([dnsleaktest.com](https://dnsleaktest.com/), footer)
- **whoer.net** — "anonymity score" suite: rolls all findings into one 0–100% gamified number. Front door for paid **Whoer VPN** subscription. ([octobrowser analysis](https://blog.octobrowser.net/how-anonymity-checkers-pixelscan-browserleaks-whoer-and-creepjs-work))
- **ipx.ac** — "IP info and leak test suite" run by **vpn.ac** (VPN provider). Most technical of four: adds TCP/IP fingerprint, TLS cipher test, IPv6-leak, battery, IP-type classification. ([ipx.ac](https://ipx.ac/), [ipx.ac/run](https://ipx.ac/run))

Common shape: land on page → batch of probes fire automatically → stack of result cards fills top-to-bottom → VPN sold or credited somewhere. Genre = marketing surface as much as diagnostic tool.

## Port scanning / network probing — how it works
**None of these four port-scan** (no TCP/UDP connect attempts, no service enumeration). They = IP/DNS/fingerprint leak checkers. But clearest public model for mixing browser-side + server-side probes into one report; their split maps directly onto what client-side port scanner must reason about. Techniques, grouped by where work happens:

### Client-side (JavaScript / WebRTC, runs in the visitor's browser)
- **WebRTC IP leak — crown jewel, & only network-address probe.** `RTCPeerConnection` gathers ICE candidates against STUN server -> surfaces machine's **local/private LAN IP(s)** & **public IP** even behind NAT, VPN, or proxy. Technique that "sees past" tunnel. ipleak.net headlines it **"Your IP addresses - WebRTC detection"**; whoer.net & ipx.ac both run it ("attempts to detect IP leaks via WebRTC"). ([ipleak.net](https://ipleak.net/), [ipx.ac/run](https://ipx.ac/run))
- **Browser geolocation** — JS Geolocation API (w/ permission prompt) for precise coordinates, shown next to coarse IP-based location. ([ipleak.net](https://ipleak.net/))
- **Browser fingerprint / system info** — User-Agent (JS `navigator` value), language, OS, screen dimensions, plugins, MIME types; ipx.ac adds **battery** level & **TLS cipher-suite** test run from browser. Whoer folds OS version, browser version, JS-enabled, plugins, screen params into score. ([ipleak.net](https://ipleak.net/), [ipx.ac/run](https://ipx.ac/run))
- **Consistency/mismatch checks** — compare browser-reported value vs server-derived one to catch spoofing: **timezone** (browser TZ vs IP TZ), **language**, **User-Agent header vs JS User-Agent**. ipx.ac & whoer both do this. ([ipx.ac/run](https://ipx.ac/run))

### Server-side (what the connection already revealed; passive)
- **IP geolocation** — connecting IP resolved to country, city, coordinates, ASN, ISP, ISP domain, PTR/reverse DNS, & **IP type** (residential / datacenter / mobile / educational / governmental). ipx.ac's = richest. ([ipx.ac/run](https://ipx.ac/run))
- **HTTP request-header inspection** — raw headers (Accept-Encoding, Connection, Host, etc.) echoed back. ([ipleak.net](https://ipleak.net/))
- **Blacklist / reputation** — whoer checks whether IP appears on spam/proxy blacklists & known hosting-ASN ranges ("this IP already distrusted" signal). ([ipcook review](https://www.ipcook.com/blog/whoernet-review), [octobrowser](https://blog.octobrowser.net/how-anonymity-checkers-pixelscan-browserleaks-whoer-and-creepjs-work))
- **TCP/IP fingerprint** — ipx.ac passively fingerprints OS, MTU, connection type from packet characteristics. ([ipx.ac/run](https://ipx.ac/run))

### Hybrid (browser triggers it, the server/authoritative infra observes the result)
These two most interesting architecturally: "scan" happens off origin server:

- **DNS leak** — browser told to fetch **freshly-generated, never-before-resolved unique hostname/subdomain**. Forces real recursive lookup; site's **authoritative DNS then logs which resolvers actually asked**. Comparing those resolvers to expected VPN resolver reveals leak. dnsleaktest.com exposes two modes: **Standard test = "1 round of 6 queries for a total of 6 queries"** (fast) & **Extended test = "6 rounds of 6 queries for a total of 36 queries"**, which "can take 10-30 seconds longer to complete" & is "for [those with] strong anonymity/privacy requirements." Deliberately aggressive query counts surface resolvers handling only part of traffic (load-balanced / race-condition resolvers). Reported fields: resolver **IP, hostname/ISP, country**. ([dnsleaktest.com/what-is-the-difference](https://www.dnsleaktest.com/what-is-the-difference.html), [techyowls explainer](https://dnsleaktest.techyowls.io/dns-leak-test-explained))
- **Torrent / magnet detection (ipleak.net)** — opt-in ("Activate" button). Site hands browser **magnet link to fake file whose tracker URL points at tracker they control**. Torrent client connects to that tracker & announces IP it broadcasts to peers; tracker page updates (~10s) w/ that IP. Reveals **torrent client's real broadcast IP**, which can differ from browser's IP (e.g. browser-only proxy not covering torrent app). Opt-in precisely because slow & needs external app to act. ([airvpn.org forum](https://airvpn.org/forums/topic/16537-ipleaknet-torrent-address-detection/), [brian.carnell.com](https://brian.carnell.com/articles/2024/ipleak-net/))

**Result-state vocabulary.** Leak checkers, not port scanners, so no open/closed/filtered. States: **leaked vs not-leaked** (WebRTC/DNS/torrent), **match vs mismatch** (timezone/language/UA consistency), **yes/no** (e.g. ipleak's "AirVPN: No" — connected through sponsor's VPN?), & whoer's aggregate **0–100% score** w/ red/yellow/green severity coloring on individual rows.

## UX & result presentation
- **Auto-run, single-scroll dashboard.** ipleak.net & whoer.net fire every probe on page load, render one long vertical stack of result cards — no "start" button for core checks. Not-ready cards show placeholder like ipleak's **"DNS detection - Pending, please wait"** & fill in async. Defining UX of genre: "here's everything we detected about you," instantly. ([ipleak.net](https://ipleak.net/))
- **Lead with the headline number.** dnsleaktest opens w/ friendly **"Hello 104.253.63.150"** plus city/country line & flag. whoer leads w/ big **anonymity %**. Single most important finding = huge, above the fold.
- **The privacy/anonymity score.** whoer.net "gamified the data presentation process and introduced its own anonymity percentage score" on 100-point scale. **90–100% = "you look like a regular user from the declared country"**; in **40–70%** band it "highlights warnings in red or yellow, showing which parameters expose you." Score computed from IP type, DNS consistency, WebRTC status, browser language, timezone match, OS/User-Agent consistency — one number aggregating a dozen row-level findings. ([octobrowser](https://blog.octobrowser.net/how-anonymity-checkers-pixelscan-browserleaks-whoer-and-creepjs-work), [ipcook review](https://www.ipcook.com/blog/whoernet-review))
- **WebRTC card presentation.** Own distinct block listing local IP(s) & public IP separately, framed "even with a VPN, this is your real address." Given prominence because most alarming finding. ([ipleak.net](https://ipleak.net/))
- **Mode toggle for the slow/thorough probe.** dnsleaktest's Standard vs Extended toggle = clean two-preset pattern: fast default & opt-in thorough mode w/ explicit time-cost warning & "who should use this" sentence. ([dnsleaktest.com/what-is-the-difference](https://www.dnsleaktest.com/what-is-the-difference.html))
- **Opt-in "Activate" for probes with side effects.** ipleak's torrent test runs only on click, because slow & pokes external app. Heavy/slow/side-effectful probes gated behind explicit button, not auto-run.
- **Map + coarse-vs-precise location.** ipleak shows IP-based map w/ accuracy radius (~20 KM) alongside optional precise browser-geolocation pin — contrasting "what your IP gives away" vs "what your browser gives away."
- **Row-level severity color.** whoer colors individual rows red/yellow/green so user scanning list instantly sees problem lines, independent of top-line score.

## Other tools & services offered
- **ipleak.net** — IP/WebRTC detection, DNS-leak detection, torrent-address detection, IP-based + browser geolocation, full system/browser/headers dump, & AirVPN-connection check. Also exposes per-probe permalink views (e.g. `?view=probe&probe=...`) & DNS-server lookups by hostname. Sibling site **ipleak.com** offers similar "full report" (separate operator). ([ipleak.net](https://ipleak.net/))
- **dnsleaktest.com** — DNS leak test (Standard/Extended) plus explainer pages: "What is a DNS leak?", "How to fix a DNS leak", & WebRTC leak test page. Narrow, single-purpose. ([dnsleaktest.com](https://dnsleaktest.com/))
- **whoer.net** — IP lookup, anonymity-score check, DNS/WebRTC leak checks, blacklist check, browser fingerprint, & speed test — all as free funnel for **Whoer VPN**. ([security.org whoer review](https://www.security.org/vpn/whoer/))
- **ipx.ac** — broadest suite: IPv4 + IPv6 geolocation, DNS, WebRTC, Flash IP, battery, User-Agent comparison, browser info, request headers, timezone comparison, TCP-connection fingerprint, & TLS cipher test. Run by vpn.ac. ([ipx.ac/run](https://ipx.ac/run))

## Business / monetization model
**Every one of the four is a VPN's marketing asset.** Free leak-test tool = top-of-funnel acquisition channel; diagnostic saying "you're exposed" naturally sells the fix (a VPN).

- **ipleak.net** — free public service, no ads/subscription, **funded by AirVPN** as privacy project. Soft-branding: checks whether you're connected via AirVPN. Model = goodwill + brand halo + subtle "are you protected by us?" nudge. ([airvpn.org forum](https://airvpn.org/forums/topic/11238-whats-the-deal-with-ipleaknet/))
- **dnsleaktest.com** — operated by **IVPN Limited**; tool builds trust/traffic & routes toward IVPN paid product. ([dnsleaktest.com](https://dnsleaktest.com/))
- **whoer.net** — most direct funnel: free score → **paid Whoer VPN**. Reported pricing: **$9.90/mo**, 6 months **$39.00 ($6.50/mo, ~35% off)**, 1 year **$46.90 ($3.90/mo, ~60% off)**; free trial = one Netherlands server capped at ~1 Mbps. ([vpnoverview review](https://vpnoverview.com/vpn-reviews/whoer-vpn/), [techjockey](https://www.techjockey.com/detail/whoer-vpn))
- **ipx.ac** — free tool crediting **vpn.ac** in footer; same free-diagnostic-to-paid-VPN pattern, low-pressure. ([ipx.ac](https://ipx.ac/))

Net: standard playbook = affiliate/first-party VPN revenue, not ads or paywalls on tool itself. Tool stays free because scaring users about exposure is the ad.

## Ideas to steal (for OUR client-side port scanner)
- **Single-scroll, auto-run dashboard.** On load, fire every check & stream results into vertical stack of cards; show `Pending…` placeholders filling in async. For port scanner: kick scan on load (or one click), then let each port/result card populate live. "Here's everything we found" framing = whole genre's appeal.
- **A single headline exposure/privacy score.** Aggregate all findings (open ports, WebRTC-leaked real IP, exposed services) into one 0–100 number w/ plain-language verdict ("You look well-protected" vs "N services are reachable from the internet"). Copy whoer's banding: green "you look normal" top band & red/yellow "here's what exposes you" band, plus row-level color so offending lines pop.
- **Use WebRTC to get the LAN IP first, then scan the local subnet.** WebRTC ICE-candidate gathering = the one technique here yielding real network address client-side — including **private LAN IP behind NAT**. Directly load-bearing for browser-side scanner: derive local subnet from WebRTC-leaked private IP, then run JS timing probes against `192.168.x.x`/`10.x` hosts. Present leaked local + public IP as own prominent card either way (most striking single finding).
- **Two-preset mode toggle (fast vs thorough).** Mirror dnsleaktest's Standard/Extended: fast default (top ~common ports) & opt-in "deep scan" (full range) w/ explicit time-cost warning & one-line "who should use this." Presets beat raw port-range box for non-technical visitors.
- **Gate slow/side-effectful probes behind an explicit "Activate" button.** ipleak's torrent test opt-in because slow & touches external app. Full-range client-side port scan is slow & can trip network defenses — gate it the same way rather than auto-run.
- **Contextual VPN (or security-product) affiliate as the monetization angle.** Genre proves model: free network-diagnostic surfacing "you're exposed" = natural, honest funnel to paid privacy product. For corpberry, contextual affiliate CTA ("we can see your real IP / these ports answer from the open internet — a VPN or firewall would hide this") next to relevant finding = proven pattern. Keep soft/first-party-branded (AirVPN/ipx.ac style), not ad-cluttered.
- **Coarse-vs-precise contrast.** Show "what your IP alone gives away" beside "what an active probe additionally revealed" — map-with-radius vs precise-pin contrast dramatizes how much scan adds over passive lookup.

## Limitations & caveats
- **Not port scanners.** These validate *genre & presentation*, not scan technique. Only directly reusable probe = WebRTC local/public-IP disclosure; rest = leak/fingerprint checking.
- **WebRTC leakage is being closed off.** Modern browsers increasingly mask private IP behind **mDNS `.local` hostname** & offer WebRTC-disable toggles, so classic "reveal the LAN IP" trick less reliable than these sites' framing implies. Don't assume every visitor's private IP obtainable. (Behavior varies by browser; treat as best-effort.)
- **DNS/torrent tests need infrastructure we don't have.** DNS-leak method needs controlled **authoritative DNS server** logging resolvers; torrent test needs **controlled BitTorrent tracker**. Both off-origin infra, out of scope for single Go binary's client-side scanner.
- **Marketing bias.** Because each tool sells a VPN, findings framed to maximize alarm ("you're exposed!"). Borrow UX, but keep our copy accurate & non-fear-mongering.
- **Direct-fetch gaps.** whoer.net blocked automated fetch; its score bands, check list, & pricing here come from third-party reviews/analyses ([octobrowser](https://blog.octobrowser.net/how-anonymity-checkers-pixelscan-browserleaks-whoer-and-creepjs-work), [ipcook](https://www.ipcook.com/blog/whoernet-review), [vpnoverview](https://vpnoverview.com/vpn-reviews/whoer-vpn/)), so exact on-page wording/current pricing = **(unverified)**. ipleak.net/ipx.ac/dnsleaktest specifics from primary pages. Precise client-side-vs-server-side split for a few whoer checks inferred from technique, not confirmed on-page **(partly unverified)**.

## Sources
- ipleak.net — https://ipleak.net/
- ipleak.net torrent detection (AirVPN forum) — https://airvpn.org/forums/topic/16537-ipleaknet-torrent-address-detection/
- ipleak.net / AirVPN relationship (AirVPN forum) — https://airvpn.org/forums/topic/11238-whats-the-deal-with-ipleaknet/
- ipleak.net torrent walkthrough — https://brian.carnell.com/articles/2024/ipleak-net/
- dnsleaktest.com — https://dnsleaktest.com/
- dnsleaktest Standard vs Extended — https://www.dnsleaktest.com/what-is-the-difference.html
- dnsleaktest "what is a DNS leak" — https://dnsleaktest.com/what-is-a-dns-leak.html
- DNS-leak unique-hostname method explainer — https://dnsleaktest.techyowls.io/dns-leak-test-explained
- ipx.ac (home) — https://ipx.ac/
- ipx.ac test suite — https://ipx.ac/run
- Octo Browser analysis of Whoer/BrowserLeaks/etc. — https://blog.octobrowser.net/how-anonymity-checkers-pixelscan-browserleaks-whoer-and-creepjs-work
- Whoer.net review (ipcook) — https://www.ipcook.com/blog/whoernet-review
- Whoer VPN pricing (VPNOverview) — https://vpnoverview.com/vpn-reviews/whoer-vpn/
- Whoer VPN pricing (Techjockey) — https://www.techjockey.com/detail/whoer-vpn
- Whoer VPN review (Security.org) — https://www.security.org/vpn/whoer/
