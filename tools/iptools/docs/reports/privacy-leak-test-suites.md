# Privacy / leak-test suites (ipleak.net, dnsleaktest, whoer)
> "What does the internet know about you?" dashboards that fan out a batch of client-side + server-side probes and show them in one scroll. All four are funded by, or a lead funnel for, a VPN. None port-scan, but their WebRTC local-IP trick and single-scroll "here's everything we detected" UX are the parts worth stealing.

## Overview
Four sites cover the same genre with slightly different emphasis:

- **ipleak.net** — the canonical IP/DNS/WebRTC/torrent leak checker. Free public service **developed/funded by AirVPN** (a VPN provider), listed among privacy projects AirVPN backs. Auto-runs its checks on page load. ([airvpn.org forum](https://airvpn.org/forums/topic/11238-whats-the-deal-with-ipleaknet/))
- **dnsleaktest.com** — single-purpose DNS-leak tool with a Standard vs Extended mode toggle. Operated by **IVPN Limited** (a VPN provider). ([dnsleaktest.com](https://dnsleaktest.com/), footer)
- **whoer.net** — the "anonymity score" suite: rolls all findings into one 0–100% gamified number. Front door for the paid **Whoer VPN** subscription. ([octobrowser analysis](https://blog.octobrowser.net/how-anonymity-checkers-pixelscan-browserleaks-whoer-and-creepjs-work))
- **ipx.ac** — "IP info and leak test suite" run by **vpn.ac** (a VPN provider). The most technical of the four: adds TCP/IP fingerprint, TLS cipher test, IPv6-leak, battery, and IP-type classification. ([ipx.ac](https://ipx.ac/), [ipx.ac/run](https://ipx.ac/run))

Common shape: land on the page → a batch of probes fire automatically → a stack of result cards fills in top-to-bottom → a VPN is sold or credited somewhere on the page. The genre is a marketing surface as much as a diagnostic tool.

## Port scanning / network probing — how it works
**None of these four port-scan** (no TCP/UDP connect attempts, no service enumeration). They are IP/DNS/fingerprint leak checkers. But they are the clearest public model for mixing browser-side and server-side probes into one report, and their split maps directly onto what a client-side port scanner has to reason about. The techniques, grouped by where the work happens:

### Client-side (JavaScript / WebRTC, runs in the visitor's browser)
- **WebRTC IP leak — the crown jewel, and the only network-address probe.** `RTCPeerConnection` gathers ICE candidates against a STUN server, which surfaces the machine's **local/private LAN IP(s)** and **public IP** even behind NAT, a VPN, or a proxy. This is the technique that "sees past" the tunnel. ipleak.net headlines it as **"Your IP addresses - WebRTC detection"**; whoer.net and ipx.ac both run it ("attempts to detect IP leaks via WebRTC"). ([ipleak.net](https://ipleak.net/), [ipx.ac/run](https://ipx.ac/run))
- **Browser geolocation** — the JS Geolocation API (with a permission prompt) for precise coordinates, shown next to the coarse IP-based location. ([ipleak.net](https://ipleak.net/))
- **Browser fingerprint / system info** — User-Agent (JS `navigator` value), language, OS, screen dimensions, plugins, MIME types; ipx.ac adds **battery** level and a **TLS cipher-suite** test run from the browser. Whoer folds OS version, browser version, JS-enabled, plugins, and screen params into its score. ([ipleak.net](https://ipleak.net/), [ipx.ac/run](https://ipx.ac/run))
- **Consistency/mismatch checks** — compare a browser-reported value against a server-derived one to catch spoofing: **timezone** (browser TZ vs IP TZ), **language**, and **User-Agent header vs JS User-Agent**. ipx.ac and whoer both do this. ([ipx.ac/run](https://ipx.ac/run))

### Server-side (what the connection already revealed; passive)
- **IP geolocation** — the connecting IP resolved to country, city, coordinates, ASN, ISP, ISP domain, PTR/reverse DNS, and **IP type** (residential / datacenter / mobile / educational / governmental). ipx.ac's is the richest. ([ipx.ac/run](https://ipx.ac/run))
- **HTTP request-header inspection** — raw headers (Accept-Encoding, Connection, Host, etc.) echoed back. ([ipleak.net](https://ipleak.net/))
- **Blacklist / reputation** — whoer checks whether the IP appears on spam/proxy blacklists and known hosting-ASN ranges (a "this IP is already distrusted" signal). ([ipcook review](https://www.ipcook.com/blog/whoernet-review), [octobrowser](https://blog.octobrowser.net/how-anonymity-checkers-pixelscan-browserleaks-whoer-and-creepjs-work))
- **TCP/IP fingerprint** — ipx.ac passively fingerprints OS, MTU, and connection type from packet characteristics. ([ipx.ac/run](https://ipx.ac/run))

### Hybrid (browser triggers it, the server/authoritative infra observes the result)
These two are the most interesting architecturally, because the "scan" happens off the origin server:

- **DNS leak** — the browser is told to fetch a **freshly-generated, never-before-resolved unique hostname/subdomain**. That forces a real recursive lookup; the site's **authoritative DNS then logs which resolvers actually asked**. Comparing those resolvers to the expected VPN resolver reveals a leak. dnsleaktest.com exposes two modes: **Standard test = "1 round of 6 queries for a total of 6 queries"** (fast) and **Extended test = "6 rounds of 6 queries for a total of 36 queries"**, which "can take 10-30 seconds longer to complete" and is "for [those with] strong anonymity/privacy requirements." Deliberately aggressive query counts surface resolvers that only handle part of the traffic (load-balanced / race-condition resolvers). Reported fields: resolver **IP, hostname/ISP, country**. ([dnsleaktest.com/what-is-the-difference](https://www.dnsleaktest.com/what-is-the-difference.html), [techyowls explainer](https://dnsleaktest.techyowls.io/dns-leak-test-explained))
- **Torrent / magnet detection (ipleak.net)** — opt-in ("Activate" button). The site hands the browser a **magnet link to a fake file whose tracker URL points at a tracker they control**. Your torrent client connects to that tracker and announces the IP it broadcasts to peers; the tracker page updates (~10s) with that IP. This reveals the **torrent client's real broadcast IP**, which can differ from the browser's IP (e.g. a browser-only proxy that doesn't cover the torrent app). It is opt-in precisely because it's slow and requires an external app to act. ([airvpn.org forum](https://airvpn.org/forums/topic/16537-ipleaknet-torrent-address-detection/), [brian.carnell.com](https://brian.carnell.com/articles/2024/ipleak-net/))

**Result-state vocabulary.** These are leak checkers, not port scanners, so they don't use open/closed/filtered. Their states are: **leaked vs not-leaked** (WebRTC/DNS/torrent), **match vs mismatch** (timezone/language/UA consistency), **yes/no** (e.g. ipleak's "AirVPN: No" — are you connected through the sponsor's VPN), and whoer's aggregate **0–100% score** with red/yellow/green severity coloring on individual rows.

## UX & result presentation
- **Auto-run, single-scroll dashboard.** ipleak.net and whoer.net fire every probe on page load and render one long vertical stack of result cards — no "start" button for the core checks. Cards that aren't ready yet show a placeholder like ipleak's **"DNS detection - Pending, please wait"** and fill in asynchronously. This is the defining UX of the genre: "here's everything we detected about you," instantly. ([ipleak.net](https://ipleak.net/))
- **Lead with the headline number.** dnsleaktest opens with a friendly **"Hello 104.253.63.150"** plus a city/country line and flag. whoer leads with the big **anonymity %**. The single most important finding is huge and above the fold.
- **The privacy/anonymity score.** whoer.net "gamified the data presentation process and introduced its own anonymity percentage score" on a 100-point scale. **90–100% = "you look like a regular user from the declared country"**; in the **40–70%** band it "highlights warnings in red or yellow, showing which parameters expose you." The score is computed from IP type, DNS consistency, WebRTC status, browser language, timezone match, and OS/User-Agent consistency — i.e. one number that aggregates a dozen row-level findings. ([octobrowser](https://blog.octobrowser.net/how-anonymity-checkers-pixelscan-browserleaks-whoer-and-creepjs-work), [ipcook review](https://www.ipcook.com/blog/whoernet-review))
- **WebRTC card presentation.** Shown as its own distinct block listing local IP(s) and public IP separately, framed as "even with a VPN, this is your real address." It's given prominence because it's the most alarming finding. ([ipleak.net](https://ipleak.net/))
- **Mode toggle for the slow/thorough probe.** dnsleaktest's Standard vs Extended toggle is a clean two-preset pattern: a fast default and an opt-in thorough mode with an explicit time-cost warning and a "who should use this" sentence. ([dnsleaktest.com/what-is-the-difference](https://www.dnsleaktest.com/what-is-the-difference.html))
- **Opt-in "Activate" for probes with side effects.** ipleak's torrent test only runs on click, because it's slow and pokes an external app. Heavy/slow/side-effectful probes are gated behind an explicit button, not auto-run.
- **Map + coarse-vs-precise location.** ipleak shows an IP-based map with an accuracy radius (~20 KM) alongside the optional precise browser-geolocation pin — visually contrasting "what your IP gives away" vs "what your browser gives away."
- **Row-level severity color.** whoer colors individual rows red/yellow/green so a user scanning the list instantly sees which lines are the problem, independent of the top-line score.

## Other tools & services offered
- **ipleak.net** — IP/WebRTC detection, DNS-leak detection, torrent-address detection, IP-based + browser geolocation, full system/browser/headers dump, and an AirVPN-connection check. Also exposes per-probe permalink views (e.g. `?view=probe&probe=...`) and DNS-server lookups by hostname. A sibling site, **ipleak.com**, offers a similar "full report" (separate operator). ([ipleak.net](https://ipleak.net/))
- **dnsleaktest.com** — DNS leak test (Standard/Extended) plus explainer pages: "What is a DNS leak?", "How to fix a DNS leak", and a WebRTC leak test page. Narrow, single-purpose. ([dnsleaktest.com](https://dnsleaktest.com/))
- **whoer.net** — IP lookup, anonymity-score check, DNS/WebRTC leak checks, blacklist check, browser fingerprint, and speed test — all as the free funnel for **Whoer VPN**. ([security.org whoer review](https://www.security.org/vpn/whoer/))
- **ipx.ac** — the broadest suite: IPv4 + IPv6 geolocation, DNS, WebRTC, Flash IP, battery, User-Agent comparison, browser info, request headers, timezone comparison, TCP-connection fingerprint, and a TLS cipher test. Run by vpn.ac. ([ipx.ac/run](https://ipx.ac/run))

## Business / monetization model
**Every one of the four is a VPN's marketing asset.** The free leak-test tool is a top-of-funnel acquisition channel; the diagnostic that says "you're exposed" naturally sells the fix (a VPN).

- **ipleak.net** — free public service, no ads/subscription, **funded by AirVPN** as a privacy project. Soft-branding: it checks whether you're connected via AirVPN. Model = goodwill + brand halo + a subtle "are you protected by us?" nudge. ([airvpn.org forum](https://airvpn.org/forums/topic/11238-whats-the-deal-with-ipleaknet/))
- **dnsleaktest.com** — operated by **IVPN Limited**; the tool builds trust/traffic and routes toward the IVPN paid product. ([dnsleaktest.com](https://dnsleaktest.com/))
- **whoer.net** — the most direct funnel: free score → **paid Whoer VPN**. Reported pricing: **$9.90/mo**, 6 months **$39.00 ($6.50/mo, ~35% off)**, 1 year **$46.90 ($3.90/mo, ~60% off)**; free trial = one Netherlands server capped at ~1 Mbps. ([vpnoverview review](https://vpnoverview.com/vpn-reviews/whoer-vpn/), [techjockey](https://www.techjockey.com/detail/whoer-vpn))
- **ipx.ac** — free tool crediting **vpn.ac** in the footer; same free-diagnostic-to-paid-VPN pattern, low-pressure. ([ipx.ac](https://ipx.ac/))

Net: the standard playbook is affiliate/first-party VPN revenue, not ads or paywalls on the tool itself. The tool stays free because scaring users about exposure is the ad.

## Ideas to steal (for OUR client-side port scanner)
- **Single-scroll, auto-run dashboard.** On load, fire every check and stream results into a vertical stack of cards; show `Pending…` placeholders that fill in async. For the port scanner: kick the scan on load (or one click), then let each port/result card populate live. This "here's everything we found" framing is the whole genre's appeal.
- **A single headline exposure/privacy score.** Aggregate all findings (open ports, WebRTC-leaked real IP, exposed services) into one 0–100 number with a plain-language verdict ("You look well-protected" vs "N services are reachable from the internet"). Copy whoer's banding: a green "you look normal" top band and a red/yellow "here's what exposes you" band, plus row-level color so the offending lines pop.
- **Use WebRTC to get the LAN IP first, then scan the local subnet.** WebRTC ICE-candidate gathering is the one technique here that yields a real network address client-side — including the **private LAN IP behind NAT**. That's directly load-bearing for a browser-side scanner: derive the local subnet from the WebRTC-leaked private IP, then run the JS timing probes against `192.168.x.x`/`10.x` hosts. Present the leaked local + public IP as its own prominent card either way (it's the most striking single finding).
- **Two-preset mode toggle (fast vs thorough).** Mirror dnsleaktest's Standard/Extended: a fast default (top ~common ports) and an opt-in "deep scan" (full range) with an explicit time-cost warning and a one-line "who should use this." Presets beat a raw port-range box for non-technical visitors.
- **Gate slow/side-effectful probes behind an explicit "Activate" button.** ipleak's torrent test is opt-in because it's slow and touches an external app. A full-range client-side port scan is slow and can trip network defenses — gate it the same way rather than auto-running it.
- **Contextual VPN (or security-product) affiliate as the monetization angle.** The entire genre proves the model: a free network-diagnostic that surfaces "you're exposed" is a natural, honest funnel to a paid privacy product. For corpberry, a contextual affiliate CTA ("we can see your real IP / these ports answer from the open internet — a VPN or firewall would hide this") next to the relevant finding is the proven pattern. Keep it soft/first-party-branded (AirVPN/ipx.ac style) rather than ad-cluttered.
- **Coarse-vs-precise contrast.** Show "what your IP alone gives away" beside "what an active probe additionally revealed" — the map-with-radius vs precise-pin contrast is a compelling way to dramatize how much a scan adds over passive lookup.

## Limitations & caveats
- **Not port scanners.** These validate the *genre and presentation*, not the scan technique. The only directly reusable probe is WebRTC local/public-IP disclosure; everything else is leak/fingerprint checking.
- **WebRTC leakage is being closed off.** Modern browsers increasingly mask the private IP behind an **mDNS `.local` hostname** and offer WebRTC-disable toggles, so the classic "reveal the LAN IP" trick is less reliable than these sites' framing implies. Do not assume every visitor's private IP is obtainable. (Behavior varies by browser; treat as best-effort.)
- **DNS/torrent tests need infrastructure we don't have.** The DNS-leak method requires a controlled **authoritative DNS server** that logs resolvers; the torrent test requires a **controlled BitTorrent tracker**. Both are off-origin infra, out of scope for a single Go binary's client-side scanner.
- **Marketing bias.** Because each tool sells a VPN, findings are framed to maximize alarm ("you're exposed!"). Borrow the UX, but keep our copy accurate and non-fear-mongering.
- **Direct-fetch gaps.** whoer.net blocked automated fetch; its score bands, check list, and pricing here come from third-party reviews/analyses ([octobrowser](https://blog.octobrowser.net/how-anonymity-checkers-pixelscan-browserleaks-whoer-and-creepjs-work), [ipcook](https://www.ipcook.com/blog/whoernet-review), [vpnoverview](https://vpnoverview.com/vpn-reviews/whoer-vpn/)), so exact on-page wording/current pricing is **(unverified)**. ipleak.net/ipx.ac/dnsleaktest specifics are from the primary pages. The precise client-side-vs-server-side split for a few whoer checks is inferred from technique, not confirmed on-page **(partly unverified)**.

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
