# GRC ShieldsUP! (grc.com)
> Steve Gibson's classic free firewall/port tester — GRC's own servers probe your public IP and report each port as Stealth / Closed / Open.

## Overview
ShieldsUP! is a free online port-scanning and firewall-testing service from Gibson Research Corporation (GRC), written by Steve Gibson. Launched November 1999; the current "Port Authority Edition" arrived in 2003, adding the 1056-port scan and TruStealth grading. It targets non-technical home/small-office users and has run 100M+ tests (GRC's counter showed ~108.3M by late 2024). It is deliberately educational, not a professional pentest replacement. ([grc.com/shieldsup](https://www.grc.com/shieldsup); [Grokipedia](https://grokipedia.com/page/shieldsup); [Wikipedia](https://en.wikipedia.org/wiki/ShieldsUP))

The single most important architectural fact for us: **ShieldsUP! is SERVER-SIDE.** The scan traffic originates from GRC's servers (a fixed IP block, 4.79.142.192–4.79.142.207) aimed inbound at the *visitor's public IP*. The browser only initiates the request and displays results. ([Grokipedia, "Server Infrastructure"](https://grokipedia.com/page/shieldsup))

## Port scanning / network probing — how it works

**Server-side, inbound.** GRC's servers send TCP/UDP probes from their own IPs to your public IP, simulating an external attacker knocking on your firewall/router from the outside. You can confirm this because the probes show up in your firewall logs as coming from GRC's 4.79.142.x range. ([Grokipedia](https://grokipedia.com/page/shieldsup))

**Technique.** Half-open TCP (SYN) scanning: send SYN → open port replies SYN/ACK, closed port replies RST, stealth port sends nothing. GRC never completes the handshake (no final ACK), which leaves minimal trace and uses ~3 packets/port. Ports are probed in **batches of 64**. UDP is only lightly probed (e.g. UPnP SSDP), because reliable UDP scanning over the public internet is impractical. IPv4 only; effectively no IPv6. ([Grokipedia, "Scanning Mechanism"](https://grokipedia.com/page/shieldsup))

**Result states (three):**
- **Open** — port accepts connections; a service is exposed. Highest risk. GRC's wording: packets "requesting a connection with your machine are being accepted and connections are being created." ([portstatusinfo](https://www.grc.com/su/portstatusinfo.htm))
- **Closed** — port responds (RST) refusing the connection. Safe-ish, but it *confirms your machine exists*. GRC: "the best you can hope for without a stealth firewall or NAT router in place." ([portstatusinfo](https://www.grc.com/su/portstatusinfo.htm))
- **Stealth** — port silently drops the packet, no response at all. Best outcome: your machine looks "turned off, disconnected, or no longer exists… a black hole for TCP/IP packets." Gibson coined "stealth" here; note it's technically non-RFC-compliant behavior that only a firewall/NAT can produce. ([portstatusinfo](https://www.grc.com/su/portstatusinfo.htm); [faq-shieldsup](https://www.grc.com/faq-shieldsup.htm))

**TruStealth verdict.** A pass/fail overall grade. You get "100% TruStealth" only if **every** probed port is Stealth AND there is no ping reply AND no unsolicited packets. Any Closed or Open port, or a ping response, = TruStealth FAILED. This is the headline plain-language verdict at the top of the results. ([portstatusinfo](https://www.grc.com/su/portstatusinfo.htm))

**Scan modes / presets** (buttons on the ShieldsUP! menu after you click "Proceed"):
- **File Sharing** — probes the Windows NetBIOS/SMB file-sharing ports (135, 137–139, 445); the "can strangers see your drives" test.
- **Common Ports** — a curated set of well-known trouble ports (e.g. 0, 21 FTP, 23 Telnet, 25 SMTP, 80 HTTP, 110 POP3, 113 IDENT, 135–139, 443, 445, 500, 5060 SIP, 5357 WSD). The "quick start" scan.
- **All Service Ports** — TCP **0–1055 (1056 ports)** = the 1024 standard service ports + first 32 client ports, drawn as a grid. (Sources phrase this as "1–1056" or "0–1055"; same 1056-port span.)
- **Specific / Custom Port Probe** — free-text box, test up to **64** user-specified ports or ranges.
- **Messenger Spam** — checks whether the (legacy Windows) Messenger service can be reached to pop spam at you.
- **Browser Headers** — echoes back what *your browser* leaks to every site (IP, user-agent, referrer, etc.), i.e. a privacy/fingerprint reveal, not a port scan.
- (Later additions: **UPnP Exposure Test** — sends SSDP M-SEARCH UDP probes to see if your router leaks internal control to the WAN; **Ping reply** test.)

([Grokipedia, "Port Scanning Features" / "Additional Security Tests"](https://grokipedia.com/page/shieldsup); [Wikipedia](https://en.wikipedia.org/wiki/ShieldsUP); scan-mode names cross-checked with the task brief)

**Why a browser fundamentally cannot do this** (the core contrast for our tool): ShieldsUP! must send *unsolicited inbound* packets from an *external* IP to the visitor's public IP to observe whether the firewall drops (stealth), refuses (closed), or accepts (open). Browser JavaScript can only make *outbound* connections that the OS/firewall already permits, is confined by the same-origin policy / CORS / port blocklists, and always originates from *inside* the NAT — so it can never see its own perimeter from the outside, can never distinguish "stealth" from "closed," and can't craft raw SYN packets. GRC even hard-stops when it can't reach you directly: through the Wayback proxy, the ShieldsUP! engine detected the intermediary via the `Via:` header and returned an interception page saying it was "unable to determine your machine's true IP address, so the results of further tests would not be trustworthy." ([archived ShieldsUP! engine page](https://web.archive.org/web/20250102140312id_/https://www.grc.com/x/ne.dll?bh0bkyd2))

## UX & result presentation
- **Color-coded port grid.** The All Service Ports scan paints a grid of cells, one per port: **Green = Stealth (best), Blue = Closed, Red = Open (danger).** All-green reads instantly as "you're safe." ([Grokipedia, "Interpreting Scan Results"](https://grokipedia.com/page/shieldsup); corroborated by [Tom's Hardware forum](https://forums.tomshardware.com/threads/grc-shields-up-test-are-stealth-ports-good.2914830/))
  - *(Note: one secondary source mapped the colors differently; GRC's own presentation and the majority of sources use green-stealth / blue-closed / red-open. Verify against a live run before hard-coding.)*
- **Clickable cells → ports database.** Every port number in the results links to GRC's port knowledgebase explaining what that port is, what runs on it, and its risk. ([portstatusinfo](https://www.grc.com/su/portstatusinfo.htm))
- **Big plain-language verdict banner** up top: e.g. "TruStealth: PASSED / FAILED", "Your system has achieved a perfect TruStealth rating", or "GRC Port Authority Report" with a one-paragraph summary a non-expert can act on.
- **Per-port narrative** below the grid: status + risk level + what to do (enable firewall, unbind NetBIOS, close the service). ([Grokipedia](https://grokipedia.com/page/shieldsup))
- **Copyable text summary + screenshot-friendly layout** for saving/sharing results.
- **Reassuring, opinionated tone** — Gibson's copy is chatty and confident ("That's very cool", "You couldn't ask for anything better"), which lowers anxiety for lay users.

## Other tools & services offered
GRC's site is a large catalog of mostly-free utilities plus one flagship paid product. From the site nav ([portstatusinfo](https://www.grc.com/su/portstatusinfo.htm) / [faq-shieldsup](https://www.grc.com/faq-shieldsup.htm) side menus):
- **SpinRite** — the flagship **paid** product: hard-drive/SSD data recovery & maintenance. v6.1 is **$89** (free upgrade for v6 owners). This is GRC's revenue engine. ([Wikipedia: SpinRite](https://en.wikipedia.org/wiki/SpinRite); [elevenforum](https://www.elevenforum.com/t/new-spinrite-version-6-1.28561/))
- **Security Now!** — long-running weekly security podcast (Steve Gibson + Leo Laporte, on the TWiT network). ([twit.tv/shows/security-now](https://twit.tv/shows/security-now))
- **DNS Benchmark** — free tool ranking DNS resolvers by speed. ([grc.com/dns/operation.htm](https://www.grc.com/dns/operation.htm))
- **InSpectre** — free Spectre/Meltdown vulnerability & performance checker.
- **Perfect Passwords / PPP** — free high-entropy random string generator; "Password Haystacks" brute-force-time explainer.
- **ValiDrive** — free tool to detect fake/counterfeit USB drives.
- **Never10** — free Win10-upgrade blocker; **InControl** — Windows-update version control.
- **ReadSpeed**, **InitDisk**, **Wizmo**, **ID Serve**, **BootAble** — assorted free utilities.
- **SQRL** — Gibson's (now dormant) passwordless auth scheme.
- Legacy security freeware: **Securable, LeakTest, Shoot the Messenger, Unplug n' Pray, DCOMbobulator, MouseTrap**.
- **DNS Spoofability Test**, **HTTPS Fingerprints**, **Certificate Revocation** checks.

## Business / monetization model
- **One paid product funds everything else.** SpinRite ($89) is the sole significant revenue product; the dozens of security/utility tools (including ShieldsUP!) are given away free, with no ads on the tools, no registration, and a strict **no-logging privacy stance** (GRC states it does not store visitor IPs or scan results). ([Grokipedia, "Accessing and Running Scans" / privacy](https://grokipedia.com/page/shieldsup); [grc.com/purchasing.htm](https://www.grc.com/purchasing.htm))
- **Podcast as reach + soft funnel, not paywall.** Security Now! builds audience and credibility; SpinRite testimonials are read on-air. The show itself monetizes via the TWiT network (third-party sponsor reads, Club TWiT membership), not via GRC. ([twit.tv](https://twit.tv/shows/security-now))
- **Reputation/brand flywheel:** free, genuinely useful tools + a trusted personal brand (Steve Gibson) → drives goodwill and word-of-mouth → sells the one paid product. No freemium tiers, no upsell inside the free tools.

## Ideas to steal (for OUR client-side port scanner)
- **The three-state model + color grid** (Green=Stealth / Blue=Closed / Red=Open) is the single most legible port-status UX ever shipped. Reuse the *presentation* even though our states will differ (see caveat below).
- **A single plain-language verdict banner** ("You are fully stealthed" / "TruStealth: PASSED") above the technical detail. Give lay users one sentence they can act on; put the grid underneath.
- **Named scan presets as buttons** — "Common Ports", "All Service Ports", "File Sharing", plus a **custom port box (cap the count, e.g. 64)**. Presets remove the "which ports do I even test?" paralysis.
- **Clickable port cells → a small port-info popover/database** ("Port 445 = SMB, risky because…"). Cheap to build, high perceived value, and educational.
- **Batch/progressive rendering** (GRC does 64 at a time) — fill the grid as results stream in; feels fast and alive. This maps well to async JS in the browser.
- **Opinionated, reassuring copy** that tells the user what a result *means* and what to do, not just raw states.
- **Copyable text summary** of results for easy sharing/support.
- **BE HONEST ABOUT WHAT CLIENT-SIDE CAN AND CANNOT DO.** This is the key strategic takeaway: because our scan runs in the *browser*, it can only test *outbound* reachability (can the browser open a connection to host:port?) — it can **not** probe the visitor's own firewall from outside, can't produce a true "stealth vs closed" distinction, and can't scan arbitrary hosts without CORS/mixed-content/port-block limits. Frame our tool as "what can this browser reach?" not "is your firewall stealthed?" Consider explicitly contrasting with ShieldsUP! in our docs/UI ("Want to test your firewall from the *outside*? Use GRC ShieldsUP!") — it manages expectations and looks credible.

## Limitations & caveats
- **TCP only, ports 0–1055** in the full scan — misses everything above ~1056 (modern app/game/P2P ports). ([Grokipedia, "Known Technical Limitations"](https://grokipedia.com/page/shieldsup))
- **Barely any UDP** and **no real IPv6** support. ([Grokipedia](https://grokipedia.com/page/shieldsup))
- **VPN/proxy/CGNAT skews results:** it tests whatever public IP it sees, so behind a VPN or carrier-grade NAT you're testing the *provider's* edge, not your own. GRC refuses to run through a detected proxy. ([Grokipedia](https://grokipedia.com/page/shieldsup); [archived engine page](https://web.archive.org/web/20250102140312id_/https://www.grc.com/x/ne.dll?bh0bkyd2))
- **"Stealth vs Closed" FUD debate:** security pros argue GRC overstates the value of stealth — a *closed* port is already secure, and dropping all unsolicited traffic to appear invisible is largely cosmetic. Some IDENT/port-113 stealth results were criticized as misleading. Treat the "closed = not good enough" framing as marketing, not gospel. ([Wilders Security thread](https://www.wilderssecurity.com/threads/rant-grcs-shields-up-and-true-stealth-firewall-test-or-harmful-fud.216892/); [Ars Technica](https://arstechnica.com/civis/threads/shields-up-online-security-scope-bogus-or-bonus-discuss.557256/))
- **Not a substitute for Nmap** or a professional audit; it's an educational entry point. ([Grokipedia](https://grokipedia.com/page/shieldsup))
- **Source caveat:** GRC's own server blocks automated fetchers (WebFetch got "socket closed"; a headless browser hit an error page), so several details here come via the Wayback Machine and the Grokipedia summary (AI-generated, but citing GRC primary pages). The color-cell mapping and exact button labels should be confirmed against a live manual run before we copy them verbatim.

## Sources
- https://www.grc.com/shieldsup — official ShieldsUP! landing
- https://www.grc.com/su/portstatusinfo.htm — GRC's Open/Closed/Stealth definitions (via Wayback: https://web.archive.org/web/20240118101147id_/https://www.grc.com/su/portstatusinfo.htm)
- https://www.grc.com/faq-shieldsup.htm — ShieldsUP! FAQ, stealth/closed explanations (via Wayback: https://web.archive.org/web/20250102140514id_/https://www.grc.com/faq-shieldsup.htm)
- https://web.archive.org/web/20250102140312id_/https://www.grc.com/x/ne.dll?bh0bkyd2 — archived ShieldsUP! engine page showing proxy/`Via:`-header interception (evidence of server-side design)
- https://grokipedia.com/page/shieldsup — consolidated summary: technique, IP range, colors, scan modes, history, limitations (AI-generated; cites GRC primary sources)
- https://en.wikipedia.org/wiki/ShieldsUP — overview, history, scan scope
- https://en.wikipedia.org/wiki/SpinRite — flagship paid product
- https://www.elevenforum.com/t/new-spinrite-version-6-1.28561/ — SpinRite 6.1 $89 pricing
- https://twit.tv/shows/security-now — Security Now! podcast
- https://www.grc.com/dns/operation.htm — DNS Benchmark
- https://forums.tomshardware.com/threads/grc-shields-up-test-are-stealth-ports-good.2914830/ — color/result discussion
- https://www.wilderssecurity.com/threads/rant-grcs-shields-up-and-true-stealth-firewall-test-or-harmful-fud.216892/ — stealth-vs-closed FUD critique
- https://arstechnica.com/civis/threads/shields-up-online-security-scope-bogus-or-bonus-discuss.557256/ — expert critique
