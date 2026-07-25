# GRC ShieldsUP! (grc.com)
> Steve Gibson's classic free firewall/port tester — GRC's own servers probe your public IP, report each port Stealth / Closed / Open.

## Overview
ShieldsUP! = free online port-scan & firewall-test service from Gibson Research Corporation (GRC), by Steve Gibson. Launched Nov 1999; current "Port Authority Edition" arrived 2003, adding 1056-port scan & TruStealth grading. Targets non-technical home/small-office users; run 100M+ tests (GRC counter ~108.3M by late 2024). Deliberately educational, not a pro pentest replacement. ([grc.com/shieldsup](https://www.grc.com/shieldsup); [Grokipedia](https://grokipedia.com/page/shieldsup); [Wikipedia](https://en.wikipedia.org/wiki/ShieldsUP))

Most important architectural fact for us: **ShieldsUP! is SERVER-SIDE.** Scan traffic originates from GRC servers (fixed IP block 4.79.142.192–4.79.142.207) aimed inbound at *visitor's public IP*. Browser only initiates req & displays results. ([Grokipedia, "Server Infrastructure"](https://grokipedia.com/page/shieldsup))

## Port scanning / network probing — how it works

**Server-side, inbound.** GRC servers send TCP/UDP probes from their IPs to your public IP, simulating external attacker knocking on firewall/router from outside. Confirmable: probes show in your firewall logs from GRC's 4.79.142.x range. ([Grokipedia](https://grokipedia.com/page/shieldsup))

**Technique.** Half-open TCP (SYN) scanning: send SYN → open port replies SYN/ACK, closed replies RST, stealth sends nothing. GRC never completes handshake (no final ACK) -> minimal trace, ~3 packets/port. Ports probed in **batches of 64**. UDP only lightly probed (e.g. UPnP SSDP); reliable UDP scanning over public internet impractical. IPv4 only; effectively no IPv6. ([Grokipedia, "Scanning Mechanism"](https://grokipedia.com/page/shieldsup))

**Result states (three):**
- **Open** — port accepts connections; service exposed. Highest risk. GRC wording: packets "requesting a connection with your machine are being accepted and connections are being created." ([portstatusinfo](https://www.grc.com/su/portstatusinfo.htm))
- **Closed** — port responds (RST) refusing connection. Safe-ish, but *confirms machine exists*. GRC: "the best you can hope for without a stealth firewall or NAT router in place." ([portstatusinfo](https://www.grc.com/su/portstatusinfo.htm))
- **Stealth** — port silently drops packet, no response. Best outcome: machine looks "turned off, disconnected, or no longer exists… a black hole for TCP/IP packets." Gibson coined "stealth"; note it's technically non-RFC-compliant behavior only firewall/NAT can produce. ([portstatusinfo](https://www.grc.com/su/portstatusinfo.htm); [faq-shieldsup](https://www.grc.com/faq-shieldsup.htm))

**TruStealth verdict.** Pass/fail overall grade. "100% TruStealth" only if **every** probed port Stealth AND no ping reply AND no unsolicited packets. Any Closed or Open port, or ping response = TruStealth FAILED. Headline plain-language verdict atop results. ([portstatusinfo](https://www.grc.com/su/portstatusinfo.htm))

**Scan modes / presets** (buttons on ShieldsUP! menu after clicking "Proceed"):
- **File Sharing** — probes Windows NetBIOS/SMB file-sharing ports (135, 137–139, 445); "can strangers see your drives" test.
- **Common Ports** — curated set of well-known trouble ports (e.g. 0, 21 FTP, 23 Telnet, 25 SMTP, 80 HTTP, 110 POP3, 113 IDENT, 135–139, 443, 445, 500, 5060 SIP, 5357 WSD). "Quick start" scan.
- **All Service Ports** — TCP **0–1055 (1056 ports)** = 1024 standard service ports + first 32 client ports, drawn as grid. (Sources phrase as "1–1056" or "0–1055"; same 1056-port span.)
- **Specific / Custom Port Probe** — free-text box, test up to **64** user-specified ports or ranges.
- **Messenger Spam** — checks whether (legacy Windows) Messenger service reachable to pop spam at you.
- **Browser Headers** — echoes back what *your browser* leaks to every site (IP, user-agent, referrer, etc.), i.e. privacy/fingerprint reveal, not a port scan.
- (Later additions: **UPnP Exposure Test** — sends SSDP M-SEARCH UDP probes to see if router leaks internal control to WAN; **Ping reply** test.)

([Grokipedia, "Port Scanning Features" / "Additional Security Tests"](https://grokipedia.com/page/shieldsup); [Wikipedia](https://en.wikipedia.org/wiki/ShieldsUP); scan-mode names cross-checked w/ task brief)

**Why a browser fundamentally cannot do this** (core contrast for our tool): ShieldsUP! must send *unsolicited inbound* packets from *external* IP to visitor's public IP to observe whether firewall drops (stealth), refuses (closed), or accepts (open). Browser JS can only make *outbound* connections OS/firewall already permits, confined by same-origin policy / CORS / port blocklists, always originating *inside* NAT — so can never see own perimeter from outside, never distinguish "stealth" from "closed," can't craft raw SYN packets. GRC even hard-stops when it can't reach you directly: through Wayback proxy, ShieldsUP! engine detected intermediary via `Via:` header & returned interception page saying it was "unable to determine your machine's true IP address, so the results of further tests would not be trustworthy." ([archived ShieldsUP! engine page](https://web.archive.org/web/20250102140312id_/https://www.grc.com/x/ne.dll?bh0bkyd2))

## UX & result presentation
- **Color-coded port grid.** All Service Ports scan paints grid of cells, one per port: **Green = Stealth (best), Blue = Closed, Red = Open (danger).** All-green reads instantly as "you're safe." ([Grokipedia, "Interpreting Scan Results"](https://grokipedia.com/page/shieldsup); corroborated by [Tom's Hardware forum](https://forums.tomshardware.com/threads/grc-shields-up-test-are-stealth-ports-good.2914830/))
  - *(Note: one secondary source mapped colors differently; GRC's own presentation & majority of sources use green-stealth / blue-closed / red-open. Verify against live run before hard-coding.)*
- **Clickable cells → ports database.** Every port number in results links to GRC's port knowledgebase explaining what port is, what runs on it, its risk. ([portstatusinfo](https://www.grc.com/su/portstatusinfo.htm))
- **Big plain-language verdict banner** up top: e.g. "TruStealth: PASSED / FAILED", "Your system has achieved a perfect TruStealth rating", or "GRC Port Authority Report" w/ one-paragraph summary a non-expert can act on.
- **Per-port narrative** below grid: status + risk level + what to do (enable firewall, unbind NetBIOS, close service). ([Grokipedia](https://grokipedia.com/page/shieldsup))
- **Copyable text summary + screenshot-friendly layout** for saving/sharing results.
- **Reassuring, opinionated tone** — Gibson's copy chatty & confident ("That's very cool", "You couldn't ask for anything better"), lowers anxiety for lay users.

## Other tools & services offered
GRC site = large catalog of mostly-free utilities plus one flagship paid product. From site nav ([portstatusinfo](https://www.grc.com/su/portstatusinfo.htm) / [faq-shieldsup](https://www.grc.com/faq-shieldsup.htm) side menus):
- **SpinRite** — flagship **paid** product: hard-drive/SSD data recovery & maintenance. v6.1 = **$89** (free upgrade for v6 owners). GRC's revenue engine. ([Wikipedia: SpinRite](https://en.wikipedia.org/wiki/SpinRite); [elevenforum](https://www.elevenforum.com/t/new-spinrite-version-6-1.28561/))
- **Security Now!** — long-running weekly security podcast (Steve Gibson + Leo Laporte, on TWiT network). ([twit.tv/shows/security-now](https://twit.tv/shows/security-now))
- **DNS Benchmark** — free tool ranking DNS resolvers by speed. ([grc.com/dns/operation.htm](https://www.grc.com/dns/operation.htm))
- **InSpectre** — free Spectre/Meltdown vulnerability & performance checker.
- **Perfect Passwords / PPP** — free high-entropy random string generator; "Password Haystacks" brute-force-time explainer.
- **ValiDrive** — free tool detecting fake/counterfeit USB drives.
- **Never10** — free Win10-upgrade blocker; **InControl** — Windows-update version control.
- **ReadSpeed**, **InitDisk**, **Wizmo**, **ID Serve**, **BootAble** — assorted free utilities.
- **SQRL** — Gibson's (now dormant) passwordless auth scheme.
- Legacy security freeware: **Securable, LeakTest, Shoot the Messenger, Unplug n' Pray, DCOMbobulator, MouseTrap**.
- **DNS Spoofability Test**, **HTTPS Fingerprints**, **Certificate Revocation** checks.

## Business / monetization model
- **One paid product funds everything else.** SpinRite ($89) = sole significant revenue product; dozens of security/utility tools (incl. ShieldsUP!) given away free, no ads on tools, no registration, strict **no-logging privacy stance** (GRC states it does not store visitor IPs or scan results). ([Grokipedia, "Accessing and Running Scans" / privacy](https://grokipedia.com/page/shieldsup); [grc.com/purchasing.htm](https://www.grc.com/purchasing.htm))
- **Podcast as reach + soft funnel, not paywall.** Security Now! builds audience & credibility; SpinRite testimonials read on-air. Show monetizes via TWiT network (third-party sponsor reads, Club TWiT membership), not via GRC. ([twit.tv](https://twit.tv/shows/security-now))
- **Reputation/brand flywheel:** free, genuinely useful tools + trusted personal brand (Steve Gibson) → goodwill & word-of-mouth → sells the one paid product. No freemium tiers, no upsell inside free tools.

## Ideas to steal (for OUR client-side port scanner)
- **Three-state model + color grid** (Green=Stealth / Blue=Closed / Red=Open) = most legible port-status UX ever shipped. Reuse *presentation* even though our states will differ (see caveat below).
- **Single plain-language verdict banner** ("You are fully stealthed" / "TruStealth: PASSED") above technical detail. Give lay users one actionable sentence; grid underneath.
- **Named scan presets as buttons** — "Common Ports", "All Service Ports", "File Sharing", plus **custom port box (cap count, e.g. 64)**. Presets remove "which ports do I even test?" paralysis.
- **Clickable port cells → small port-info popover/database** ("Port 445 = SMB, risky because…"). Cheap to build, high perceived value, educational.
- **Batch/progressive rendering** (GRC does 64 at a time) — fill grid as results stream in; feels fast & alive. Maps well to async JS in browser.
- **Opinionated, reassuring copy** telling user what a result *means* & what to do, not just raw states.
- **Copyable text summary** of results for easy sharing/support.
- **BE HONEST ABOUT WHAT CLIENT-SIDE CAN & CANNOT DO.** Key strategic takeaway: our scan runs in *browser*, so can only test *outbound* reachability (can browser open connection to host:port?) — can **not** probe visitor's own firewall from outside, can't produce true "stealth vs closed" distinction, can't scan arbitrary hosts w/o CORS/mixed-content/port-block limits. Frame tool as "what can this browser reach?" not "is your firewall stealthed?" Consider explicitly contrasting w/ ShieldsUP! in docs/UI ("Want to test your firewall from the *outside*? Use GRC ShieldsUP!") — manages expectations & looks credible.

## Limitations & caveats
- **TCP only, ports 0–1055** in full scan — misses everything above ~1056 (modern app/game/P2P ports). ([Grokipedia, "Known Technical Limitations"](https://grokipedia.com/page/shieldsup))
- **Barely any UDP** & **no real IPv6** support. ([Grokipedia](https://grokipedia.com/page/shieldsup))
- **VPN/proxy/CGNAT skews results:** tests whatever public IP it sees, so behind VPN or carrier-grade NAT you're testing *provider's* edge, not your own. GRC refuses to run through detected proxy. ([Grokipedia](https://grokipedia.com/page/shieldsup); [archived engine page](https://web.archive.org/web/20250102140312id_/https://www.grc.com/x/ne.dll?bh0bkyd2))
- **"Stealth vs Closed" FUD debate:** security pros argue GRC overstates value of stealth — a *closed* port already secure, & dropping all unsolicited traffic to appear invisible largely cosmetic. Some IDENT/port-113 stealth results criticized as misleading. Treat "closed = not good enough" framing as marketing, not gospel. ([Wilders Security thread](https://www.wilderssecurity.com/threads/rant-grcs-shields-up-and-true-stealth-firewall-test-or-harmful-fud.216892/); [Ars Technica](https://arstechnica.com/civis/threads/shields-up-online-security-scope-bogus-or-bonus-discuss.557256/))
- **Not a substitute for Nmap** or pro audit; educational entry point. ([Grokipedia](https://grokipedia.com/page/shieldsup))
- **Source caveat:** GRC's own server blocks automated fetchers (WebFetch got "socket closed"; headless browser hit error page), so several details here come via Wayback Machine & Grokipedia summary (AI-generated, but citing GRC primary pages). Color-cell mapping & exact button labels should be confirmed against live manual run before copying verbatim.

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
