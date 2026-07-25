# Web-based Nmap frontends (ipfingerprints, HackerTarget, Pentest-Tools)
> Three server-side "scan on your behalf" port scanners — UX, freemium/credit models, & (the point) abuse controls they bolt on because scan traffic leaves *their* IP, not visitor's.

## Overview

All three = **server-side** port scanners: type target into web form, *their* backend (real Nmap, or Nmap-equivalent raw-packet scanning) sends probe packets, results come back to your browser. Visitor's machine never touches target. Third-party wrappers confirm framing — `scanless` CLI calls ipfingerprints & friends "websites that can perform port scans **on your behalf**" ([github.com/vesche/scanless](https://github.com/vesche/scanless)).

That single architectural fact — packets originate from service's IP — drives everything worth learning here:
- Why they can offer SYN stealth, OS fingerprinting, UDP scans, & full 65,535-port sweeps (raw sockets need OS privileges browser lacks).
- *Also* why each bolts on captchas, per-IP daily caps, rate limits, login/payment-as-identity, & "you must have permission" disclaimers — abuse lands on their infra & IP reputation.

This report captures each tool's UX & business model, then makes abuse argument justifying our scanner **client-side** (from visitor's browser).

---

## Port scanning / network probing — how it works

### ipfingerprints.com — Network Port Checker & Scanner
- **Execution:** Server-side. Sends "raw IP packets" to detect open ports, determine OS, check firewall ([ipfingerprints.com/portscan](https://ipfingerprints.com/portscan)). OS detection + SYN stealth need raw-socket privileges → browser can't.
- **Input:** Hostname/IP + **start port** & **end port**. "Normal" vs "Advanced" mode toggle ([portscan](https://ipfingerprints.com/portscan)).
- **Scan techniques:** `connect()` (default) & **SYN Stealth**; FAQ also discusses FIN, XMAS, ACK & Window scans, plus OS detection & firewall-protection checking ([ipfingerprints.com/faq](https://ipfingerprints.com/faq)).
- **Result states:** open / closed / filtered (standard Nmap vocab), plus OS guess & firewall presence.
- **Soft limit:** *"If the difference between the start and end port exceeds 500, scans may take a long time or fail to complete."* ([portscan](https://ipfingerprints.com/portscan)) — range cap dressed as perf note.

### HackerTarget.com — two tiers of same server-side Nmap
- **Execution:** Server-side Nmap on HackerTarget's infra.
- **Quick "TCP Port Scan" (free):** Fixed **10 common ports** — 21 FTP, 22 SSH, 23 Telnet, 25 SMTP, 80 HTTP, 110 POP3, 143 IMAP, 443 HTTPS, 445 SMB, 3389 RDP ([hackertarget.com/tcp-port-scan](https://hackertarget.com/tcp-port-scan/)). Accepts IPv4, IPv6, or hostname.
- **Advanced "Nmap Online Port Scanner":** Any IP or IP range, **all 65,535 ports**, toggles for port set (Default / Fast `-F` / all 65535), UDP, IPv6 (`-6`), skip-ping (`-Pn`), OS detection (`-O`), & traceroute (`--traceroute`) ([hackertarget.com/nmap-online-port-scanner](https://hackertarget.com/nmap-online-port-scanner/)).
- **Result states:** open / closed / filtered.

### Pentest-Tools.com — "Port Scanner with Nmap"
- **Execution:** Server-side / cloud Nmap. Markets that cloud hosting *"bypasses firewall or local egress restrictions"* ([pentest-tools.com/.../port-scanner-online-nmap](https://pentest-tools.com/network-vulnerability-scanning/port-scanner-online-nmap)) — i.e. scans from IP that isn't yours. Abuse vector stated as feature.
- **Techniques:** *"TCP SYN scans, full TCP connect scans, and can be configured to test UDP"* ([port-scanner page FAQ](https://pentest-tools.com/network-vulnerability-scanning/port-scanner-online-nmap)).
- **Two presets:**
  - **Light scan** — Top 100 TCP + UDP ports, reports running service versions.
  - **Deep scan** — full range up to all 65,535 ports.
- **Result states:** open / closed / filtered; plus detected service, service version, OS guess, & SSL/TLS cert details when port supports it.

---

## UX & result presentation

**Target input**
- ipfingerprints: host/IP + numeric start/end port boxes (most manual of three).
- HackerTarget: single box, accepts IPv4/IPv6/hostname/ranges/CIDR; multiple targets comma- or newline-separated.
- Pentest-Tools: single target box + structured options panel.

**Port-range presets (worth stealing)**
- HackerTarget: **Default / Fast (`-F`) / all 65535** as radio-style choices.
- Pentest-Tools: **Light vs Deep** headline toggle, then finer "Port selection: Common ports / List of ports / Top 10 / Top 100 / Top 1000" & Protocol **TCP / UDP** switch, plus checkboxes "Detect service version" & "Detect operating system" ([verbatim from port-scanner page](https://pentest-tools.com/network-vulnerability-scanning/port-scanner-online-nmap)).

**Results table**
- HackerTarget's = cleanest template: three-column **PORT / STATE / SERVICE** table, states open/closed/filtered ([tcp-port-scan](https://hackertarget.com/tcp-port-scan/)). Advanced tool adds searchable tabular dashboard, plain-text view, & HTML report, emailed to registered address & kept in member dashboard ([nmap-online-port-scanner](https://hackertarget.com/nmap-online-port-scanner/)).
- Pentest-Tools: results exportable in **JSON, CSV, & PDF**, w/ "sample report" shown on page & "see it in action" section before you scan ([port-scanner page FAQ](https://pentest-tools.com/network-vulnerability-scanning/port-scanner-online-nmap)).

**Authorization framing shown in UI**
- Pentest-Tools puts checkbox right on scan form: *"I am authorized to scan this target and I agree with the Terms of Service."* ([port-scanner page](https://pentest-tools.com/network-vulnerability-scanning/port-scanner-online-nmap)).
- HackerTarget states plainly: *"You must have permission to scan the target."* ([nmap-online-port-scanner](https://hackertarget.com/nmap-online-port-scanner/)).
- ipfingerprints shows **no** on-page permission disclaimer & no visible captcha/rate limit — notable gap for raw-packet scanner ([portscan](https://ipfingerprints.com/portscan)).

---

## Other tools & services offered

**ipfingerprints.com** — broad free "IP tools" suite: IP Geolocation, IP/proxy/VPN identification & browser fingerprinting, Ping, Port Scanner, WHOIS, Reverse IP/DNS, DNS Lookup, DNS Propagation, MAC address lookup, IP Blacklist check, SSL/TLS checker, & email-auth cluster (SPF checker/generator, DMARC, DKIM, MX/SMTP check) ([ipfingerprints.com/faq](https://ipfingerprints.com/faq)). Proxy/geo detection = headline feature alongside scanner.

**HackerTarget.com** — advertises ~18 free web tools &, for members, ~28+ more vuln scanners: Nmap, OpenVAS, Zmap, plus DNS/subdomain/recon & web-app scanners ([ip-tools](https://hackertarget.com/ip-tools/), [scan-membership](https://hackertarget.com/scan-membership/)).

**Pentest-Tools.com** — full cloud pentest platform: network vuln scanning, web-app/API DAST, authenticated scanning, automated CVE exploitation (SQLi/XSS exploiters), recon, & report generation ([pentest-tools.com/pricing](https://pentest-tools.com/pricing)). Port scanner = one tool inside suite.

---

## Business / monetization model

**ipfingerprints.com** — No pricing or paywall surfaced on scanner or FAQ pages; appears free, ad-supported IP-tools portal (monetization *unverified*).

**HackerTarget.com — membership/subscription w/ quota tiers** ([scan-membership](https://hackertarget.com/scan-membership/)):
- Free web forms (no signup) but **captcha + limits**: page says *"Remove limits & captcha with membership."* Free **API** capped at **50 queries/day**, **2 requests/second** (excess → HTTP 429), results capped (~500 lines).
- **Starter $10/mo ($120/yr):** Nmap 64 IPs/day, OpenVAS 16 IPs/day, 16 scans/day, Tools API 500/day, +8 scanners.
- **Pro $25/mo ($300/yr):** scheduled scans, Nmap 512 IPs/day, OpenVAS 128 IPs/day, 30 scans/day, API 1000/day.
- **Business $50/mo ($600/yr):** Zmap, Nmap 2048 IPs/day, OpenVAS 512 IPs/day, 100 scans/day, API 2000/day.
- **Enterprise from $100/mo:** 5,192+ IPs/day, API 7,500+/day, custom quotas.
- Tellingly: *"Payment functions as identification to minimize abuse of the system."* — paywall = anti-abuse identity mechanism as much as revenue model.

**Pentest-Tools.com — asset-quota freemium** ([pricing](https://pentest-tools.com/pricing)):
- **Free Edition:** up to 5 scanned assets/month, 2 parallel scans, 25 scheduled scans, tools in "light" mode only.
- **NetSec from $95/mo**, **WebNetSec from $140/mo**, **Pentest Suite from $190/mo** (5 assets, yearly billing "saves 2 months"; scale 5→500 assets, or sales for more).
- **Quota model:** "asset" = single hostname or IP; quota **resets every 30 days**; rescanning same asset within month counts once; subdomains count as separate assets.
- 10-day money-back guarantee; 7-day trial requiring business email + card is *reported in search results but not confirmed on pricing page (unverified)*.

---

## Ideas to steal (for OUR client-side port scanner)

- **Named port-range presets, not raw start/end boxes.** Offer buttons/dropdown: *Top 10 common*, *Top 100*, *Top 1000*, *custom list*, *full range* — HackerTarget's Default/Fast/All & Pentest-Tools' Top-10/100/1000 = model. Far friendlier than ipfingerprints' two numeric boxes.
- **Single "Light vs Deep" mode toggle** (Pentest-Tools) bundling port count + depth, granular options tucked into "Advanced" disclosure. Matches our "scan-mode presets" instinct.
- **PORT / STATE / SERVICE results table** (HackerTarget) = clean, skimmable template. Add **port→service-name map** so users see "22 SSH", "443 HTTPS" not bare numbers. Colour STATE cell (open/closed/filtered/timeout).
- **Set expectations on long scans** — ipfingerprints' ">500 ports may be slow" note. In-browser this maps to warning when user picks large range (browser probes serial-ish & slow).
- **Export / copy results** — even "copy as JSON" or CSV download echoes Pentest-Tools' JSON/CSV/PDF exports; professional for near-zero effort.
- **Show sample result before scanning** (Pentest-Tools "see it in action") so first-time visitors understand output.
- **Authorization nudge** — lightweight "only scan hosts you own or are authorized to test" line. For us = good-citizen framing rather than liability shielding (see below), but sets right tone.
- **Lead w/ client-side differentiator as trust feature:** e.g. "This scan runs in *your* browser, from *your* connection — corpberry never sends the packets." Both honest technical statement & selling point none of these three can make.

### Why server-side scanning invites abuse & blocklisting (justification for going client-side)

- **Attribution lands on operator.** In all three, probe packets leave *service's* IP. To target's firewall/IDS, scan came from HackerTarget/Pentest-Tools/ipfingerprints — so their IPs end up in abuse reports, AbuseIPDB/Spamhaus-style blocklists, & hosting-provider ToS complaints. If corpberry scanned server-side, **corpberry's IP** collects that reputation damage.
- **You become free anonymizing launchpad.** Anyone can point server-side scanner at third party they don't own; operator carries legal & reputational weight of traffic they didn't originate. Pentest-Tools even advertises this as benefit — cloud hosting *"bypasses firewall or local egress restrictions."* Great for user, radioactive for whoever runs servers.
- **Exactly why they gate.** Captchas + per-IP daily caps + 2 req/s rate limits + 429s + login/payment-as-identity + "you must have permission" checkboxes = all defenses for *operator's* infra, not features for user. HackerTarget says quiet part out loud: *"Payment functions as identification to minimize abuse of the system."*
- **Client-side inverts whole problem.** If probe traffic originates from *visitor's* browser & IP, visitor bears attribution & consequences; corpberry's server never emits scan traffic & can't be blocklisted for it — so no need for captchas, credit-gating, or identity walls to protect our IP reputation. Abuse-control machinery these three are built around simply doesn't apply to us.

---

## Limitations & caveats

- **We can't copy their *technique*, only their *vocabulary*.** SYN stealth, OS fingerprinting, true UDP scanning, & ICMP ping all need raw sockets / OS privileges browser denies. That privilege gap = *the reason* these tools are server-side.
- **Browser can only infer reachability, fuzzily.** Client-side JS probes via `fetch`/`WebSocket`/image-load attempts plus timing — you get roughly "reachable / refused / timed-out", not Nmap-grade open/closed/filtered w/ service versions. Manage expectations in UI accordingly.
- **Browser restrictions bite:** CORS, mixed-content (HTTPS page can't freely probe `http://` or arbitrary ports), & browsers' hard-coded **blocked-port lists** (Chrome/Firefox refuse connections to many well-known ports like 22 & 25). Our preset lists must account for ports browser simply refuses.
- **Source-verification gaps:** ipfingerprints' monetization unverified (no pricing surfaced); Pentest-Tools' "business email + card for trial" detail comes from search snippet, not pricing page (marked unverified above). Pentest-Tools tool-page details transcribed via verbatim fetch after summarizer declined analytical prompts — figures quoted as shown on page.

---

## Sources
- ipfingerprints Port Scanner — https://ipfingerprints.com/portscan
- ipfingerprints FAQ (tool list, scan types) — https://ipfingerprints.com/faq
- HackerTarget quick TCP Port Scan (10 ports, PORT/STATE/SERVICE, captcha note) — https://hackertarget.com/tcp-port-scan/
- HackerTarget advanced Nmap Online Port Scanner (toggles, permission note) — https://hackertarget.com/nmap-online-port-scanner/
- HackerTarget Scan Membership (pricing tiers, "payment as identification") — https://hackertarget.com/scan-membership/
- HackerTarget IP Tools index — https://hackertarget.com/ip-tools/
- Pentest-Tools Port Scanner with Nmap (Light/Deep, presets, authorization checkbox, exports, cloud-egress claim) — https://pentest-tools.com/network-vulnerability-scanning/port-scanner-online-nmap
- Pentest-Tools pricing (Free Edition, NetSec/WebNetSec/Pentest Suite, asset-quota model) — https://pentest-tools.com/pricing
- scanless (confirms these are third-party "scan on your behalf" backends) — https://github.com/vesche/scanless
