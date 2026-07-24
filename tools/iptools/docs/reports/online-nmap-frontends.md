# Web-based Nmap frontends (ipfingerprints, HackerTarget, Pentest-Tools)
> Three server-side "scan on your behalf" port scanners — their UX, their freemium/credit models, and (the point) the abuse controls they bolt on because the scan traffic leaves *their* IP, not the visitor's.

## Overview

All three targets are **server-side** port scanners: you type a target into a web form, *their* backend (real Nmap, or Nmap-equivalent raw-packet scanning) sends the probe packets, and the results come back to your browser. The visitor's own machine never touches the target. Third-party wrappers confirm this framing — the `scanless` CLI literally calls ipfingerprints and friends "websites that can perform port scans **on your behalf**" ([github.com/vesche/scanless](https://github.com/vesche/scanless)).

That single architectural fact — the packets originate from the service's IP — drives everything worth learning here:
- It's why they can offer SYN stealth, OS fingerprinting, UDP scans, and full 65,535-port sweeps (raw sockets need OS privileges a browser doesn't have).
- It's *also* why every one of them bolts on captchas, per-IP daily caps, rate limits, login/payment-as-identity, and "you must have permission" disclaimers — because abuse lands on their infrastructure and their IP reputation.

This report captures each tool's UX and business model, then articulates the abuse argument that justifies doing our scanner **client-side** (from the visitor's browser).

---

## Port scanning / network probing — how it works

### ipfingerprints.com — Network Port Checker & Scanner
- **Execution:** Server-side. Sends "raw IP packets" to detect open ports, determine OS, and check for a firewall ([ipfingerprints.com/portscan](https://ipfingerprints.com/portscan)). OS detection + SYN stealth require raw-socket privileges → not something a browser can do.
- **Input:** Hostname/IP + **start port** and **end port**. A "Normal" vs "Advanced" mode toggle ([portscan](https://ipfingerprints.com/portscan)).
- **Scan techniques:** `connect()` (default) and **SYN Stealth**; the FAQ additionally discusses FIN, XMAS, ACK and Window scans, plus OS detection and firewall-protection checking ([ipfingerprints.com/faq](https://ipfingerprints.com/faq)).
- **Result states:** open / closed / filtered (standard Nmap vocabulary), plus OS guess and firewall presence.
- **Soft limit:** *"If the difference between the start and end port exceeds 500, scans may take a long time or fail to complete."* ([portscan](https://ipfingerprints.com/portscan)) — a range cap dressed up as a performance note.

### HackerTarget.com — two tiers of the same server-side Nmap
- **Execution:** Server-side Nmap on HackerTarget's infrastructure.
- **Quick "TCP Port Scan" (free):** Fixed set of **10 common ports** — 21 FTP, 22 SSH, 23 Telnet, 25 SMTP, 80 HTTP, 110 POP3, 143 IMAP, 443 HTTPS, 445 SMB, 3389 RDP ([hackertarget.com/tcp-port-scan](https://hackertarget.com/tcp-port-scan/)). Accepts IPv4, IPv6, or hostname.
- **Advanced "Nmap Online Port Scanner":** Any IP or IP range, **all 65,535 ports**, with toggles for port set (Default / Fast `-F` / all 65535), UDP, IPv6 (`-6`), skip-ping (`-Pn`), OS detection (`-O`), and traceroute (`--traceroute`) ([hackertarget.com/nmap-online-port-scanner](https://hackertarget.com/nmap-online-port-scanner/)).
- **Result states:** open / closed / filtered.

### Pentest-Tools.com — "Port Scanner with Nmap"
- **Execution:** Server-side / cloud Nmap. Explicitly markets that its cloud hosting *"bypasses firewall or local egress restrictions"* ([pentest-tools.com/.../port-scanner-online-nmap](https://pentest-tools.com/network-vulnerability-scanning/port-scanner-online-nmap)) — i.e. it scans from an IP that isn't yours. That's the abuse vector stated as a feature.
- **Techniques:** *"TCP SYN scans, full TCP connect scans, and can be configured to test UDP"* ([port-scanner page FAQ](https://pentest-tools.com/network-vulnerability-scanning/port-scanner-online-nmap)).
- **Two presets:**
  - **Light scan** — Top 100 TCP + UDP ports, reports running service versions.
  - **Deep scan** — full range up to all 65,535 ports.
- **Result states:** open / closed / filtered; plus detected service, service version, OS guess, and SSL/TLS certificate details when the port supports it.

---

## UX & result presentation

**Target input**
- ipfingerprints: host/IP + numeric start/end port boxes (most manual of the three).
- HackerTarget: single box, accepts IPv4/IPv6/hostname/ranges/CIDR; multiple targets comma- or newline-separated.
- Pentest-Tools: single target box + a structured options panel.

**Port-range presets (worth stealing)**
- HackerTarget: **Default / Fast (`-F`) / all 65535** as radio-style choices.
- Pentest-Tools: **Light vs Deep** as the headline toggle, then finer "Port selection: Common ports / List of ports / Top 10 / Top 100 / Top 1000" and a Protocol **TCP / UDP** switch, plus checkboxes "Detect service version" and "Detect operating system" ([verbatim from port-scanner page](https://pentest-tools.com/network-vulnerability-scanning/port-scanner-online-nmap)).

**Results table**
- HackerTarget's is the cleanest template: a three-column **PORT / STATE / SERVICE** table, states open/closed/filtered ([tcp-port-scan](https://hackertarget.com/tcp-port-scan/)). The advanced tool adds a searchable tabular dashboard, a plain-text view, and an HTML report, emailed to the registered address and kept in the member dashboard ([nmap-online-port-scanner](https://hackertarget.com/nmap-online-port-scanner/)).
- Pentest-Tools: results exportable in **JSON, CSV, and PDF**, with a "sample report" shown on the page and a "see it in action" section before you scan ([port-scanner page FAQ](https://pentest-tools.com/network-vulnerability-scanning/port-scanner-online-nmap)).

**Authorization framing shown in the UI**
- Pentest-Tools puts a checkbox right on the scan form: *"I am authorized to scan this target and I agree with the Terms of Service."* ([port-scanner page](https://pentest-tools.com/network-vulnerability-scanning/port-scanner-online-nmap)).
- HackerTarget states plainly: *"You must have permission to scan the target."* ([nmap-online-port-scanner](https://hackertarget.com/nmap-online-port-scanner/)).
- ipfingerprints shows **no** on-page permission disclaimer and no visible captcha/rate limit — a notable gap for a raw-packet scanner ([portscan](https://ipfingerprints.com/portscan)).

---

## Other tools & services offered

**ipfingerprints.com** — a broad free "IP tools" suite: IP Geolocation, IP/proxy/VPN identification & browser fingerprinting, Ping, Port Scanner, WHOIS, Reverse IP/DNS, DNS Lookup, DNS Propagation, MAC address lookup, IP Blacklist check, SSL/TLS checker, and an email-auth cluster (SPF checker/generator, DMARC, DKIM, MX/SMTP check) ([ipfingerprints.com/faq](https://ipfingerprints.com/faq)). Proxy/geo detection is a headline feature alongside the scanner.

**HackerTarget.com** — advertises ~18 free web tools and, for members, ~28+ additional vulnerability scanners: Nmap, OpenVAS, Zmap, plus DNS/subdomain/recon and web-app scanners ([ip-tools](https://hackertarget.com/ip-tools/), [scan-membership](https://hackertarget.com/scan-membership/)).

**Pentest-Tools.com** — a full cloud pentest platform: network vuln scanning, web-app/API DAST, authenticated scanning, automated CVE exploitation (SQLi/XSS exploiters), reconnaissance, and report generation ([pentest-tools.com/pricing](https://pentest-tools.com/pricing)). The port scanner is one tool inside the suite.

---

## Business / monetization model

**ipfingerprints.com** — No pricing or paywall surfaced on the scanner or FAQ pages; appears to be a free, ad-supported IP-tools portal (monetization model *unverified*).

**HackerTarget.com — membership/subscription with quota tiers** ([scan-membership](https://hackertarget.com/scan-membership/)):
- Free web forms (no signup) but **captcha + limits**: the page says *"Remove limits & captcha with membership."* Free **API** is capped at **50 queries/day**, **2 requests/second** (excess → HTTP 429), and results are capped (~500 lines).
- **Starter $10/mo ($120/yr):** Nmap 64 IPs/day, OpenVAS 16 IPs/day, 16 scans/day, Tools API 500/day, +8 scanners.
- **Pro $25/mo ($300/yr):** scheduled scans, Nmap 512 IPs/day, OpenVAS 128 IPs/day, 30 scans/day, API 1000/day.
- **Business $50/mo ($600/yr):** Zmap, Nmap 2048 IPs/day, OpenVAS 512 IPs/day, 100 scans/day, API 2000/day.
- **Enterprise from $100/mo:** 5,192+ IPs/day, API 7,500+/day, custom quotas.
- Tellingly: *"Payment functions as identification to minimize abuse of the system."* — the paywall is an anti-abuse identity mechanism as much as a revenue model.

**Pentest-Tools.com — asset-quota freemium** ([pricing](https://pentest-tools.com/pricing)):
- **Free Edition:** up to 5 scanned assets/month, 2 parallel scans, 25 scheduled scans, tools in "light" mode only.
- **NetSec from $95/mo**, **WebNetSec from $140/mo**, **Pentest Suite from $190/mo** (5 assets, yearly billing "saves 2 months"; scale 5→500 assets, or sales for more).
- **Quota model:** an "asset" = a single hostname or IP; quota **resets every 30 days**; rescanning the same asset within a month counts once; subdomains count as separate assets.
- 10-day money-back guarantee; a 7-day trial requiring a business email + card is *reported in search results but not confirmed on the pricing page (unverified)*.

---

## Ideas to steal (for OUR client-side port scanner)

- **Named port-range presets, not raw start/end boxes.** Offer buttons/dropdown: *Top 10 common*, *Top 100*, *Top 1000*, *custom list*, *full range* — HackerTarget's Default/Fast/All and Pentest-Tools' Top-10/100/1000 are the model. Far friendlier than ipfingerprints' two numeric boxes.
- **A single "Light vs Deep" mode toggle** (Pentest-Tools) that bundles port count + depth, with the granular options tucked into an "Advanced" disclosure. Matches our own "scan-mode presets" instinct.
- **The PORT / STATE / SERVICE results table** (HackerTarget) is the clean, skimmable template. Add a **port→service-name map** so users see "22 SSH", "443 HTTPS" not bare numbers. Colour the STATE cell (open/closed/filtered/timeout).
- **Set expectations on long scans** — ipfingerprints' ">500 ports may be slow" note. In-browser this maps to a warning when the user picks a large range (browser probes are serial-ish and slow).
- **Export / copy results** — even a "copy as JSON" or CSV download echoes Pentest-Tools' JSON/CSV/PDF exports and feels professional for near-zero effort.
- **Show a sample result before scanning** (Pentest-Tools "see it in action") so first-time visitors understand the output.
- **An authorization nudge** — a lightweight "only scan hosts you own or are authorized to test" line. For us it's good-citizen framing rather than liability shielding (see below), but it sets the right tone.
- **Lead with the client-side differentiator as a trust feature:** e.g. "This scan runs in *your* browser, from *your* connection — corpberry never sends the packets." It's both an honest technical statement and a selling point none of these three can make.

### Why server-side scanning invites abuse and blocklisting (the justification for going client-side)

- **Attribution lands on the operator.** In all three tools the probe packets leave the *service's* IP. To the target's firewall/IDS, the scan came from HackerTarget/Pentest-Tools/ipfingerprints — so their IPs are what end up in abuse reports, AbuseIPDB/Spamhaus-style blocklists, and hosting-provider ToS complaints. If corpberry scanned server-side, **corpberry's IP** would collect that reputation damage.
- **You become a free anonymizing launchpad.** Anyone can point a server-side scanner at a third party they don't own; the operator carries the legal and reputational weight of traffic they didn't originate. Pentest-Tools even advertises this as a benefit — cloud hosting *"bypasses firewall or local egress restrictions."* Great for the user, radioactive for whoever runs the servers.
- **That's exactly why they gate.** Captchas + per-IP daily caps + 2 req/s rate limits + 429s + login/payment-as-identity + "you must have permission" checkboxes are all defenses for the *operator's* infrastructure, not features for the user. HackerTarget says the quiet part out loud: *"Payment functions as identification to minimize abuse of the system."*
- **Client-side inverts the whole problem.** If the probe traffic originates from the *visitor's* browser and IP, the visitor bears attribution and consequences; corpberry's server never emits scan traffic and can't be blocklisted for it — so we don't need captchas, credit-gating, or identity walls to protect our IP reputation. The abuse-control machinery these three are built around simply doesn't apply to us.

---

## Limitations & caveats

- **We cannot copy their *technique*, only their *vocabulary*.** SYN stealth, OS fingerprinting, true UDP scanning, and ICMP ping all need raw sockets / OS privileges the browser denies. That privilege gap is *the reason* these tools are server-side in the first place.
- **A browser can only infer reachability, fuzzily.** Client-side JS probes via `fetch`/`WebSocket`/image-load attempts plus timing — you get roughly "reachable / refused / timed-out", not Nmap-grade open/closed/filtered with service versions. Manage expectations in the UI accordingly.
- **Browser restrictions bite:** CORS, mixed-content (an HTTPS page can't freely probe `http://` or arbitrary ports), and the browsers' hard-coded **blocked-port lists** (Chrome/Firefox refuse connections to many well-known ports like 22 and 25). Our preset lists must account for ports the browser will simply refuse.
- **Source-verification gaps:** ipfingerprints' monetization is unverified (no pricing surfaced); Pentest-Tools' "business email + card for trial" detail comes from a search snippet, not the pricing page (marked unverified above). The Pentest-Tools tool-page details were transcribed via a verbatim fetch after the summarizer declined analytical prompts — figures are quoted as shown on the page.

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
