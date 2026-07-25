# YouGetSignal (yougetsignal.com)
> Long-running free suite of single-input web network tools (open-port check, traceroute, WHOIS, reverse-IP, etc.) built by Kirk Ouimet; Open Port Check = flagship.

## Overview
Personal "network tools" site — small collection of single-purpose web utilities,
each on own `/tools/<name>/` page, cross-linked from shared landing page. Credited
to **Kirk Ouimet Design** ("©2009 Kirk Ouimet Design. All rights reserved." in
footer); describes itself as "uncomplicated, powerful network tools." Best-known =
**Open Port Check Tool** (a.k.a. Port Forwarding Tester), heavily used for
debugging router port-forwarding & firewall rules.
Sources: <https://www.yougetsignal.com/>, <https://www.yougetsignal.com/tools/open-ports/>

## Port scanning / network probing — how it works
**Server-side probe of *your* public IP against *one* chosen port.** Key
architectural difference from browser-side scanner: TCP connection attempt
originates from YouGetSignal's server, not visitor's browser.

- **Auto-detected target.** On load, pre-fills "Remote Address" field w/ visitor's
  detected public IP (e.g. `104.253.63.150` in fetched example). **"Use Current
  IP"** button re-inserts it if typed over. Default action = "check a port on
  *me*," but can point at any remote address / DDNS hostname.
- **Two inputs only:** Remote Address + Port Number. Enter port, click Check.
- **Technique.** Server opens TCP connection to `remote_address:port`. Successful
  connect = **open**; refused / timed out = **closed**. Single-port TCP connect
  probe per req (not SYN scan, not UDP). Result states binary **open / closed** —
  no separate "filtered"/"stealth" state exposed to user (contrast GRC ShieldsUp,
  which distinguishes "stealth"). (open/closed binary confirmed by usage guides;
  exact timeout/retry behavior unverified.)
- **Quick-pick common ports.** Below input = row of ~20 clickable
  frequently-forwarded ports; clicking one fills port field & runs check.
  List (port → label):
  `21 FTP · 22 SSH · 23 TELNET · 25 SMTP · 53 DNS · 80 HTTP · 110 POP3 ·
  115 SFTP · 135 RPC · 139 NetBIOS · 143 IMAP · 194 IRC · 443 SSL · 445 SMB ·
  1433 MSSQL · 3306 MySQL · 3389 Remote Desktop · 5632 PCAnywhere · 5900 VNC ·
  25565 Minecraft`.
- **"Scan All Common Ports"** runs whole quick-pick list sequentially instead of
  one click per port.
- **Result presentation.** Each result = colored **flag icon + text line**: green
  flag for open, red for closed, w/ line naming port & IP. (Exact result string
  wording unverified from primary source; pattern = "Port `<n>` is open/closed on
  `<ip>`".)
Sources: <https://www.yougetsignal.com/tools/open-ports/>, <https://www.rarst.net/web/yougetsignal-open-port/>, <https://ruvium.com/blog/check-open-ports-with-yougetsignal>

## UX & result presentation
- **Radical single-input simplicity.** Every tool = one page, one primary text
  field, one button. No login, no config, no wizard. Port tool adds exactly one
  extra field (port).
- **Sensible auto-fill default.** Pre-populating visitor's own public IP means most
  common task (check port on own connection) is ~zero-input: pick port, go.
- **Quick-pick chips remove "what port number is X?" friction.** Users who don't
  know RDP=3389 or Minecraft=25565 click the label.
- **Inline, incremental results.** Results append below form on same page (server
  round-trip per check) w/ at-a-glance red/green flag so status readable w/o
  reading text.
- **Consistent chrome across tools.** Left-hand vertical nav lists all tools on
  every page, plus grid of image tiles on landing page — any tool page is also a
  directory to rest of suite.

## Other tools & services offered
All free web tools under `/tools/`, each same single-input pattern. Exact
landing-page labels:
| Tool | Landing-page description |
|---|---|
| **Open Ports** | "Port Forwarding Tester → find open ports on your connection" |
| **Web Sites on Web Server** | "Reverse IP Domain Check → find other sites on a web server" |
| **Network Location** | "Network Location Tool → locate a network using Google Maps" |
| **Visual Tracert** | "Visual Trace Route Tool → plot the route to a network address" |
| **Phone Location** | "Phone Number Geolocator → find out who's calling" |
| **Reverse Email Lookup** | "Reverse E-mail Lookup Tool → figure out who's e-mailing" |
| **WHOIS Lookup** | "WHOIS Lookup Tool → check to see if a domain name is available" |
| **What Is My IP Address** | "quickly identify your external IP address" |

Notable detail on individual tools:
- **Visual Trace Route** — takes remote IP ("Use Current IP" option), runs
  server-side traceroute (incrementing TTL), plots each hop on **Google Map** w/
  hop IP list; hop geolocation uses **MaxMind's GeoIP database**. IPv4-oriented.
- **Reverse IP Domain Check** — single "Remote Address" field; "takes a domain name
  or IP address pointing to a web server and searches for other sites known to be
  hosted on that same web server." IPv4 only (no IPv6-only sites).
Sources: <https://www.yougetsignal.com/>, <https://www.yougetsignal.com/tools/visual-tracert/>, <https://www.yougetsignal.com/tools/web-sites-on-web-server/>

## Business / monetization model
- **Free-to-use, ad-supported personal site.** **No pricing page, no account
  system, no paywall, no subscription** — verified by absence of any such
  pages/links in tool suite. Tools free & anonymous.
- **Author-owned hobby/portfolio property.** Attributed to Kirk Ouimet (footer:
  "©2009 Kirk Ouimet Design"). Business model = display advertising on
  otherwise-free utility pages — classic "useful free tool that ranks well in search
  → serve ads against traffic" model. (Live display ads = widely-understood model
  but **not directly verifiable** in fetched markdown, which strips ad iframes;
  treat *ads specifically* as partially unverified. Free/no-paywall structure IS
  verified.)
- **No upsell to paid tier or API** advertised on pages reviewed.
Sources: <https://www.yougetsignal.com/>

## Ideas to steal (for OUR client-side port scanner)
- **Quick-pick common-ports chips w/ service labels.** One-click row like
  `22 SSH · 80 HTTP · 443 HTTPS · 3389 RDP · 3306 MySQL · 25565 Minecraft` removes
  "which number is that service?" friction. Cheap to build, high UX payoff.
  Tailwind note: these = literal class strings so fine (rule: no Go-built class
  names). Keep label list in Go data, render server-side into template.
- **"Scan common ports" preset button** alongside single-port entry — one click to
  sweep popular list instead of N manual entries. Maps well to scan-mode preset
  (Quick / Common / Custom).
- **Auto-fill visitor's own value as default target.** YouGetSignal pre-fills your
  public IP; our IP tool already knows visitor IP, so port scanner can default to
  "scan me" w/ "Use my IP" button — near-zero-input first run. (Note: browser-side
  JS generally **cannot** connect to arbitrary raw TCP ports, so "scan me from your
  browser" behaves very differently from YouGetSignal's server probe — see caveats.
  *UX pattern* worth copying, not mechanism.)
- **Tool-suite cross-linking as default chrome.** Persistent side/nav listing of
  sibling tools on every tool page, plus landing grid — turns each tool into funnel
  to others. Fits our one-binary/subdomain model: apex + IP tool + botcheck can
  cross-link same way.
- **Binary + color-coded results, read at a glance.** Green = open, red = closed,
  w/ plain-text line. Simple, accessible, no jargon. (We can add third
  "filtered/no-response" state YouGetSignal omits — differentiator.)
- **One page, one input, one button.** Whole site's discipline: resist adding
  config. Content-negotiated HTML/JSON (per our ARCHITECTURE) keeps that clean.

## Limitations & caveats
- **Server-side, single-port, TCP-connect only.** No UDP, no port ranges in one req
  ("all common ports" sweep = just fixed ~20-item list), no "filtered/stealth"
  distinction. Probe comes from *their* server -> tests
  reachability-from-the-internet — exactly the outbound-traffic behavior our design
  avoids by scanning client-side.
- **Direct mechanism NOT reusable for us.** Browser cannot open arbitrary raw TCP
  sockets; JS "port scanner" typically infers state via `fetch`/`WebSocket`/`img`
  timing & CSP/mixed-content errors, generally only probes visitor's *own* localhost
  or hosts serving web content. YouGetSignal's exact open/closed semantics don't
  translate — steal UX, not method.
- **Dated stack & data.** Footer copyright reads 2009; Visual Tracert relies on
  Google Maps embeds + MaxMind GeoIP; Reverse IP IPv4-only. Geo/reverse-IP accuracy
  on such tools best-effort.
- **Exact result-string wording & timeout/retry logic not verified** from primary
  source (marked inline). Tool list, quick-pick ports, auto-fill IP, & free/no-paywall
  model ARE verified from live pages.

## Sources
- <https://www.yougetsignal.com/> — landing page, tool list, footer attribution
- <https://www.yougetsignal.com/tools/open-ports/> — Open Port Check tool, inputs, quick-pick ports, auto-fill IP
- <https://www.yougetsignal.com/tools/visual-tracert/> — Visual Trace Route tool
- <https://www.yougetsignal.com/tools/web-sites-on-web-server/> — Reverse IP Domain Check tool
- <https://www.rarst.net/web/yougetsignal-open-port/> — 3rd-party walkthrough (test-connection description)
- <https://ruvium.com/blog/check-open-ports-with-yougetsignal> — 3rd-party guide (open/closed result semantics)
