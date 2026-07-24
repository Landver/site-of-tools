# YouGetSignal (yougetsignal.com)
> A long-running, free suite of single-input web network tools (open-port check, traceroute, WHOIS, reverse-IP, etc.) built by Kirk Ouimet; the Open Port Check is its flagship.

## Overview
YouGetSignal.com is a personal "network tools" site — a small collection of
single-purpose web utilities, each on its own `/tools/<name>/` page, cross-linked
from a shared landing page. It is credited to **Kirk Ouimet Design** ("©2009 Kirk
Ouimet Design. All rights reserved." in the footer), and describes itself as a set
of "uncomplicated, powerful network tools." The best-known tool is the **Open Port
Check Tool** (a.k.a. Port Forwarding Tester), heavily used by people debugging
router port-forwarding and firewall rules.
Sources: <https://www.yougetsignal.com/>, <https://www.yougetsignal.com/tools/open-ports/>

## Port scanning / network probing — how it works
**Server-side probe of *your* public IP against *one* chosen port.** This is the
key architectural difference from a browser-side scanner: the actual TCP connection
attempt originates from YouGetSignal's server, not from the visitor's browser.

- **Auto-detected target.** On load, the tool pre-fills the "Remote Address" field
  with the visitor's detected public IP (e.g. `104.253.63.150` in the fetched
  example). A **"Use Current IP"** button re-inserts it if you've typed over it.
  So the default action is "check a port on *me*," but you can point it at any
  remote address / DDNS hostname.
- **Two inputs only:** Remote Address + Port Number. Enter a port, click Check.
- **Technique.** The server opens a TCP connection to `remote_address:port`. A
  successful connect = **open**; connection refused / timed out = **closed**. It is
  a single-port TCP connect probe per request (not a SYN scan, not UDP). Result
  states are binary **open / closed** — there is no separate "filtered"/"stealth"
  state exposed to the user (contrast with GRC ShieldsUp, which distinguishes
  "stealth"). (The open/closed binary is confirmed by usage guides; the exact
  timeout/retry behavior is unverified.)
- **Quick-pick common ports.** Below the input is a row of ~20 clickable
  frequently-forwarded ports; clicking one fills the port field and runs the check.
  The list (port → label) is:
  `21 FTP · 22 SSH · 23 TELNET · 25 SMTP · 53 DNS · 80 HTTP · 110 POP3 ·
  115 SFTP · 135 RPC · 139 NetBIOS · 143 IMAP · 194 IRC · 443 SSL · 445 SMB ·
  1433 MSSQL · 3306 MySQL · 3389 Remote Desktop · 5632 PCAnywhere · 5900 VNC ·
  25565 Minecraft`.
- **"Scan All Common Ports"** runs the whole quick-pick list sequentially rather
  than requiring one click per port.
- **Result presentation.** Each result is shown as a colored **flag icon + text
  line**: a green flag for open, a red flag for closed, with a line naming the
  port and IP. (Exact result string wording is unverified from primary source; the
  pattern is "Port `<n>` is open/closed on `<ip>`".)
Sources: <https://www.yougetsignal.com/tools/open-ports/>, <https://www.rarst.net/web/yougetsignal-open-port/>, <https://ruvium.com/blog/check-open-ports-with-yougetsignal>

## UX & result presentation
- **Radical single-input simplicity.** Every tool is one page, one primary text
  field, one button. No login, no config, no wizard. The port tool adds exactly one
  extra field (the port).
- **Sensible auto-fill default.** Pre-populating the visitor's own public IP means
  the most common task (check a port on my own connection) is basically zero-input:
  pick a port, go.
- **Quick-pick chips remove the "what port number is X?" friction.** Users who
  don't know that RDP is 3389 or Minecraft is 25565 just click the label.
- **Inline, incremental results.** Results append below the form on the same page
  (server round-trip per check) with an at-a-glance red/green flag so status is
  readable without reading text.
- **Consistent chrome across tools.** Left-hand vertical nav lists all tools on
  every page, plus a grid of image tiles on the landing page — so any tool page is
  also a directory to the rest of the suite.

## Other tools & services offered
All are free web tools under `/tools/`, each with the same single-input pattern.
Exact landing-page labels:
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
- **Visual Trace Route** — takes a remote IP ("Use Current IP" option), runs a
  server-side traceroute (incrementing TTL), and plots each hop on a **Google Map**
  with a hop IP list; hop geolocation uses **MaxMind's GeoIP database**. IPv4-oriented.
- **Reverse IP Domain Check** — single "Remote Address" field; "takes a domain name
  or IP address pointing to a web server and searches for other sites known to be
  hosted on that same web server." IPv4 only (no IPv6-only sites).
Sources: <https://www.yougetsignal.com/>, <https://www.yougetsignal.com/tools/visual-tracert/>, <https://www.yougetsignal.com/tools/web-sites-on-web-server/>

## Business / monetization model
- **Free-to-use, ad-supported personal site.** There is **no pricing page, no
  account system, no paywall, and no subscription** — verified by the absence of any
  such pages/links in the tool suite. The tools are free and anonymous.
- **Author-owned hobby/portfolio property.** Attributed to Kirk Ouimet (footer:
  "©2009 Kirk Ouimet Design"). The business model is display advertising on
  otherwise-free utility pages — a classic "useful free tool that ranks well in
  search → serve ads against the traffic" model. (The presence of live display ads
  is the widely-understood model but was **not directly verifiable** in the fetched
  markdown, which strips ad iframes; treat the *ads specifically* as
  partially unverified. The free/no-paywall structure IS verified.)
- **No upsell to a paid tier or API** is advertised on the pages reviewed.
Sources: <https://www.yougetsignal.com/>

## Ideas to steal (for OUR client-side port scanner)
- **Quick-pick common-ports chips with service labels.** A one-click row like
  `22 SSH · 80 HTTP · 443 HTTPS · 3389 RDP · 3306 MySQL · 25565 Minecraft` removes
  the "which number is that service?" friction. Cheap to build, high UX payoff.
  Tailwind note: these are literal class strings so they're fine (rule: no
  Go-built class names). Keep the label list in Go data, render server-side into
  the template.
- **"Scan common ports" preset button** alongside single-port entry — one click to
  sweep the popular list instead of N manual entries. Maps well to a scan-mode
  preset (Quick / Common / Custom).
- **Auto-fill the visitor's own value as the default target.** YouGetSignal
  pre-fills your public IP; our IP tool already knows the visitor IP, so the port
  scanner can default to "scan me" with a "Use my IP" button — near-zero-input first
  run. (Note: browser-side JS generally **cannot** connect to arbitrary raw TCP
  ports, so "scan me from your browser" behaves very differently from YouGetSignal's
  server probe — see caveats. The *UX pattern* is what's worth copying, not the
  mechanism.)
- **Tool-suite cross-linking as default chrome.** Persistent side/nav listing of
  sibling tools on every tool page, plus a landing grid — turns each tool into a
  funnel to the others. Fits our one-binary/subdomain model: apex + IP tool +
  botcheck can cross-link the same way.
- **Binary + color-coded results, read at a glance.** Green = open, red = closed,
  with a plain-text line. Simple, accessible, no jargon. (We can add a third
  "filtered/no-response" state that YouGetSignal omits — a differentiator.)
- **One page, one input, one button.** The whole site's discipline: resist adding
  config. Content-negotiated HTML/JSON (per our ARCHITECTURE) can keep that clean.

## Limitations & caveats
- **Server-side, single-port, TCP-connect only.** No UDP, no port ranges in one
  request (the "all common ports" sweep is just the fixed ~20-item list), no
  "filtered/stealth" distinction. Because the probe comes from *their* server, it
  tests reachability-from-the-internet — which is exactly the outbound-traffic
  behavior our design avoids by scanning client-side.
- **Direct mechanism is NOT reusable for us.** A browser cannot open arbitrary raw
  TCP sockets; a JS "port scanner" typically infers state via `fetch`/`WebSocket`/
  `img` timing and CSP/mixed-content errors, and can generally only probe the
  visitor's *own* localhost or hosts that serve web content. YouGetSignal's exact
  open/closed semantics don't translate — steal the UX, not the method.
- **Dated stack & data.** Footer copyright reads 2009; Visual Tracert relies on
  Google Maps embeds + MaxMind GeoIP; Reverse IP is IPv4-only. Geo/reverse-IP
  accuracy on such tools is best-effort.
- **Exact result-string wording and the timeout/retry logic were not verified**
  from primary source (marked inline). The tool list, quick-pick ports, auto-fill IP,
  and free/no-paywall model ARE verified from the live pages.

## Sources
- <https://www.yougetsignal.com/> — landing page, tool list, footer attribution
- <https://www.yougetsignal.com/tools/open-ports/> — Open Port Check tool, inputs, quick-pick ports, auto-fill IP
- <https://www.yougetsignal.com/tools/visual-tracert/> — Visual Trace Route tool
- <https://www.yougetsignal.com/tools/web-sites-on-web-server/> — Reverse IP Domain Check tool
- <https://www.rarst.net/web/yougetsignal-open-port/> — third-party walkthrough (test-connection description)
- <https://ruvium.com/blog/check-open-ports-with-yougetsignal> — third-party guide (open/closed result semantics)
