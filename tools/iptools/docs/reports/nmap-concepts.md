# Nmap — port-state vocabulary to borrow
> Canonical CLI port scanner. NOT copying it — borrow its honest **result model** (six port states) & **frequency-ranked port list** to describe uncertain browser-side probes truthfully.

## Overview
Nmap ("Network Mapper") = reference open-source port scanner & network discovery
tool, by Gordon "Fyodor" Lyon. **Server/host-side CLI**: sends crafted
TCP/UDP/SCTP/IP packets & interprets responses. Architecturally opposite our tool
(we probe from visitor's browser, no raw sockets), so can't copy its *techniques*.
Worth stealing: its **vocabulary & result model** — small honest set of port states
that explicitly encode *uncertainty*, & a ranked "which ports matter" list. Both map
onto browser's core constraint — browser frequently **cannot tell open from filtered**,
& Nmap has precise words for that.
Source: https://nmap.org/book/man-port-scanning-basics.html

## Port scanning / network probing — how it works
- **Server-side, raw packets.** Nmap runs on scanning host, sends probes directly
  (SYN scan, connect scan, UDP, FIN/NULL/Xmas, idle scan, etc.). Not relevant to us
  mechanically — browser has no raw sockets — but its *result states* are what we borrow.
- **The six port states (verbatim-ish from official docs).** Nmap stresses these
  describe *how Nmap perceives the port*, not inherent property; "the same port may
  appear differently depending on network location and scan parameters."
  1. **open** — "An application is actively accepting TCP connections, UDP datagrams or
     SCTP associations on this port."
  2. **closed** — "A closed port is accessible (it receives and responds to Nmap probe
     packets), but there is no application listening on it."
  3. **filtered** — "Nmap cannot determine whether the port is open because packet
     filtering prevents its probes from reaching the port." Filtering may be "a dedicated
     firewall device, router rules, or host-based firewall software." Filter may send
     ICMP error (e.g. type 3 code 13) but "filters that simply drop probes without
     responding are far more common."
  4. **unfiltered** — "The unfiltered state means that a port is accessible, but Nmap is
     unable to determine whether it is open or closed." (Only from ACK scan.)
  5. **open|filtered** — "Nmap places ports in this state when it is unable to determine
     whether a port is open or filtered." Occurs "for scan types in which open ports give
     no response" — namely **UDP, IP protocol, FIN, NULL, and Xmas scans**. Point:
     silence is ambiguous — port open & stayed quiet, or filter dropped probe/response.
  6. **closed|filtered** — "This state is used when Nmap is unable to determine whether a
     port is closed or filtered. It is only used for the IP ID idle scan."
  Source: https://nmap.org/book/man-port-scanning-basics.html
- **Key idea for us:** two of six states (`filtered`, `open|filtered`) exist
  *specifically to name the case where scanner got no clear signal.* Nmap never guesses
  "open" when it doesn't know — downgrades to explicit uncertainty state. Exactly the
  discipline a browser probe needs.
- **`--top-ports` / `nmap-services` frequency ranking.** Rather than scan all 65,536
  ports, Nmap ships a frequency table (`nmap-services` file) built from empirical scans of
  "tens of millions of Internet IP addresses as well as enterprise networks scanned from
  within." Each port carries open-frequency value; `--top-ports N` scans N
  most-commonly-open ports. Reported coverage: default 1,000 ports catches ~93% of open
  TCP ports; `-F` (fast, 100 ports) ~78% TCP; 10 TCP ports covers ~50% of open ports; 576
  ports reaches ~90%. Insight: "the vast majority of open ports fall within a much smaller
  set."
  Source: https://nmap.org/book/performance-port-selection.html
- **Service/version detection (`-sV`).** Separate step *after* port found open: Nmap
  connects & interrogates w/ service-specific probes from `nmap-service-probes` database
  (1,000+ signatures across 180+ protocols), matches response, reports service
  name/product (e.g. "Apache httpd"), version, extra info (protocol version, modules),
  hostname, sometimes OS / device type. Framing: port number alone tells you port 25 is
  open but not which mail server version runs there.
  Source: https://nmap.org/book/vscan.html

## UX & result presentation
Zenmap = Nmap's official cross-platform GUI, "designed to make Nmap easy for beginners to
use while providing advanced features for experienced users." Presentation ideas worth
noting:
- **Scan profiles / presets.** Named, saved command profiles (e.g. quick scan, intense
  scan) so users repeat common scans w/o re-specifying flags.
- **Command wizard + always-visible command line.** Interactive builder that *always
  shows the exact command it will run* — beginners learn, experts verify. Great pattern:
  expose the "real" operation behind friendly UI.
- **Multiple result tabs:** Nmap Output (raw), **Ports/Hosts** (pivot: ports across hosts,
  or hosts by service), Topology (network map), Host Details (per-host summary), Scans
  (history).
- **Aggregation & comparison.** Multiple scans combined & viewed at once, runs diffed to
  show new/disappearing hosts/services.
- **Persistent searchable results.** Scans saved to searchable store; no need to pre-plan
  filenames.
Source: https://nmap.org/book/zenmap.html

## Other tools & services offered
Nmap = ecosystem, not one binary:
- **Nmap** core scanner + **NSE** (Nmap Scripting Engine) for vuln checks & extended
  probing.
- **Zenmap** — official GUI (above).
- **Ncat** — netcat replacement (read/write across networks).
- **Ndiff** — scan-result diff tool.
- **Nping** — packet generation / response analysis.
- **Npcap** — project's Windows packet-capture/-send driver (also used by Wireshark &
  others).
Sources: https://nmap.org/book/ , https://npcap.com/

## Business / monetization model
- **Open source core.** Nmap itself free/open-source, used by millions.
- **Npcap OEM licensing = commercial engine.** Free Npcap edition limited (up to 5
  systems, no external redistribution; unlimited only when used solely w/
  Nmap/Wireshark/MS Defender for Identity). Revenue from two paid OEM tiers:
  **Redistribution License** (companies embedding Npcap in a product;
  perpetual-unlimited or annual, w/ support) & **Internal-Use License** (enterprises
  deploying past the 5-system cap; silent installers, support). Project explicitly funds
  Npcap dev by "selling Npcap OEM."
  Source: https://npcap.com/
- **The book.** *Nmap Network Scanning* by Gordon Lyon (ISBN 978-0-9799587-1-7, 2009,
  ~468 pp, list $49.95). About half content free online as reference guide; print edition
  adds exclusive chapters (firewall/IDS evasion, performance optimization, scanning
  algorithms). Free reference & paid book complementary — quick reference vs.
  comprehensive depth.
  Source: https://nmap.org/book/
- **Takeaway for us:** "open tool, monetize the hard-to-replicate adjacent asset (driver /
  book)" pattern — not directly applicable to a free portfolio tool, but a clean example
  of free-core + paid-edge split.

## Ideas to steal (for OUR client-side port scanner)
- **Adopt Nmap's uncertainty states instead of binary open/closed.** A browser connect
  attempt (fetch/WebSocket/img w/ timeout) can reliably distinguish only a few outcomes.
  Map onto honest labels:
  - Fast connection refused / immediate error → **closed** (something there, nothing
    listening).
  - Successful connect / handshake → **open**.
  - **Timeout / no signal → `filtered` (or "unknown"), never "open".** Single most
    important borrow: browser genuinely *cannot tell* open from silently-dropped —
    precisely Nmap's `open|filtered` / `filtered` case. Name it, don't guess it.
- **Use `open|filtered` verbatim as a state** for the common "we got nothing back" result,
  w/ one-line tooltip lifted from Nmap's framing: unable to determine whether open or
  filtered because no response was received.
- **Explain that a port state reflects what the probe could observe from the visitor's
  browser, not ground truth** — echo Nmap's "these states describe how the scanner
  perceives the port" caveat. Sets honest expectations, pre-empts "your tool is wrong"
  complaints.
- **Ship a frequency-ranked default port set, not 1–65535.** Steal `--top-ports` idea:
  offer presets like "Top 10 / Top 100 / Top 1000" w/ honest coverage framing ("Top 100
  finds most services people actually run"). Browser can only reasonably probe a handful
  of ports, so a curated well-known-port list (w/ human labels: 22 SSH, 80 HTTP, 443
  HTTPS, 3389 RDP, 3306 MySQL...) far more useful than a raw range.
- **Scan-mode presets à la Zenmap profiles** — e.g. "Common web ports", "Remote access",
  "Databases" — instead of asking a layperson to type port numbers.
- **Show the underlying operation** the way Zenmap always displays the command line — e.g.
  surface "attempting connection to host:port (timeout 2s)" so result is legible &
  trustworthy.
- **Service labels as aspiration, not detection.** True `-sV` version detection impossible
  from a browser, but we can *label* well-known ports w/ conventional service name. Be
  clear it's "port 443 is conventionally HTTPS," not "we detected HTTPS."

## Limitations & caveats
- Nmap is **server/host-side w/ raw packet access**; none of its scan *techniques* (SYN,
  FIN, idle, UDP) reproducible in a browser sandbox — we borrow vocabulary & product
  framing only.
- Browsers restrict cross-origin/mixed-content requests & block many ports outright; real
  browser port-scanning is coarse (mostly connect-timing) & much less reliable than Nmap.
  Set expectations accordingly.
- Some port-state wording above quoted from WebFetch rendering of official page — very
  close to but maybe not character-perfect vs source; treat as verbatim-ish, re-check vs
  live page before quoting in user-facing copy.
- Book chapter/price details are as of 2009 first edition (per book page); current online
  discount pricing (~$33) is (unverified) beyond what the page states.
- Npcap tier specifics (perpetual vs annual, exact system caps) summarized from npcap.com
  & may change; verify before citing precise terms.

## Sources
- https://nmap.org/book/man-port-scanning-basics.html (six port states, verbatim definitions)
- https://nmap.org/book/performance-port-selection.html (--top-ports, nmap-services frequency ranking)
- https://nmap.org/book/vscan.html (service/version detection, -sV)
- https://nmap.org/book/zenmap.html (Zenmap GUI result presentation)
- https://npcap.com/ (Npcap licensing / OEM funding model)
- https://nmap.org/book/ (Nmap Network Scanning book; free-vs-paid content)
