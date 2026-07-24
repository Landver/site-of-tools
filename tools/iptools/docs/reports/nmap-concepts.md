# Nmap — port-state vocabulary to borrow
> The canonical CLI port scanner. We are NOT copying it — we borrow its honest **result model** (six port states) and its **frequency-ranked port list** to describe uncertain browser-side probes truthfully.

## Overview
Nmap ("Network Mapper") is the reference open-source port scanner and network
discovery tool, authored by Gordon "Fyodor" Lyon. It is a **server/host-side
CLI** tool that sends crafted TCP/UDP/SCTP/IP packets and interprets responses.
It is architecturally the opposite of our tool (we probe from the visitor's
browser, no raw sockets), so we cannot copy its *techniques*. What is worth
stealing is its **vocabulary and result model**: a small, honest set of port
states that explicitly encode *uncertainty*, and a ranked "which ports actually
matter" list. Both map directly onto the browser's core constraint — a browser
frequently **cannot tell open from filtered**, and Nmap already has precise
words for exactly that situation.
Source: https://nmap.org/book/man-port-scanning-basics.html

## Port scanning / network probing — how it works
- **Server-side, raw packets.** Nmap runs on the scanning host and sends probes
  directly (SYN scan, connect scan, UDP, FIN/NULL/Xmas, idle scan, etc.). Not
  relevant to us mechanically — a browser has no raw sockets — but the *result
  states* it derives are what we borrow.
- **The six port states (verbatim-ish from the official docs).** Nmap stresses
  these describe *how Nmap perceives the port*, not an inherent property; "the
  same port may appear differently depending on network location and scan
  parameters."
  1. **open** — "An application is actively accepting TCP connections, UDP
     datagrams or SCTP associations on this port."
  2. **closed** — "A closed port is accessible (it receives and responds to Nmap
     probe packets), but there is no application listening on it."
  3. **filtered** — "Nmap cannot determine whether the port is open because
     packet filtering prevents its probes from reaching the port." The filtering
     may be "a dedicated firewall device, router rules, or host-based firewall
     software." A filter may send an ICMP error (e.g. type 3 code 13) but
     "filters that simply drop probes without responding are far more common."
  4. **unfiltered** — "The unfiltered state means that a port is accessible, but
     Nmap is unable to determine whether it is open or closed." (Only from ACK
     scan.)
  5. **open|filtered** — "Nmap places ports in this state when it is unable to
     determine whether a port is open or filtered." Occurs "for scan types in
     which open ports give no response" — namely **UDP, IP protocol, FIN, NULL,
     and Xmas scans**. The point: silence is ambiguous — either the port is open
     and stayed quiet, or a filter dropped the probe/response.
  6. **closed|filtered** — "This state is used when Nmap is unable to determine
     whether a port is closed or filtered. It is only used for the IP ID idle
     scan."
  Source: https://nmap.org/book/man-port-scanning-basics.html
- **The key idea for us:** two of the six states (`filtered`, `open|filtered`)
  exist *specifically to name the case where the scanner got no clear signal.*
  Nmap never guesses "open" when it doesn't know — it downgrades to an explicit
  uncertainty state. That is exactly the discipline a browser probe needs.
- **`--top-ports` / `nmap-services` frequency ranking.** Rather than scan all
  65,536 ports, Nmap ships a frequency table (in the `nmap-services` file) built
  from empirical scans of "tens of millions of Internet IP addresses as well as
  enterprise networks scanned from within." Each port carries an open-frequency
  value; `--top-ports N` scans the N most-commonly-open ports. Reported
  coverage: default 1,000 ports catches ~93% of open TCP ports; `-F` (fast, 100
  ports) ~78% TCP; just 10 TCP ports already covers ~50% of open ports; 576
  ports reaches ~90%. Insight: "the vast majority of open ports fall within a
  much smaller set."
  Source: https://nmap.org/book/performance-port-selection.html
- **Service/version detection (`-sV`).** Separate step *after* a port is found
  open: Nmap connects and interrogates with service-specific probes from the
  `nmap-service-probes` database (1,000+ signatures across 180+ protocols),
  matches the response, and reports service name/product (e.g. "Apache httpd"),
  version, extra info (protocol version, modules), hostname, and sometimes OS /
  device type. Framing: port number alone tells you port 25 is open but not
  which mail server version runs there.
  Source: https://nmap.org/book/vscan.html

## UX & result presentation
Zenmap is Nmap's official cross-platform GUI, "designed to make Nmap easy for
beginners to use while providing advanced features for experienced users."
Presentation ideas worth noting:
- **Scan profiles / presets.** Named, saved command profiles (e.g. quick scan,
  intense scan) so users repeat common scans without re-specifying flags.
- **Command wizard + always-visible command line.** Interactive builder that
  *always shows the exact command it will run* — beginners learn, experts
  verify. Great pattern: expose the "real" operation behind the friendly UI.
- **Multiple result tabs:** Nmap Output (raw), **Ports/Hosts** (pivot: ports
  across hosts, or hosts by service), Topology (network map), Host Details
  (per-host summary), Scans (history).
- **Aggregation & comparison.** Multiple scans can be combined and viewed at
  once, and runs can be diffed to show new hosts / services appearing or
  disappearing.
- **Persistent searchable results.** Scans saved to a searchable store; no need
  to pre-plan filenames.
Source: https://nmap.org/book/zenmap.html

## Other tools & services offered
Nmap is an ecosystem, not one binary:
- **Nmap** core scanner + **NSE** (Nmap Scripting Engine) for vuln checks and
  extended probing.
- **Zenmap** — official GUI (above).
- **Ncat** — netcat replacement (read/write across networks).
- **Ndiff** — scan-result diff tool.
- **Nping** — packet generation / response analysis.
- **Npcap** — the project's Windows packet-capture/-send driver (also used by
  Wireshark and others).
Sources: https://nmap.org/book/ , https://npcap.com/

## Business / monetization model
- **Open source core.** Nmap itself is free/open-source, used by millions.
- **Npcap OEM licensing is the commercial engine.** The free Npcap edition is
  limited (up to 5 systems, no external redistribution; unlimited only when used
  solely with Nmap/Wireshark/MS Defender for Identity). Revenue comes from two
  paid OEM tiers: a **Redistribution License** (companies embedding Npcap in a
  product; perpetual-unlimited or annual, with support) and an **Internal-Use
  License** (enterprises deploying past the 5-system cap; silent installers,
  support). The project explicitly funds Npcap development by "selling Npcap
  OEM."
  Source: https://npcap.com/
- **The book.** *Nmap Network Scanning* by Gordon Lyon (ISBN 978-0-9799587-1-7,
  2009, ~468 pp, list $49.95). About half the content is free online as the
  reference guide; the print edition adds exclusive chapters (firewall/IDS
  evasion, performance optimization, scanning algorithms). Free reference and
  paid book are complementary — quick reference vs. comprehensive depth.
  Source: https://nmap.org/book/
- **Takeaway for us:** the "open tool, monetize the hard-to-replicate adjacent
  asset (driver / book)" pattern — not directly applicable to a free portfolio
  tool, but a clean example of a free-core + paid-edge split.

## Ideas to steal (for OUR client-side port scanner)
- **Adopt Nmap's uncertainty states instead of a binary open/closed.** A browser
  connect attempt (fetch/WebSocket/img with a timeout) can reliably distinguish
  only a few outcomes. Map them onto honest labels:
  - Fast connection refused / immediate error → **closed** (something is there,
    nothing listening).
  - Successful connect / handshake → **open**.
  - **Timeout / no signal → `filtered` (or "unknown"), never "open".** This is
    the single most important borrow: the browser genuinely *cannot tell* open
    from silently-dropped, which is precisely Nmap's `open|filtered` /
    `filtered` case. Name it, don't guess it.
- **Use `open|filtered` verbatim as a state** for the common "we got nothing
  back" result, with a one-line tooltip lifted from Nmap's own framing: unable
  to determine whether open or filtered because no response was received.
- **Explain that a port state reflects what the probe could observe from the
  visitor's browser, not ground truth** — echo Nmap's "these states describe how
  the scanner perceives the port" caveat. Sets honest expectations and
  pre-empts "your tool is wrong" complaints.
- **Ship a frequency-ranked default port set, not 1–65535.** Steal the
  `--top-ports` idea: offer presets like "Top 10 / Top 100 / Top 1000" with the
  honest coverage framing ("Top 100 finds most services people actually run").
  A browser can only reasonably probe a handful of ports, so a curated
  well-known-port list (with human labels: 22 SSH, 80 HTTP, 443 HTTPS, 3389 RDP,
  3306 MySQL...) is far more useful than a raw range.
- **Scan-mode presets à la Zenmap profiles** — e.g. "Common web ports", "Remote
  access", "Databases" — instead of asking a layperson to type port numbers.
- **Show the underlying operation** the way Zenmap always displays the command
  line — e.g. surface "attempting connection to host:port (timeout 2s)" so the
  result is legible and trustworthy.
- **Service labels as an aspiration, not detection.** True `-sV` version
  detection is impossible from a browser, but we can *label* well-known ports
  with their conventional service name. Be clear it's "port 443 is conventionally
  HTTPS," not "we detected HTTPS."

## Limitations & caveats
- Nmap is **server/host-side with raw packet access**; none of its scan
  *techniques* (SYN, FIN, idle, UDP) are reproducible in a browser sandbox — we
  borrow vocabulary and product framing only.
- Browsers restrict cross-origin/mixed-content requests and block many ports
  outright; real browser port-scanning is coarse (mostly connect-timing) and
  much less reliable than Nmap. Set expectations accordingly.
- Some port-state wording above is quoted from the WebFetch rendering of the
  official page and is very close to but may not be character-perfect against
  the source; treat as verbatim-ish and re-check against the live page before
  quoting in user-facing copy.
- Book chapter/price details are as of the 2009 first edition (per the book
  page); current online discount pricing (~$33) is (unverified) beyond what the
  page states.
- Npcap tier specifics (perpetual vs annual, exact system caps) are summarized
  from npcap.com and may change; verify before citing precise terms.

## Sources
- https://nmap.org/book/man-port-scanning-basics.html (six port states, verbatim definitions)
- https://nmap.org/book/performance-port-selection.html (--top-ports, nmap-services frequency ranking)
- https://nmap.org/book/vscan.html (service/version detection, -sV)
- https://nmap.org/book/zenmap.html (Zenmap GUI result presentation)
- https://npcap.com/ (Npcap licensing / OEM funding model)
- https://nmap.org/book/ (Nmap Network Scanning book; free-vs-paid content)
