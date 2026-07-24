# CanYouSeeMe.org
> A dead-simple, single-purpose web tool that tells you whether one TCP port on your own public IP is reachable from the outside internet.

## Overview
CanYouSeeMe.org is a long-running, minimalist "open port check" utility. Its
stated purpose is to remotely verify whether a single port is open or closed,
so users can confirm **port forwarding** works, check whether a server/service
is reachable, or find out if a **firewall or ISP is blocking** a port
([canyouseeme.org](https://canyouseeme.org/)). The whole product is one page:
an auto-filled IP field, one port field, one button, and a one-line result.

Important framing for our project: this tool checks **inbound reachability**
(can the outside world connect *in* to a port on *your* machine). That is the
opposite direction from a browser-side scanner, which can only make **outbound**
connections. See Limitations — the technique is not portable to our use case,
but the UX and copy absolutely are.

## Port scanning / network probing — how it works
- **Server-side, not client-side.** When you click the check button, your
  browser submits the IP + port to canyouseeme.org's **server**, which then
  attempts to open a TCP connection *back to your public IP on that port* from
  the outside. The result reflects whether that inbound TCP handshake
  succeeded. The visitor's browser does no probing itself
  ([canyouseeme.org](https://canyouseeme.org/); corroborated by
  [portcheckers.com review](https://www.portcheckers.com/canyouseeme)).
- **Auto-detects the visitor's public IP.** The IP field is pre-populated with
  the requester's public address ("Your IP:"), so most users only type a port
  ([WebFetch of canyouseeme.org home](https://canyouseeme.org/); the IP
  auto-fill is also noted in [portcheckers.com review](https://www.portcheckers.com/canyouseeme)).
  You *can* edit the IP, but the tool is designed around checking your own.
- **One port at a time.** You enter a single port number and check it. There is
  no port range, no comma-separated list, no "scan all common ports" on
  canyouseeme.org itself (that multi-port behavior belongs to *other* sites like
  portcheckers.com, not this one).
- **Result states: effectively OPEN vs NOT-OPEN (with a reason).** It is a
  binary success/failure result rather than the nmap-style
  open/closed/filtered taxonomy:
  - **Success (port reachable):**
    `Success: I can see your service on <IP> on port (<port>) Your ISP is not blocking port <port>`
    ([techsupportforum thread quoting canyouseeme](https://www.techsupportforum.com/threads/solved-port-forwarding-connection-timed-out-cant-get-ports-open-or-forwarded.823073/);
    [anandtech forum quoting canyouseeme](https://forums.anandtech.com/threads/cant-get-port-forward-to-work.2339215/post-35433324)).
  - **Failure (port not reachable):**
    `Error: I could not see your service on <IP> on port (<port>) Reason: <reason>`
    where `<reason>` is a human-readable TCP outcome such as **Connection timed
    out**, **Connection refused**, or **No route to host**
    ([techsupportforum](https://www.techsupportforum.com/threads/solved-port-forwarding-connection-timed-out-cant-get-ports-open-or-forwarded.823073/);
    [netgate forum](https://forum.netgate.com/topic/119873/canyouseeme-reports-errors-for-my-port-forward-can-t-figure-out-why)).
  - Note the tool folds "filtered/timeout" and "closed/refused" into the single
    Error line and just surfaces the raw TCP reason string. It does not label a
    distinct "filtered" state the way a scanner would.

## UX & result presentation
- **Radical simplicity.** One screen, minimal chrome. Heading is "Open Port
  Check Tool" with the tagline "Verify Port Forwarding on Your Router"
  ([canyouseeme.org](https://canyouseeme.org/)). Below it: IP field (pre-filled),
  a port field, and a single check button (labeled to the effect of "Check
  Port"). Nothing else competes for attention.
- **Success/failure copy is the star.** The result is one plain-English
  sentence written in the first person ("I can see your service…" / "I could not
  see your service…"). It is unambiguous, non-technical, and directly answers
  the user's actual question ("can you see me?"). The success line even
  volunteers the reassuring interpretation ("Your ISP is not blocking port X"),
  and the error line gives the *reason* so the user knows what to fix.
- **Common-ports reference table** on the same page lists standard ports so
  non-experts know what to type: FTP (21), SSH (22), SMTP (25), DNS (53),
  HTTP (80), plus app/game ports like Remote Desktop (3389) and Minecraft
  (25565) ([WebFetch of canyouseeme.org](https://canyouseeme.org/)).
- **Educational "Background" section** explains port forwarding in plain terms
  and warns that "Most residential ISP's block ports to combat viruses and
  spam," calling out port 80 (HTTP) and port 25 (SMTP) specifically
  ([WebFetch of canyouseeme.org](https://canyouseeme.org/)). This both helps the
  user and provides SEO/keyword text.

## Other tools & services offered
- Essentially **none — it is deliberately single-purpose.** The page is just the
  port checker, the common-ports table, the background explainer, a privacy
  policy link, and a legal disclaimer footer
  ([canyouseeme.org](https://canyouseeme.org/)).
- (Contrast: review/aggregator sites such as
  [portcheckers.com](https://www.portcheckers.com/canyouseeme) bundle DNS lookup,
  SSL check, proxy test, ping, and multi-port scanning — but those are *their*
  features, **not** canyouseeme.org's. Don't attribute them to canyouseeme.)

## Business / monetization model
- **Ad-supported.** The site is a free utility monetized through display
  advertising; it carries no paid tier, login, or product. (The provided
  static-content fetch didn't surface ad markup, so exact ad network/placements
  are **(unverified)**, but the site is widely characterized as a free,
  ad-supported single-page tool — e.g. [ipaddress.com profile](https://www.ipaddress.com/website/www.canyouseeme.org/).)
- No accounts, no data product, no API offering advertised on the page.
- A **legal disclaimer** ("THE INFORMATION ON THIS PAGE IS STRICTLY FOR
  INFORMATIONAL PURPOSES ONLY") and a privacy policy link are the only
  policy-style content ([WebFetch of canyouseeme.org](https://canyouseeme.org/)).

## Ideas to steal (for OUR client-side port scanner)
- **One-question flow.** Auto-fill the target (their IP is already known
  server-side; for us, a scan target field defaulted sensibly), make the user
  supply the minimum (a port), one button, one answer. Resist adding options
  above the fold.
- **First-person, plain-English result sentences.** Steal the voice: a single
  clear line the user can act on. Adapt to our (outbound) direction, e.g.
  success → "Port <port> on <target> is open (accepted a connection)."
  failure → "Port <port> on <target> is not reachable. Reason: <timeout / refused>."
- **Surface the *reason*, not just open/closed.** Distinguish
  timeout-vs-refused-style outcomes in the copy so the user knows whether it's a
  firewall/filter (timeout) or nothing listening (refused). This maps cleanly
  onto our filtered-vs-closed states.
- **Volunteer the interpretation.** Like "Your ISP is not blocking port X,"
  add a reassuring/actionable clause to the success/failure line instead of
  making the user infer meaning.
- **Inline common-ports cheat sheet** (21/22/80/443/3389/25565…) as clickable
  chips that fill the port field — helps non-experts and doubles as SEO copy.
- **Short "Background" explainer + disclaimer** on the same page: educates,
  ranks in search, and sets legal expectations, all without another page load.
- **Naming/branding hook.** The name literally *is* the question the user is
  asking ("can you see me?"). A memorable, question-shaped name is cheap
  marketing.

## Limitations & caveats
- **Technique does NOT transfer to a browser-side scanner.** CanYouSeeMe works
  because its *server* initiates an **inbound** connection to the visitor's IP.
  A scanner running in the visitor's browser can only make **outbound**
  connections and cannot cause a third party to connect back inbound. So we can
  steal the UX/copy, but not the mechanism — our client-side scan answers a
  different question (can *this browser* reach a target) than canyouseeme (can
  *the outside world* reach *you*).
- **Only meaningful if a service is actually listening.** A success requires
  something bound to that port on the user's side; otherwise even a correctly
  forwarded port returns an Error. Users routinely misread this
  ([netgate forum](https://forum.netgate.com/topic/119873/canyouseeme-reports-errors-for-my-port-forward-can-t-figure-out-why)).
- **TCP-oriented, single port, no range/UDP visibility** advertised on the page.
- **Binary result collapses nuance.** It does not expose a formal
  open/closed/filtered/stealth taxonomy; it reports success or an Error+reason.
  Fine for its audience, but less precise than a real scanner.
- **Exact current button label, on-submit markup, and ad placements are
  (unverified)** from a static fetch — the result line only renders after a live
  server round-trip, so the quoted success/error strings come from users quoting
  the tool in forums rather than from the rendered page.

## Sources
- https://canyouseeme.org/ (home / tool page)
- https://www.ipaddress.com/website/www.canyouseeme.org/ (site profile)
- https://www.portcheckers.com/canyouseeme (third-party review; note it conflates its own multi-tool features)
- https://www.techsupportforum.com/threads/solved-port-forwarding-connection-timed-out-cant-get-ports-open-or-forwarded.823073/ (users quoting exact success/error strings)
- https://forums.anandtech.com/threads/cant-get-port-forward-to-work.2339215/post-35433324 (success string quoted)
- https://forum.netgate.com/topic/119873/canyouseeme-reports-errors-for-my-port-forward-can-t-figure-out-why (error behavior; "must have a service listening" caveat)
