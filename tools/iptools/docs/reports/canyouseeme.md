# CanYouSeeMe.org
> Dead-simple, single-purpose web tool: tells you whether one TCP port on your own public IP is reachable from outside internet.

## Overview
Long-running, minimalist "open port check" utility. Stated purpose: remotely
verify whether a single port open or closed, so users confirm **port forwarding**
works, check whether server/service reachable, or find out if **firewall or ISP
blocking** a port
([canyouseeme.org](https://canyouseeme.org/)). Whole product = one page:
auto-filled IP field, one port field, one button, one-line result.

Framing for our project: this tool checks **inbound reachability** (can outside
world connect *in* to a port on *your* machine). Opposite direction from a
browser-side scanner, which can only make **outbound** connections. See
Limitations — technique not portable to our use case, but UX & copy are.

## Port scanning / network probing — how it works
- **Server-side, not client-side.** Click check button -> browser submits IP +
  port to canyouseeme.org's **server**, which then attempts to open a TCP
  connection *back to your public IP on that port* from outside. Result reflects
  whether that inbound TCP handshake succeeded. Visitor's browser does no
  probing itself
  ([canyouseeme.org](https://canyouseeme.org/); corroborated by
  [portcheckers.com review](https://www.portcheckers.com/canyouseeme)).
- **Auto-detects visitor's public IP.** IP field pre-populated w/ requester's
  public address ("Your IP:"), so most users only type a port
  ([WebFetch of canyouseeme.org home](https://canyouseeme.org/); IP auto-fill
  also noted in [portcheckers.com review](https://www.portcheckers.com/canyouseeme)).
  You *can* edit the IP, but tool designed around checking your own.
- **One port at a time.** Enter single port number, check it. No port range, no
  comma-separated list, no "scan all common ports" on canyouseeme.org itself
  (that multi-port behavior belongs to *other* sites like portcheckers.com, not
  this one).
- **Result states: effectively OPEN vs NOT-OPEN (with a reason).** Binary
  success/failure rather than nmap-style open/closed/filtered taxonomy:
  - **Success (port reachable):**
    `Success: I can see your service on <IP> on port (<port>) Your ISP is not blocking port <port>`
    ([techsupportforum thread quoting canyouseeme](https://www.techsupportforum.com/threads/solved-port-forwarding-connection-timed-out-cant-get-ports-open-or-forwarded.823073/);
    [anandtech forum quoting canyouseeme](https://forums.anandtech.com/threads/cant-get-port-forward-to-work.2339215/post-35433324)).
  - **Failure (port not reachable):**
    `Error: I could not see your service on <IP> on port (<port>) Reason: <reason>`
    where `<reason>` is human-readable TCP outcome such as **Connection timed
    out**, **Connection refused**, or **No route to host**
    ([techsupportforum](https://www.techsupportforum.com/threads/solved-port-forwarding-connection-timed-out-cant-get-ports-open-or-forwarded.823073/);
    [netgate forum](https://forum.netgate.com/topic/119873/canyouseeme-reports-errors-for-my-port-forward-can-t-figure-out-why)).
  - Note: tool folds "filtered/timeout" & "closed/refused" into single Error
    line & just surfaces raw TCP reason string. Does not label a distinct
    "filtered" state the way a scanner would.

## UX & result presentation
- **Radical simplicity.** One screen, minimal chrome. Heading "Open Port
  Check Tool" w/ tagline "Verify Port Forwarding on Your Router"
  ([canyouseeme.org](https://canyouseeme.org/)). Below it: IP field (pre-filled),
  port field, single check button (labeled ~ "Check Port"). Nothing else
  competes for attention.
- **Success/failure copy is the star.** Result = one plain-English first-person
  sentence ("I can see your service…" / "I could not see your service…").
  Unambiguous, non-technical, directly answers user's actual question ("can you
  see me?"). Success line even volunteers reassuring interpretation ("Your ISP
  is not blocking port X"); error line gives *reason* so user knows what to fix.
- **Common-ports reference table** on same page lists standard ports so
  non-experts know what to type: FTP (21), SSH (22), SMTP (25), DNS (53),
  HTTP (80), plus app/game ports like Remote Desktop (3389) & Minecraft
  (25565) ([WebFetch of canyouseeme.org](https://canyouseeme.org/)).
- **Educational "Background" section** explains port forwarding in plain terms,
  warns "Most residential ISP's block ports to combat viruses and spam,"
  calling out port 80 (HTTP) & port 25 (SMTP) specifically
  ([WebFetch of canyouseeme.org](https://canyouseeme.org/)). Helps user &
  provides SEO/keyword text.

## Other tools & services offered
- Essentially **none — deliberately single-purpose.** Page = just port checker,
  common-ports table, background explainer, privacy policy link, legal
  disclaimer footer
  ([canyouseeme.org](https://canyouseeme.org/)).
- (Contrast: review/aggregator sites such as
  [portcheckers.com](https://www.portcheckers.com/canyouseeme) bundle DNS lookup,
  SSL check, proxy test, ping, & multi-port scanning — but those are *their*
  features, **not** canyouseeme.org's. Don't attribute them to canyouseeme.)

## Business / monetization model
- **Ad-supported.** Free utility monetized via display advertising; no paid
  tier, login, or product. (Provided static-content fetch didn't surface ad
  markup, so exact ad network/placements **(unverified)**, but site widely
  characterized as free, ad-supported single-page tool — e.g.
  [ipaddress.com profile](https://www.ipaddress.com/website/www.canyouseeme.org/).)
- No accounts, no data product, no API advertised on the page.
- **Legal disclaimer** ("THE INFORMATION ON THIS PAGE IS STRICTLY FOR
  INFORMATIONAL PURPOSES ONLY") & privacy policy link are only policy-style
  content ([WebFetch of canyouseeme.org](https://canyouseeme.org/)).

## Ideas to steal (for OUR client-side port scanner)
- **One-question flow.** Auto-fill target (their IP already known server-side;
  for us, scan target field defaulted sensibly), user supplies minimum (a port),
  one button, one answer. Resist adding options above the fold.
- **First-person, plain-English result sentences.** Steal the voice: single
  clear line user can act on. Adapt to our (outbound) direction, e.g.
  success → "Port <port> on <target> is open (accepted a connection)."
  failure → "Port <port> on <target> is not reachable. Reason: <timeout / refused>."
- **Surface the *reason*, not just open/closed.** Distinguish
  timeout-vs-refused-style outcomes in copy so user knows whether firewall/filter
  (timeout) or nothing listening (refused). Maps cleanly onto our
  filtered-vs-closed states.
- **Volunteer the interpretation.** Like "Your ISP is not blocking port X,"
  add reassuring/actionable clause to success/failure line instead of making
  user infer meaning.
- **Inline common-ports cheat sheet** (21/22/80/443/3389/25565…) as clickable
  chips that fill port field — helps non-experts & doubles as SEO copy.
- **Short "Background" explainer + disclaimer** on same page: educates, ranks
  in search, sets legal expectations, all w/o another page load.
- **Naming/branding hook.** Name literally *is* the question user asking ("can
  you see me?"). Memorable, question-shaped name = cheap marketing.

## Limitations & caveats
- **Technique does NOT transfer to a browser-side scanner.** CanYouSeeMe works
  because its *server* initiates an **inbound** connection to visitor's IP. A
  scanner in the visitor's browser can only make **outbound** connections,
  cannot cause a third party to connect back inbound. So steal UX/copy, not
  mechanism — our client-side scan answers a different question (can *this
  browser* reach a target) than canyouseeme (can *the outside world* reach
  *you*).
- **Only meaningful if a service is actually listening.** Success requires
  something bound to that port on user's side; otherwise even a correctly
  forwarded port returns an Error. Users routinely misread this
  ([netgate forum](https://forum.netgate.com/topic/119873/canyouseeme-reports-errors-for-my-port-forward-can-t-figure-out-why)).
- **TCP-oriented, single port, no range/UDP visibility** advertised on the page.
- **Binary result collapses nuance.** No formal open/closed/filtered/stealth
  taxonomy; reports success or Error+reason. Fine for its audience, less precise
  than a real scanner.
- **Exact current button label, on-submit markup, & ad placements
  (unverified)** from a static fetch — result line only renders after a live
  server round-trip, so quoted success/error strings come from users quoting
  the tool in forums rather than the rendered page.

## Sources
- https://canyouseeme.org/ (home / tool page)
- https://www.ipaddress.com/website/www.canyouseeme.org/ (site profile)
- https://www.portcheckers.com/canyouseeme (third-party review; note it conflates its own multi-tool features)
- https://www.techsupportforum.com/threads/solved-port-forwarding-connection-timed-out-cant-get-ports-open-or-forwarded.823073/ (users quoting exact success/error strings)
- https://forums.anandtech.com/threads/cant-get-port-forward-to-work.2339215/post-35433324 (success string quoted)
- https://forum.netgate.com/topic/119873/canyouseeme-reports-errors-for-my-port-forward-can-t-figure-out-why (error behavior; "must have a service listening" caveat)
