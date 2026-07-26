---
title: "What I learned reverse-engineering 12 commercial bot detectors (and the open-source checker I built from it)"
description: "I studied 12 bot detectors firsthand and built Bot check — a free, open-source, 68-signal bot-detection self-test that shows every signal and exactly how it scored you. Here's what I found."
date: "2026-07-28"
---

I run a small collection of tools at corpberry.com. The one I've put the most
into is Bot check: a live score of how much your browser looks like a human
versus an automated bot. It's free, open source, and it shows every signal it
uses. This post is about why I built it that way, and what I found when I studied
how the commercial detectors actually work.

## The thesis: a browser can claim anything

Every signal a browser reports over JavaScript is spoofable. User-agent,
platform, screen size, the `navigator` object, canvas output, WebGL vendor: a
determined script can lie about all of it, and stealth tooling like
puppeteer-extra-plugin-stealth does exactly that, well.

So trusting what the browser *claims* is a losing game. The detection power is in
the cross-check: compare what the browser says against what the connection and
the deeper fingerprint actually reveal, and look for the disagreements. A
headless browser can tell you it's Chrome on Windows. It's much harder for it to
make that claim survive its HTTP header order, its IP reputation, and the way its
JavaScript engine feature-tests as Blink-versus-Gecko all agreeing.

Bot check runs 68 tiered checks on exactly that principle. It fuses:

- a client-side JavaScript fingerprint,
- server-observed HTTP headers,
- and IP reputation (datacenter / VPN / proxy / Tor),

then cross-checks the three and shows you every signal, why it fired, and how
much it moved the score. Verdict comes out as human, suspicious, bot, or
"good-bot" for a verified crawler like Googlebot.

## What the commercial services do well

To build it I studied 12 public detectors firsthand: CreepJS, FingerprintJS,
DataDome, BrowserScan, iphey, pixelscan, sannysoft, whoer, AmIUnique, EFF's
Cover Your Tracks, incolumitas, and deviceandbrowserinfo. A few things stood out:

- **The best ones feature-detect the real engine.** Instead of trusting the UA
  string, iphey's engine (the open-source MixVisit core) probes for APIs only a
  given engine has: `webkitResolveLocalFileSystemURL` + `BatteryManager` +
  `navigator.vendor` for Chromium, `buildID` + `onmozfullscreenchange` for
  Gecko, `ApplePayError` for WebKit — then compares the answer to what the UA
  claims. Bot check ships its own version of this: one check fingerprints the
  JS VM itself from the `Error` stack format (V8's ` at ` frames vs
  SpiderMonkey's `fn@url` frames and proprietary `fileName`/`lineNumber`). When
  I pointed a browser claiming to be Firefox at it, the real engine stayed V8 —
  and the check fired.
- **CreepJS goes deep on lie detection.** It doesn't just check `toString` for
  `[native code]`; per API function it checks illegal own-properties and
  descriptors (`prototype`/`arguments`/`caller`), and traps whether calling,
  `new`, `apply`, or class-`extends` throws the correct `TypeError`. The
  sobering part: I built six checks specifically targeting the patches
  puppeteer-extra-plugin-stealth installs — and stealth 2.11.2 evaded all six,
  cleanly, including hiding `navigator.webdriver` in the main thread, iframes,
  *and* Service Workers. What caught it instead was three boring cross-context
  consistency checks (UA, CPU cores, and WebGL renderer disagreeing between
  contexts) — enough for a 25/100 "bot". Then it got better: a single illegal
  call, `Function.prototype.toString.call(null)`, leaked stealth's Proxy
  through a raw stack frame, because a recent V8 stack-format change silently
  broke stealth's own stack-stripping logic. With that check in, stealth's
  score dropped from 25 to 0.
- **The unforgeable layer is the network.** The edge vendors cross-check the
  TLS/TCP/HTTP2 handshake against the claimed browser. That's the one class of
  signal a JavaScript spoofer can't touch from the page. It's also the one I
  structurally can't see: Cloudflare terminates the visitor's TLS at its own
  edge and opens a *separate* connection to my origin, so the ClientHello my
  server sees is Cloudflare's, identical for every visitor. (Cloudflare will
  sell you the real fingerprint as a header — gated behind Enterprise Bot
  Management, which is a steep price for a personal tool.) I say so plainly on
  the page instead of pretending otherwise.
- **Honesty is a feature.** deviceandbrowserinfo states outright that its verdict
  doesn't use IP or behavior; incolumitas warns "false positives are expected."
  That candor is what makes a checker trustworthy as a reference.

## What it catches in practice

I ran the real thing against five automation setups. Playwright headless
Chromium: 0/100 — `webdriver`, the `HeadlessChrome` UA, and the SwiftShader
software renderer gave it away. Selenium + chromedriver: 0/100 — plus
chromedriver's classic `$cdc_...` global markers, all seven of them. The
humbling one was a hand-rolled raw-CDP Chromium with no automation flags: 40/100,
caught almost entirely by its `HeadlessChrome` user-agent while every
architectural check read clean. A disciplined custom client evades nearly
everything client-side, and I've documented that as an accepted gap rather than
pretending the score is magic.

## Why open source, why transparent

Most polished checkers are either closed demos for a paid product or opaque about
how the number is computed. I wanted the opposite: a checker you can read. The
scorer is open source, every signal is shown with a plain reason, and the repo
includes my writeups of all 12 services. A low score means "looks automated,"
not "is malicious," and privacy-hardened or VPN users will score lower by design.
It stores nothing but a one-way hash of the stable fingerprint plus IP, on a
30-day rolling window, purely to spot the same fingerprint reused across many
IPs. It blocks nothing. It's a mirror, not a firewall.

## The boring-but-nice engineering bit

The whole site, portfolio plus every tool, is one Go binary that routes by
subdomain. Server-rendered HTML with htmx and Alpine, and zero Node: Tailwind
runs via its standalone CLI and the little JS is vendored. Every endpoint
content-negotiates, so every tool is also a curl-able JSON API for free. I'm a
Python backend dev by day; Go's "one static binary, no runtime" story is why
this is one `docker compose up` instead of a stack.

## Try it / read it

- Tool: https://botcheck.corpberry.com
- Point a headless browser at it and watch it get caught, signal by signal.
- Code + the 12-service research: https://github.com/Landver/site-of-tools

I'd genuinely like to know what it flags on your setup, and where it's wrong.
