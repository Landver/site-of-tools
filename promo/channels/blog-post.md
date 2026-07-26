# The blog post (your canonical content piece)

Single most reusable asset in whole campaign. Write it **once**,
publish on a home you control, then every other channel points at it:
Show HN first comment, dev.to / Hashnode cross-posts, Golang Weekly
& Changelog submissions, LinkedIn follow-up, Reddit posts.

---

## Canonical strategy (do this or you compete with yourself for SEO)

1. **Pick ONE canonical home.** Best options: post on **corpberry.com** (your
   domain, your SEO) or **Hashnode blog on custom domain**. Publish there
   first.
   ✅ **DONE 2026-07-28:** canonical home is `https://corpberry.com/blog/reverse-engineering-12-bot-detectors`
   (blog built into the apex site; the filled draft lives at `site/posts/2026-07-28-reverse-engineering-12-bot-detectors.md`).
   Use this URL everywhere the playbook says "blog post URL".
2. **Cross-post everywhere else w/ canonical URL pointing back.** On
   dev.to set `canonical_url` in front-matter. On Hashnode set it in Draft
   Settings → "Are you republishing?" **before** publishing (can't add it
   after). On Medium use "Import a story" (sets `rel=canonical` automatically).
3. Never let dev.to / Medium be only home. They outrank your own domain for
   your own words otherwise.

---

## Which angle to lead with

You have two hooks. **Research** hook is stronger than **tool** hook,
because "here's my tool" is common & "here's what I found tearing down 12
commercial bot detectors" is rare & genuinely interesting. Lead w/
research, let tool be the thing readers reach for at the end.

Suggested title (pick one):

- **What I learned reverse-engineering 12 commercial bot detectors (and the open-source checker I built from it)**
- **Every browser bot-detector claims to catch you. I built an open-source one that shows exactly how.**
- **68 signals that give your headless browser away — an open-source, transparent bot-detection self-test**

---

## Full draft (edit freely — it's a starting point, not scripture)

> Fill the `[BRACKETED]` spots with a real number, screenshot, or finding from
> your own `tools/botcheck/docs/` notes. Those specifics are what make it yours
> and what people quote.

```markdown
# What I learned reverse-engineering 12 bot detectors (and the open-source checker I built)

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

Bot check runs [68] tiered checks on exactly that principle. It fuses:

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
  string, iphey-style checks feature-test whether the engine behaves like Blink,
  Gecko, or WebKit, then compare that to what the UA claims. [ADD YOUR FINDING]
- **CreepJS goes deep on lie detection.** It doesn't just check `toString` for
  `[native code]`; it walks property descriptors and traps whether `call`/`new`
  throw the right `TypeError`. Sobering finding: current stealth plugins evade
  most of it anyway. [ADD YOUR FINDING]
- **The unforgeable layer is the network.** The edge vendors cross-check the
  TLS/TCP/HTTP2 handshake against the claimed browser. That's the one class of
  signal a JavaScript spoofer can't touch. It's also the one I structurally
  can't see: behind Cloudflare, my origin only sees Cloudflare's own connection.
  I say so plainly on the page instead of pretending otherwise.
- **Honesty is a feature.** deviceandbrowserinfo states outright that its verdict
  doesn't use IP or behavior; incolumitas warns "false positives are expected."
  That candor is what makes a checker trustworthy as a reference.

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
```

---

## After it's published

- Grab canonical URL. You'll paste it into: Show HN first comment
  (`channels/hackernews.md`), Golang Weekly / Changelog / Console.dev
  submissions, dev.to & Hashnode cross-posts, & LinkedIn follow-up.
- "ADD YOUR FINDING" spots: pull one concrete, specific detail each from
  `tools/botcheck/docs/reports/` & `tools/botcheck/docs/testing/findings/`.
  Specifics are what get quoted & what separate this from every other launch
  post.

## Sources / verified
- Canonical / cross-post mechanics: dev.to `canonical_url`, Hashnode pre-publish
  canonical, Medium "Import a story" (verified July 2026).
