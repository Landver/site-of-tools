# Bot check (`botcheck.corpberry.com`) — docs index

A live score of how much the visitor's browser looks like a human vs. an
automated bot. It fuses **client-side signals** (collected by a vendored JS
collector) with **server-observed signals** (HTTP headers + IP reputation) and
cross-checks the two — the disagreements are what give automation away. Output is
a 0–100 authenticity score, a verdict band (`human` / `suspicious` / `bot`, plus
`good-bot` for a verified crawler / AI agent), and a transparent per-signal breakdown.

**The thesis:** client signals are all spoofable, so the detection power lives in
the server cross-checking what the browser *claims* against what the connection
*actually shows*. The tool reuses the entire server-observed IP layer from
[`iptools`](../../iptools/docs/README.md) (IP2Proxy PX12 + IP2Location) for free, so it is
essentially "a JS collector + a deterministic server scorer."

> **Naming:** the tool is **Bot check** (display name) / `botcheck` (the Go
> package, routes, and the `botcheck.corpberry.com` subdomain). "Bot-or-not"
> refers only to the competitor research ([RESEARCH.md](RESEARCH.md) +
> [reports/](reports/)), never to this tool.

## How this folder is organized

This is an **index, not a document** — every topic below lives in its own file
so a reader (human or AI) only opens what the current task needs, instead of
one multi-thousand-line dump. If you're about to grep across every file in
this folder to answer one question, stop and check the table first — there's
almost certainly a single file that already answers it.

### Design & reference (how the tool works today)

| File | What's in it |
|---|---|
| [architecture.md](architecture.md) | Package layout, the request-flow diagram, routes & content negotiation, the Client-Hints opt-in detail |
| [signals-server.md](signals-server.md) | Server-observed signals: IP reputation, headers, the fingerprint corpus, what we structurally can't see (TLS/TCP) |
| [signals-client.md](signals-client.md) | Client-collected signals: everything the vendored JS collector gathers, by technique |
| [scoring-model.md](scoring-model.md) | Tiers (hard/consistency/soft), weights, the good-bot override, how `Evaluate` turns signals into a score |
| [storage.md](storage.md) | The Mongo fingerprint corpus (G41/G42) — what's stored, TTL, nil-safety |
| [collector-provenance.md](collector-provenance.md) | OSS projects the hand-vendored collector borrows technique from, and license notes |
| [go-test-suite.md](go-test-suite.md) | Go test conventions (`botcheck_test.go` / `handler_test.go` / `corpus_test.go`) and a structural limitation of that suite worth knowing |

### Research (how competitors work)

| File | What's in it |
|---|---|
| [RESEARCH.md](RESEARCH.md) | How 12 public bot-detection services work, and how our test browser scored against each |
| [reports/](reports/) | The 12 firsthand per-service writeups `RESEARCH.md` summarizes |

### Roadmap (what's shipped, what's not, why)

| | |
|---|---|
| [roadmap/README.md](roadmap/README.md) | Start here — index, executive summary, how to read the ratings, links to every category file (client signals, network layer, behavioral, IP reputation, persistent identity, scoring fusion, reporting/UX, enforcement, collector hardening, deferred/non-goals, internal backlog) |
| [roadmap/changelog.md](roadmap/changelog.md) | Dated build-status history |

### Testing (does detection actually work, verified against real tools)

| | |
|---|---|
| [testing/README.md](testing/README.md) | The npm/Puppeteer-based test harness architecture (gitignored, not shipped) — why it exists, how to run it, how to add a framework |
| [testing/findings-log.md](testing/findings-log.md) | Dated findings — confirmed bugs, confirmed-dead techniques, what real stealth tooling does and doesn't evade |
| [testing/next-steps.md](testing/next-steps.md) | Prioritized open items from the audit |

## Scope & non-goals

`GET /` renders a page shell (a short explainer, a "your request" server card
like the iptools connection inspector, and the vendored collector script); the
collector gathers client signals and POSTs them to `POST /check`, which fuses them
with the server signals, runs the scorer, and returns an HTML fragment (browser)
or JSON (API/CLI) by content negotiation. Full detail in
[architecture.md](architecture.md).

**Non-goals:** this is a self-test/inspection tool, **not an inline WAF**. It does
not block requests, set a verdict cookie, or protect other endpoints — it returns
a score for *the person looking at the page*. (An "enforcement mode" other tools
could call is a possible later bolt-on — see
[roadmap/enforcement.md](roadmap/enforcement.md).) The full list of deferred
items and explicit non-goals lives in
[roadmap/deferred-nongoals.md](roadmap/deferred-nongoals.md).
