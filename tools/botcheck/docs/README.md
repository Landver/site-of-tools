# Bot check (`botcheck.corpberry.com`) — docs index

Live score of how much visitor's browser looks human vs bot. Fuses **client-side signals**
(vendored JS collector) with **server-observed signals** (HTTP headers + IP reputation),
cross-checks both — disagreements give automation away. Output: 0–100 authenticity score,
verdict band (`human` / `suspicious` / `bot`, plus `good-bot` for verified crawler/AI agent),
transparent per-signal breakdown.

**Thesis:** client signals all spoofable, so detection power lives in server cross-checking
what browser *claims* vs what connection *actually shows*. Tool reuses entire server-observed
IP layer from [`iptools`](../../iptools/docs/README.md) (IP2Proxy PX12 + IP2Location) for free —
essentially "a JS collector + a deterministic server scorer."

> **Naming:** tool is **Bot check** (display name) / `botcheck` (Go package, routes,
> `botcheck.corpberry.com` subdomain). "Bot-or-not" refers only to competitor research
> ([RESEARCH.md](RESEARCH.md) + [reports/](reports/)), never this tool.

## How this folder is organized

An **index, not a document** — every topic lives in own file so reader (human or AI) opens
only what current task needs, not one multi-thousand-line dump. About to grep across every
file here to answer one question? Stop, check table first — almost certainly one file already
answers it.

### Design & reference (how the tool works today)

| File | What's in it |
|---|---|
| [architecture.md](architecture.md) | Package layout, request-flow diagram, routes & content negotiation, Client-Hints opt-in detail |
| [signals-server.md](signals-server.md) | Server-observed signals: IP reputation, headers, fingerprint corpus, what we structurally can't see (TLS/TCP) |
| [signals-client.md](signals-client.md) | Client-collected signals: everything vendored JS collector gathers, by technique |
| [scoring-model.md](scoring-model.md) | Tiers (hard/consistency/soft), weights, good-bot override, how `Evaluate` turns signals into score |
| [storage.md](storage.md) | Mongo fingerprint corpus (G41/G42) — what's stored, TTL, nil-safety |
| [collector-provenance.md](collector-provenance.md) | OSS projects hand-vendored collector borrows technique from, license notes |
| [go-test-suite.md](go-test-suite.md) | Go test conventions (`botcheck_test.go` / `handler_test.go` / `corpus_test.go`) and structural limitation of that suite worth knowing |

### Research (how competitors work)

| File | What's in it |
|---|---|
| [RESEARCH.md](RESEARCH.md) | How 12 public bot-detection services work, how our test browser scored against each |
| [reports/](reports/) | 12 firsthand per-service writeups `RESEARCH.md` summarizes |

### Roadmap (what's shipped, what's not, why)

| | |
|---|---|
| [roadmap/README.md](roadmap/README.md) | Start here — index, executive summary, how to read ratings, links to every category file (client signals, network layer, behavioral, IP reputation, persistent identity, scoring fusion, reporting/UX, enforcement, collector hardening, deferred/non-goals, internal backlog) |
| [roadmap/changelog.md](roadmap/changelog.md) | Dated build-status history |

### Testing (does detection actually work, verified against real tools)

| | |
|---|---|
| [testing/README.md](testing/README.md) | npm/Puppeteer-based test harness architecture (gitignored, not shipped) — why it exists, how to run it, how to add a framework |
| [testing/findings-log.md](testing/findings-log.md) | Dated findings — confirmed bugs, confirmed-dead techniques, what real stealth tooling does and doesn't evade |
| [testing/next-steps.md](testing/next-steps.md) | Prioritized open items from audit |

## Scope & non-goals

`GET /` renders page shell (short explainer, "your request" server card like iptools connection
inspector, vendored collector script); collector gathers client signals, POSTs to `POST /check`,
which fuses with server signals, runs scorer, returns HTML fragment (browser) or JSON (API/CLI)
by content negotiation. Full detail in [architecture.md](architecture.md).

**Non-goals:** self-test/inspection tool, **not inline WAF**. Doesn't block requests, set
verdict cookie, or protect other endpoints — returns score for *the person looking at the page*.
("Enforcement mode" other tools could call is possible later bolt-on — see
[roadmap/enforcement.md](roadmap/enforcement.md).) Full list of deferred items and explicit
non-goals lives in [roadmap/deferred-nongoals.md](roadmap/deferred-nongoals.md).
