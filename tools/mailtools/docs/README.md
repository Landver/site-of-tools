# Mail Tools (`mail.corpberry.com`)

Email deliverability, infrastructure security, and forensics suite on one subdomain (`mail.corpberry.com`), switched by sub-nav. All features speak HTML (htmx), JSON REST API, and MCP tools, with client-side WebAssembly execution available for privacy-sensitive parsers.

## Features & Routing

| Route | Page / Function | Engine | Description |
|---|---|---|---|
| `GET`, `POST /`<br>`GET`, `POST /health` | **Domain & Email Intelligence Audit** | Server (`health.go`) | All-in-one health score (0–100) aggregating SPF, DMARC, DKIM, MTA-STS, DANE TLSA, BIMI, Secure Email Gateway (SEG) detection, and multi-DNSBL reputation with actionable advice. |
| `GET`, `POST /disposable` | **Disposable Email Checker** | In-Memory (`domain_index.go`) | Detects over 10,000+ throwaway, burner, and temporary email domains. Auto-synced daily from upstream blocklists with wildcard parent domain matching. |
| `GET`, `POST /classifier` | **Domain Classifier** | In-Memory (`domain_index.go`) | Classifies email addresses/domains into corporate business accounts vs. personal free consumer webmail (Gmail, Yahoo, Proton, Mail.ru, etc.). Protected by enterprise whitelist. |
| `GET`, `POST /blacklist` | **Multi-DNSBL Reputation Checker** | Server (`dnsbl.go`) | High-concurrency lookup querying 15+ global spam blacklists (Spamhaus ZEN/DBL, Barracuda, SpamCop, Mailspike, SURBL, URIBL). Responses cached in MongoDB with 20-min TTL. |
| `GET`, `POST /dmarc`<br>`POST /dmarc/parse` | **DMARC Report Visualizer & Analyzer** | Server + Client WASM (`dmarc.go`, `wasm/`) | Parses RFC 7489 aggregate XML and `.xml.gz` reports (RUA). Evaluates SPF/DKIM alignment, IP sources, ESP provider identification, and policy disposition. |
| `GET`, `POST /bimi`<br>`POST /bimi/fix` | **BIMI & VMC Validator** | Server + Client WASM (`bimi.go`, `vmc.go`, `wasm/`) | Audits SVG logos against BIMI Tiny P/S requirements (<= 32 KB, square aspect ratio, no external links/scripts) with one-click auto-fix. Cryptographically validates Verified Mark Certificates (VMC). |
| `GET`, `POST /arc`<br>`POST /arc/parse` | **ARC Header Analyzer** | Server + Client WASM (`arc.go`, `wasm/`) | Inspects RFC 8617 Authenticated Received Chain header structure (`ARC-Seal`, `ARC-Message-Signature`, `ARC-Authentication-Results`), hop sequence, and intermediate authentication results. |

## Architecture & Security Principles

1. **Layered Design (CLAUDE.md #1)**:
   - Handlers in `handler.go` parse inputs, invoke domain services, and return results via `platform.Reply`.
   - Domain logic (`health.go`, `auth.go`, `dane.go`, `spf_eval.go`, `seg.go`, `dnsbl.go`, `domain_index.go`, `dmarc.go`, `bimi.go`, `vmc.go`, `arc.go`) is pure Go.
2. **Outbound SSRF Protection (EgressGuard)**:
   - All outbound HTTPS requests (MTA-STS policy fetching at `mta-sts.<domain>` and VMC certificates from `a=` tags) are routed strictly through `platform.EgressGuard`.
   - EgressGuard restricts ports to 443, enforces strict timeouts, checks host deny lists, and refuses HTTP redirects per RFC 8461 §3.3.
3. **Privacy-Preserving WASM Engine**:
   - `dmarc.go`, `bimi.go`, and `arc.go` can compile to WebAssembly (`wasm/main.go` via `engine.go`).
   - When executed in the visitor's browser, confidential email reports, headers, and brand logos never leave the client's tab.
4. **Rate Limiting & Concurrency Capping**:
   - Pure routes (`/disposable`, `/classifier`, `/bimi`, `/arc`) share `Limits.Pure` (10 req/s, burst 50).
   - Heavy network/parsing routes (`/health`, `/blacklist`, `/dmarc`) share `Limits.Heavy` (2 req/s, burst 10) backed by `HeavyCap` semaphore (8 concurrent tasks) to protect system resources.
5. **Persistence & Self-Pruning**:
   - Multi-DNSBL query results are cached in MongoDB collection `email_dnsbl_cache` via `Store` (`store.go`) with an automatic TTL index of 20 minutes (`platform.EnsureTTLIndex`).
6. **Automated Background Sync**:
   - `worker.go` runs a background worker (`RunSync`), refreshing disposable domain blocklists from canonical sources 1 minute after server boot and every 24 hours thereafter, atomically updating `DomainClassifier` via `sync/atomic.Pointer`.

## MCP Integration (`tools/mcptools`)

Every capability in `mailtools` maps directly to Model Context Protocol (MCP) tools:
- `mail_domain_health`: Full email health audit (SPF, DMARC, DKIM, MTA-STS, DANE, SEG, DNSBL).
- `mail_check_dnsbl`: Real-time reputation check across authoritative spam blacklists.
- `mail_classify_domain`: In-memory classification (disposable vs. free webmail vs. corporate domain).
- `mail_dmarc_parse`: DMARC aggregate XML/GZ parser with provider rollups.
- `mail_bimi_validate`: SVG Tiny P/S compliance check and auto-fix generator.
