# site-of-tools (`corpberry.com`)

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go 1.26](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](go.mod)
[![CI/CD](https://github.com/Landver/site-of-tools/actions/workflows/ci.yml/badge.svg)](https://github.com/Landver/site-of-tools/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Landver/site-of-tools?include_prereleases&logo=github)](https://github.com/Landver/site-of-tools/releases)
[![MCP Enabled](https://img.shields.io/badge/MCP-35%2B%20tools-8A2BE2)](https://mcp.corpberry.com)
[![Privacy: No Ads / No Tracking](https://img.shields.io/badge/privacy-no%20ads%20%7C%20no%20analytics-success)](https://corpberry.com)

A high-performance, privacy-first web utility and diagnostic suite. **36 specialized tools across 7 subdomains**, plus a full **Model Context Protocol (MCP)** server for AI agents — all served by a **single standalone Go binary** with zero external runtime dependencies.

---

## Highlights

- ⚡ **Single Standalone Binary**: HTML templates, CSS, and client-side WASM are embedded directly into one binary (`embed.FS`). No Node.js runtime, no complex microservices.
- 🔒 **Privacy-First (No Ads / No 3rd-Party Analytics)**: No third-party analytics scripts, no advertising trackers, no marketing cookies. Private lookups stored locally in your browser.
- 🔐 **Client-Side WASM Cryptography**: For Cipher tools, keys and plaintexts never touch the server. All cryptography executes in browser memory via compiled WebAssembly.
- 🤖 **Native MCP Server**: Every tool is exposed over the Model Context Protocol (Streamable HTTP / JSON-RPC), allowing Claude Code, Cursor, ChatGPT, and AI agents to invoke any diagnostic directly.
- 🔄 **Dual Interface (HTML + JSON API)**: Every single route serves responsive HTML for humans and structured JSON for machines (`Accept: application/json` or CLI scripts).
- 🧭 **Collapsible Sidebar Navigation**: Instant fuzzy search across titles, descriptions, and deep technical tags (`data-tags`). Collapsible sidebar (`Ctrl+B`) with synchronized state across subdomains.

---

## Tools Suite (36 Tools across 7 Subdomains)

### 🤖 [Bot Check](https://botcheck.corpberry.com) (`botcheck.corpberry.com`)
A transparent browser automation and bot-detection self-test:
- **68 Heuristic Signals**: Evaluates client-side navigator properties, CDP runtime tells, WebGL parameters, automation flags, HTTP headers, and IP reputation.
- **Scoring & Verdict**: Scores browsers 0–100 (human / suspicious / automated / verified good-bot).
- **Transparency**: Explains exactly what triggered each flag, caveats, and false-positive risks.

### 🔐 [Cipher Tools](https://cipher.corpberry.com) (`cipher.corpberry.com`)
13 in-browser cryptographic tools powered by WebAssembly (secrets never leave your machine):
- **JWT Decoder, Verifier & Signer**: Inspect headers/payloads, verify RSA/ECDSA/EdDSA/HMAC signatures, test JWK/JWKS.
- **Password Hasher & Verifier**: Benchmark and generate hashes with Argon2id, bcrypt, scrypt, and PBKDF2.
- **Hash & Checksums**: Simultaneous multi-hash engine (SHA-256, SHA-512, SHA-3, BLAKE2b/s, MD5, CRC32).
- **HMAC & Webhooks**: Constant-time signature verification for Stripe, GitHub, and custom webhooks.
- **Keys Converter**: Parse, convert, and inspect PEM, JWK, and OpenSSH keys (Ed25519, RSA, ECDSA, X25519).
- **Certificates (X.509)**: Decode and validate X.509 certificates, CSRs, and certificate chains.
- **TOTP / 2FA Authenticator**: RFC 6238 code generator, counter-based HOTP, and `otpauth://` URI parser.
- **Random & UUID**: Cryptographically secure tokens, diceware passphrases, and UUIDs (v4 / v7).
- **Encode / Decode**: Conversions for Base64, Hex, Base32, URL encoding, and HTML entities.
- **Magic String Identifier**: Heuristic detection of unknown hashes, tokens, and Hashcat modes.
- **DPoP Proofs**: RFC 9449 Demonstrating Proof-of-Possession tokens for OAuth 2.0.
- **PKCE Generator**: RFC 7636 code verifiers and SHA-256 code challenge pairs.
- **Encrypt & Decrypt**: Authenticated symmetric encryption (AES-256-GCM, ChaCha20-Poly1305).

### 🌐 [DNS Tools](https://dns.corpberry.com) (`dns.corpberry.com`)
Parallel global DNS inspection and security auditing:
- **Global Propagation Checker**: Query 28+ authoritative public resolvers worldwide in real-time.
- **Root DNSSEC Trace**: Visual iteration walk from the ICANN DNS root servers down to authoritative zone cuts.
- **Domain & Certificates**: RDAP registration inspection and crt.sh Certificate Transparency logs.
- **Email Auth DNS**: One-stop auditing for SPF records, DMARC policies, DKIM keys, BIMI, and MTA-STS.
- **Core Record Lookup**: Multi-type parallel queries (A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, CAA).

### 🌍 [IP Tools](https://ip.corpberry.com) (`ip.corpberry.com`)
Network diagnostics and IP intelligence:
- **IP Lookup & Threat Intel**: Geolocation (IP2Location LITE), ASN network owner, proxy/VPN detection, and Spamhaus DROP check.
- **Subnet Calculator**: IPv4 & IPv6 CIDR calculations, usable host ranges, netmasks, and wildcard masks.
- **Lookup History**: Local audit log of previous queries.

### 🔗 [Link Tools](https://link.corpberry.com) (`link.corpberry.com`)
11 utilities for link hygiene, redirection tracing, and cache debugging:
- **Clean Trackers**: Strips marketing parameters (`utm_*`, `fbclid`, `gclid`) and unwraps Outlook Safelinks.
- **Redirect Tracer**: Follows HTTP redirect chains, measures per-hop latency, and checks HSTS upgrade policies.
- **HTTP Headers & Cache**: Validates RFC 9111 cache control headers, stale directives, and security headers.
- **URL Parameter Diff**: Compares query strings between two URLs side-by-side.
- **Link Extractor**: Discovers, categorizes, and validates hyperlinks from any webpage.
- **UTM Campaign Builder**: Standardized marketing link creator with preset taxonomy.
- **cURL Converter**: Converts web requests into copy-pasteable terminal commands.
- **URL Percent Encoding**: RFC 3986 encoding and decoding utilities.
- **RFC 3986 Reference**: Quick reference of reserved, unreserved, and sub-delimiter characters.
- **Link Shortener**: Lightweight self-hosted short links with automatic TTL expiration.

### ✉️ [Mail Tools](https://mail.corpberry.com) (`mail.corpberry.com`)
Email deliverability and forensic diagnostics:
- **DMARC Aggregate Reports (RUA)**: Ingests and visualizes XML/GZ aggregate deliverability reports.
- **BIMI SVG Validator**: Validates SVG Tiny P/S compliance, checks dimensions/security, and provides auto-fix downloads.
- **ARC Trace Analyzer**: RFC 8617 Authenticated Received Chain header validator and seal verifier.

### 🤖 [MCP Server](https://mcp.corpberry.com) (`mcp.corpberry.com`)
Model Context Protocol endpoint exposing the entire toolset to AI workflows:
- Supports **Claude Code**, **Cursor**, **ChatGPT**, **Codex**, and **Gemini**.
- Streamable HTTP transport (`/mcp` for all tools, or dedicated per-toolset subpaths).
- Quick setup for Claude Code:
  ```bash
  claude mcp add --scope user --transport http corpberry https://mcp.corpberry.com/mcp
  ```

---

## Releases & Downloads

Precompiled standalone binaries for every release are available on the [**GitHub Releases**](https://github.com/Landver/site-of-tools/releases) page:

| Platform | Architecture | Archive |
|---|---|---|
| **Linux** | `x86_64` (amd64) | `site-of-tools-vX.Y.Z-linux-amd64.tar.gz` |
| **Linux** | `ARM64` (aarch64) | `site-of-tools-vX.Y.Z-linux-arm64.tar.gz` |
| **macOS** | Apple Silicon (`M1/M2/M3/M4`) | `site-of-tools-vX.Y.Z-darwin-arm64.tar.gz` |
| **macOS** | Intel (`x86_64`) | `site-of-tools-vX.Y.Z-darwin-amd64.tar.gz` |
| **Windows** | `x86_64` (amd64) | `site-of-tools-vX.Y.Z-windows-amd64.zip` |

Each release includes SHA256 checksums (`checksums.txt`). Simply extract the archive and run:
```bash
./site-of-tools
```

---

## Quick Start (Docker)

To run the full suite with Docker:

```bash
git clone https://github.com/Landver/site-of-tools.git
cd site-of-tools
docker compose up -d --build
```

The service binds to port `8080` and routes subdomains locally (`ip.localhost:8080`, `cipher.localhost:8080`, etc.).

---

## Development & Building from Source

### Prerequisites
- **Go 1.26+**
- Make

### Build Steps

```bash
git clone git@github.com:Landver/site-of-tools.git
cd site-of-tools

cp .env.example .env      # Optional: configure token for IP2Location or MongoDB
make tools                # Fetches standalone Tailwind CLI and Air
make css                  # Compiles and minifies shared/static/css/styles.css
make wasm                 # Compiles client-side WASM engine (cipher.wasm)
make build                # Builds static binary -> bin/server
```

### Live Development (Air)
```bash
make dev                  # Starts server with hot-reload on changes
```

### Running Tests
```bash
make test                 # Runs full unit test suite with race detector
```

---

## Architecture & Technology Stack

```
                     ┌───────────────────────────────────┐
                     │    Nginx / Cloudflare (Reverse)   │
                     └─────────────────┬─────────────────┘
                                       │ Host Header
         ┌─────────────────────────────┼─────────────────────────────┐
         ▼                             ▼                             ▼
┌──────────────────┐          ┌──────────────────┐          ┌──────────────────┐
│  corpberry.com   │          │  *.corpberry.com │          │ mcp.corpberry.com│
│   (Apex Site)    │          │  (Tools Suite)   │          │   (MCP Server)   │
└────────┬─────────┘          └────────┬─────────┘          └────────┬─────────┘
         │                             │                             │
         └─────────────────────────────┼─────────────────────────────┘
                                       ▼
                     ┌───────────────────────────────────┐
                     │  site-of-tools (Single Go Binary) │
                     │  - Echo v5 Framework              │
                     │  - Embedded Templates & Assets    │
                     │  - Dual Output: HTML + JSON API   │
                     │  - WebAssembly Cryptographic Engine│
                     └─────────────────┬─────────────────┘
                                       │ (Optional)
                     ┌─────────────────▼─────────────────┐
                     │ MongoDB (History / Request Corpus)│
                     │ (Empty URI = Runs Fully Stateless)│
                     └───────────────────────────────────┘
```

- **Backend**: Go 1.26, Echo v5
- **Frontend**: Server-rendered `html/template`, htmx, Alpine.js, Tailwind CSS v4
- **Client Engine**: In-browser Go WebAssembly (`GOOS=js GOARCH=wasm`)
- **Protocol**: REST / JSON API + Model Context Protocol (MCP 2025-11-25)
- **Database**: MongoDB (optional: for IP lookup history and request corpus; runs completely stateless when unset)

---

## Directory Layout

```
site-of-tools/
├── main.go                     # Entrypoint (single binary, host router)
├── platform/                   # Shared engine: config, render, MongoDB, catalog
├── shared/                     # Shared UI: templates (sidebar, header, head), CSS, JS
├── site/                       # Apex domain: landing page, tools overview, blog
├── tools/                      # Tool implementations (co-located code, templates & tests)
│   ├── botcheck/               # Bot Check heuristic engine & self-test
│   ├── ciphertools/            # 13 Cryptographic tools & client WASM source
│   ├── dnstools/               # Global propagation, DNSSEC trace, RDAP, Email Auth
│   ├── iptools/                # IP geolocation, threat intel, subnet CIDR calculator
│   ├── linktools/              # Tracker cleaner, redirect tracer, cache validator
│   ├── mailtools/              # DMARC RUA parser, BIMI validator, ARC seal analyzer
│   └── mcptools/               # Model Context Protocol adapter & AI tool definitions
├── .github/workflows/          # CI/CD and automated cross-platform release pipeline
└── docs/                       # Architecture and deployment documentation
```

---

## License

This project is licensed under the [MIT License](LICENSE).
IP tools include IP2Location LITE database under the [Creative Commons Attribution-ShareAlike 4.0](https://lite.ip2location.com).
