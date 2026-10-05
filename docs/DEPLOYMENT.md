# Deployment — corpberry.com

Dev + prod = **same host**. Prod = Docker; dev = local Go toolchain + live
reload. CI/CD = GitHub Actions (`.github/workflows/ci.yml`): every push/PR to
`master` runs `go vet` + `go build` + `go test -race`; green push to `master`
auto-deploys to prod over SSH (§8).

App design → [ARCHITECTURE.md](ARCHITECTURE.md); this doc = host/edge/container
plumbing.

---

## 1. The request path

```
Cloudflare (proxy ON, TLS)  →  nginx (TLS termination, per-subdomain server{})  →  Go container :8080
```

Cloudflare = **only** thing in front of nginx -> client-IP trust model (§4)
safe.

---

## 2. Ports & binding

- Go listens **:8080** inside container (`LISTEN_ADDR=:8080` = `0.0.0.0:8080`).
  **Bind `0.0.0.0`, not `127.0.0.1`** — container-loopback unreachable from nginx.
- Docker publishes on **bridge gateway**: `172.17.0.1:8080:8080` (docker-compose.yml).
  That IP only — off public interface, reachable from nginx container (on bridge).
- nginx reaches app at gateway: `proxy_pass http://172.17.0.1:8080;`.

---

## 3. nginx (per subdomain)

One `server{}` block per subdomain, living in the reverse-proxy project's
`conf.d` (`/srv/my_projects/nginx-reverse-proxy/conf.d/`), not in this repo.
All -> same `:8080` upstream, all forward `Host` (else host routing collapses)
+ client-IP headers.

TLS reuses proxy's Let's Encrypt cert
(`/etc/letsencrypt/live/llm.corpberry.com/`), like every *.corpberry.com vhost —
Cloudflare terminates browser TLS (proxy ON), so origin cert name needn't match.
Reload after editing a block:
```bash
docker exec nginx-reverse-proxy-nginx-1 nginx -t \
  && docker exec nginx-reverse-proxy-nginx-1 nginx -s reload
```
`nginx -t` must pass before reload; bad config rejected, running config stays —
other (client) sites safe. New subdomain = block in proxy's `conf.d` + proxied
Cloudflare DNS record + entry in `main.go`'s `subdomains` list and `apps` map.
502s until app runs on `:8080` & DNS points here.

### `mcp.corpberry.com` (launch checklist)

The MCP server ships in the binary; this is what the edge needs before it is
announced (tools/mcptools/docs/02-security-and-ops.md §10).

- **Cloudflare DNS:** proxied record `mcp`. Proxied records publish `A`
  records, which claude.ai needs (its connectors are IPv4-only).
- **nginx block:** a copy of an existing corpberry block with
  `server_name mcp.corpberry.com;`, forwarding `Host` + the client-IP headers
  like every block, plus `client_max_body_size 1m;` (the app refuses bodies
  over 1 MiB anyway; don't copy cipher's 8m). **No SSE settings**: every
  request gets one plain JSON body (stateless, JSON responses), so no
  `proxy_buffering off`, long `proxy_read_timeout` or `X-Accel-Buffering`.
- **Ingress gate (§4):** confirm on the proxy host that it accepts connections
  only from Cloudflare's published ranges, or uses Authenticated Origin Pulls.
- **Bot Fight Mode off.** On the Free plan it is zone-wide and can't be
  skipped per hostname; it can block Anthropic's connectors and MCP scanners. The
  site's own `curl` users suggest it is off: confirm. Optional backstop: one
  generous Cloudflare rate-limit rule on `mcp.*`, sized for connector IPs that
  many users share.
- **`.env.prod`:** `EGRESS_DENY_ADDRS` and `MCP_OWNER_KEY` (§5).
- **Check:** `claude mcp add --scope user --transport http corpberry
  https://mcp.corpberry.com/mcp` lists and calls tools, and so does a claude.ai
  custom connector on a toolset URL. Its `Origin`, logged as `mcp: foreign
  Origin`, is what D15's allowlist will be built from.

---

## 4. Client-IP trust model

Request log records *real* visitor IP (not nginx's); future features may use it.

- `IPExtractor` prefers **`CF-Connecting-IP`**, then `X-Forwarded-For` (trusted
  hops), then `RemoteAddr`.
- Those headers **spoofable by anyone reaching app directly**. Two guards:
  (1) app published only on bridge gateway (§2), not public interface -> nginx =
  sole front door; (2) Cloudflare = only thing upstream -> nginx sets
  `CF-Connecting-IP` from Cloudflare, client can't inject it.
- Guard (2) holds only if the proxy **accepts connections from Cloudflare
  alone** (its published ranges, or Authenticated Origin Pulls). Not checkable
  from this repo; verify on the proxy host. **Load-bearing for rate limits:**
  every per-client budget, REST and MCP, keys on this IP
  (`platform.RateLimitKey`), so a forged header reaching nginx directly would
  buy a fresh bucket per request on every subdomain.

---

## 5. Docker

**Dockerfile** — two stages: `golang:1.26` build stage fetches arch-correct
Tailwind standalone binary, builds stylesheet, compiles fully static Go binary
(embeds templates + built CSS + vendored JS); then distroless-static runtime.
Full file [`../Dockerfile`](../Dockerfile); shape:

```dockerfile
# 1) Build: Tailwind CSS (standalone, no Node) + fully static Go binary.
FROM golang:1.26 AS build
ARG TARGETARCH                 # docker's amd64/arm64 → Tailwind's x64/arm64
WORKDIR /src
# The golang image already ships curl + ca-certs, so no separate debian CSS stage.
RUN case "$TARGETARCH" in amd64) TW=x64;; arm64) TW=arm64;; esac; \
    curl -fsSL -o /usr/local/bin/tailwindcss \
      "https://github.com/tailwindlabs/tailwindcss/releases/download/v4.3.2/tailwindcss-linux-$TW" \
    && chmod +x /usr/local/bin/tailwindcss
COPY go.mod go.sum ./          # cache deps before copying the tree
RUN go mod download
COPY . .
RUN tailwindcss -i shared/static/css/input.css -o shared/static/css/styles.css --minify
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app .

# 2) Runtime: distroless-static (CA certs + tzdata + nonroot, ~2 MB).
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /app /app
ENV APP_ENV=prod
ENTRYPOINT ["/app"]
```
`CGO_ENABLED=0` mandatory for distroless-static; `ip2location-go/v9` = pure Go,
fine. Run `make deps` (writes `go.sum`) before building.

**docker-compose.yml** — publish on bridge gateway (nginx-reachable, §2), env
from `.env` + `.env.prod` (later wins), bind-mount DB assets **read-only** at
same repo-relative path app uses. Binary cwd = `/`, so relative `IP2LOCATION_*`
paths resolve to mount unchanged:
```yaml
ports:    ["172.17.0.1:8080:8080"]
env_file: [.env, .env.prod]
volumes:  ["./tools/iptools/assets:/tools/iptools/assets:ro"]   # IP2LOCATION_* env → /tools/iptools/assets/...
```
`.env.prod` (per host, gitignored) also needs:
- `EGRESS_DENY_ADDRS` — the host's public IPv4 and its IPv6 /64,
  comma-separated. Every outbound guard (link trace, RDAP/CT redirects,
  MTA-STS, nameserver probes) refuses them; inside the container
  `net.InterfaceAddrs` never sees them, so without this a trace can loop back
  to the origin behind Cloudflare.
- `MCP_OWNER_KEY` — the owner's key for `mcp.corpberry.com/mcp/owner`
  (`openssl rand -base64 32`). Empty → that endpoint is 404; the public ones
  don't need it.

---

## 6. The DB assets

IP2Location LITE BINs large (DB11 92M+216M, ASN 156M+262M, + 1.7 GB IP2Proxy
PX12 — all read via `ReadAt`, ~no RAM). Gitignored; never in git or image.

- On host: `tools/iptools/assets/`, bind-mounted read-only.
- `make assets` (→ `tools/iptools/download-assets.sh`) (re)downloads via
  `IP2LOCATION_DOWNLOAD_TOKEN` from `.env`.

---

## 7. Local development

Install once on host:
- **Go 1.26.x** — extract downloaded tarball:
  ```bash
  sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.26.5.linux-arm64.tar.gz
  echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc
  ```
  (No LTS; bump ~every 6mo to stay in supported window.)
- **Tailwind + air + git hooks** — `make tools` (downloads arch-correct Tailwind
  binary, installs air, enables pre-push hook).
- **Deps + DBs** — `make deps` (writes `go.sum`), then `make assets`.

Run it (two terminals, or wire own):
```bash
make css-watch      # Tailwind --watch → rebuilds styles.css on edits
make dev            # air: rebuild+restart the Go binary on .go edits (APP_ENV=dev)
```
Open **http://localhost:8080** & **http://ip.localhost:8080** — browsers route
`*.localhost` to 127.0.0.1, so host routing works w/ no `/etc/hosts` edits. In
dev, templates read from disk & re-parse per req, so `.html` edits show on
refresh, no rebuild (air rebuilds only on `.go` changes).

Tests: `make test` (`go test ./... -race`). Pre-push hook runs `go vet` +
`go test`, blocks failing push.

---

## 8. Deploy

Automated. `.github/workflows/ci.yml` runs `go vet` + `go build` + `go test -race`
on every push & PR to **`master`**; green push to `master` (or manual **Run
workflow**) then runs `deploy` job: SSHes to prod, fast-forwards + rebuilds:
```bash
git fetch --prune origin && git checkout master && git merge --ff-only origin/master
docker compose up -d --build
```
So merging to `master` ships to prod. Whole pipeline keyed on `master` (CI
triggers, deploy ref guard, SSH checkout/merge) — `master` = standing default
branch, don't rename w/o updating all three.

Break-glass (manual deploy on host, e.g. Actions down):
```bash
git pull && docker compose up -d --build && docker compose logs -f site-of-tools
```

---

## 9. MongoDB (external dependency)

App can talk to shared **MongoDB** at `localhost`, dedicated `site-of-tools` DB.
Unlike IP2Location BINs (§6), this = **network dependency, not bind-mounted
file** — nothing to download or mount.

- **Config, not volumes.** `MONGODB_URI` (& optional `MONGODB_DATABASE`) in
  `.env`, which `docker-compose` loads via `env_file` (§5), so value reaches
  container w/ **no compose change & no new volume**. Container needs outbound
  network to reach server.
- **Per-host secret.** `.env` gitignored & per-host, deploy = `git merge
  --ff-only` (§8) that never touches it — so add `MONGODB_URI` to **prod host's
  `.env`** separately; not shipped by deploy. Same URI works dev & prod.
- **Optional + fail-fast.** Empty `MONGODB_URI` disables Mongo cleanly
  (`ErrMongoUnavailable`); set-but-unreachable server fails fast at open time
  (10s server-selection timeout) vs hanging. Two features use it now — IP-tool
  lookup history & request log — both degrade to no-ops when disabled, so app
  still boots w/o a DB.
- **Provisioning.** Mongo creates a DB on first write, so `site-of-tools` only
  "exists" once something writes to it. Run `make mongo-init` once from a host
  that can reach server to create it explicitly (adds empty `_meta` collection,
  idempotent).

> **Reachability caveat.** `localhost` = Cloudflare-proxied DNS record, &
> Cloudflare's proxy won't forward raw MongoDB TCP (port 27017) — so server
> reachable only from hosts on its allowed network path (e.g. prod host /
> internal network), **not** from arbitrary machine. Provision the DB & run
> Mongo-backed work from such a host.
