# Deployment — corpberry.com

Host, edge and container plumbing; app design is in
[ARCHITECTURE.md](ARCHITECTURE.md). Dev and prod share **one host**: prod runs
in Docker, dev uses the local Go toolchain with live reload.

## 1. The request path

```
Cloudflare (proxy ON, TLS) → nginx (TLS, one server{} per subdomain) → Go container :8080
```

## 2. Ports & binding

Go binds **`0.0.0.0:8080`** in the container (loopback is unreachable from
nginx). Compose publishes it on the bridge gateway only, `172.17.0.1:8080`, and
nginx proxies to `http://172.17.0.1:8080`.

## 3. nginx (per subdomain)

Blocks live in the reverse-proxy project, `/srv/my_projects/nginx-reverse-proxy/conf.d/`,
not in this repo. Each forwards `Host` (else host routing collapses) and the
client-IP headers; TLS reuses the proxy's Let's Encrypt cert (Cloudflare
terminates browser TLS, so the name needn't match). Reload:

```bash
docker exec nginx-reverse-proxy-nginx-1 nginx -t && docker exec nginx-reverse-proxy-nginx-1 nginx -s reload
```

New subdomain = a block in `conf.d` + a proxied Cloudflare DNS record + an
entry in `main.go`'s `subdomains` list. It 502s until the app serves it.

**mcp.corpberry.com** also needs `client_max_body_size 1m;` (don't copy
cipher's 8m) and no SSE settings (every reply is one JSON body); Cloudflare
**Bot Fight Mode off** (zone-wide on the Free plan; it blocks MCP clients); and
the §5 env vars. Check with
`claude mcp add --scope user --transport http corpberry https://mcp.corpberry.com/mcp`
and a claude.ai custom connector; the `Origin` it logs (`mcp: foreign Origin`)
seeds the Origin allowlist.

## 4. Client-IP trust model

Client IP = `CF-Connecting-IP`, then trusted `X-Forwarded-For`, then
`RemoteAddr`. Safe only because the app is published on the bridge gateway
alone and nginx **accepts connections from Cloudflare alone** (its ranges or
Authenticated Origin Pulls) — verify that on the proxy host. Every rate limit,
REST and MCP, keys on this IP; a forged header reaching nginx directly would buy
unlimited buckets.

## 5. Docker

[`Dockerfile`](../Dockerfile): a `golang:1.26` stage fetches the arch-correct
Tailwind binary, builds `styles.css` and a static binary (`CGO_ENABLED=0`,
required for distroless); the runtime is `distroless/static-debian12:nonroot`
with just `/app`. A commit that doesn't change the binary rebuilds to an
identical image, so compose doesn't recreate the container.

`docker-compose.yml`: `ports: ["172.17.0.1:8080:8080"]`, `env_file: [.env,
.env.prod]` (later wins), IP2Location assets bind-mounted **read-only** at the
same relative path (binary cwd is `/`).

`.env.prod` (per host, gitignored) also holds:
- `EGRESS_DENY_ADDRS` — the host's public IPv4 and IPv6 /64, comma-separated.
  The container can't see them and every outbound guard must refuse them, or a
  trace can loop back to the origin behind Cloudflare.
- `MCP_OWNER_KEY` — `openssl rand -base64 32`; empty → `/mcp/owner` is 404.

## 6. The DB assets

IP2Location BINs (~2.4 GB incl. IP2Proxy PX12, read via `ReadAt`, ~no RAM):
gitignored, in `tools/iptools/assets/` on the host, bind-mounted read-only,
fetched by `make assets` (`IP2LOCATION_DOWNLOAD_TOKEN` in `.env`).

## 7. Local development

Once: Go 1.26.x (no LTS; bump about every 6 months), `make tools` (Tailwind,
air, git hooks), `make deps`, `make assets`. Then `make css-watch` and
`make dev` in two terminals, and open `http://localhost:8080` /
`http://ip.localhost:8080` (browsers route `*.localhost` to 127.0.0.1).
Templates re-parse per request in dev; air rebuilds on `.go` changes.

## 8. Deploy

`.github/workflows/ci.yml` runs `go vet`, `go build` and `go test -race` on
every push and PR to **`master`**. A green push to `master` (or a manual run)
SSHes to prod and runs:

```bash
git fetch --prune origin && git checkout master && git merge --ff-only origin/master
docker compose up -d --build
```

So merging to `master` ships. The pipeline is keyed on `master` in three places
(triggers, deploy ref guard, SSH checkout); don't rename it without all three.
Break-glass on the host: `git pull && docker compose up -d --build`.

## 9. MongoDB

A network dependency, configured by `MONGODB_URI` (+ optional
`MONGODB_DATABASE`) in each host's `.env`; deploys never touch it. Empty →
every Mongo feature no-ops and the app boots stateless; set but unreachable →
fails fast (10 s). `make mongo-init` creates the DB up front. Reachable only from
hosts on its network path (Cloudflare doesn't proxy port 27017).
