# Deployment — corpberry.com

Dev and prod run on the **same host**. Prod is Docker; dev is a local Go
toolchain with live reload. CI/CD is GitHub Actions (`.github/workflows/ci.yml`):
every push/PR to `master` runs `go vet` + `go build` + `go test -race`, and a green
push to `master` auto-deploys to the prod host over SSH (§8).

See [ARCHITECTURE.md](ARCHITECTURE.md) for the app design; this doc is the
host/edge/container plumbing.

---

## 1. The request path

```
Cloudflare (proxy ON, TLS)  →  nginx (TLS termination, per-subdomain server{})  →  Go container :8080
```

Cloudflare is the **only** thing in front of nginx. That single fact is what
makes the client-IP trust model (§4) safe.

---

## 2. Ports & binding

- The Go process listens on **:8080** inside its container (`LISTEN_ADDR=:8080`,
  i.e. `0.0.0.0:8080`). **Bind `0.0.0.0` inside the container, not `127.0.0.1`** —
  a container-loopback bind is unreachable from nginx.
- Docker publishes it on the **docker bridge gateway**: `172.17.0.1:8080:8080`
  (see docker-compose.yml). Bound to that IP only — off the public interface, but
  reachable from the nginx container, which sits on the bridge.
- So nginx (its own container) reaches the app at that gateway:
  `proxy_pass http://172.17.0.1:8080;`.

---

## 3. nginx (per subdomain)

Canonical blocks live in [`deploy/nginx/`](../deploy/nginx/) — one per subdomain,
both forwarding to the same `:8080` upstream, both forwarding `Host` (or host
routing collapses) + client-IP headers. **They are already installed** in the
proxy's `conf.d` and the proxy has been reloaded.

TLS reuses the proxy's existing Let's Encrypt cert
(`/etc/letsencrypt/live/llm.corpberry.com/`), like every other *.corpberry.com
vhost — Cloudflare terminates the browser TLS (proxy ON), so the origin cert name
needn't match. Re-deploy after editing a block:
```bash
cp deploy/nginx/*.conf /srv/my_projects/nginx-reverse-proxy/conf.d/
docker exec nginx-reverse-proxy-nginx-1 nginx -t \
  && docker exec nginx-reverse-proxy-nginx-1 nginx -s reload
```
`nginx -t` must pass before reload; a bad config is rejected and the running
config stays, so the other (client) sites are safe. Each new subdomain = a block
in `deploy/nginx/` + a proxied Cloudflare DNS record + a `cfg.VHost` entry in
`main.go`. Sites 502 until the app runs on `:8080` and DNS points here.

---

## 4. Client-IP trust model

The request log should record the *real* visitor IP (not nginx's), and future
features may use it.

- The app's `IPExtractor` prefers **`CF-Connecting-IP`**, then `X-Forwarded-For`
  (trusted hops), then `RemoteAddr`.
- Those headers are **spoofable by anyone who can reach the app directly**. Two
  things prevent that: (1) the app is published only on the docker bridge gateway
  (§2), not the public interface, so nginx is the sole front door; (2) Cloudflare
  is the only thing upstream, so nginx sets `CF-Connecting-IP` from Cloudflare and
  a client can't inject it.

---

## 5. Docker

**Dockerfile** — two stages: a `golang:1.26` build stage that fetches the
arch-correct Tailwind standalone binary, builds the stylesheet, and compiles the
fully static Go binary (embedding templates + built CSS + vendored JS); then a
distroless-static runtime stage. Full file at [`../Dockerfile`](../Dockerfile); shape:

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
`CGO_ENABLED=0` is mandatory for distroless-static; `ip2location-go/v9` is pure
Go, so it's fine. Run `make deps` (writes `go.sum`) before building.

**docker-compose.yml** — publish on the docker bridge gateway (reachable by the
nginx container, §2), env from `.env` + `.env.prod` (later wins), bind-mount the DB
assets **read-only** at the same repo-relative path the app uses. The binary runs
with cwd `/`, so the relative `IP2LOCATION_*` paths resolve to the mount unchanged:
```yaml
ports:    ["172.17.0.1:8080:8080"]
env_file: [.env, .env.prod]
volumes:  ["./tools/iptools/assets:/tools/iptools/assets:ro"]   # IP2LOCATION_* env → /tools/iptools/assets/...
```

---

## 6. The DB assets

The IP2Location LITE BINs are large (DB11 92M+216M, ASN 156M+262M, plus the
1.7 GB IP2Proxy PX12 — all read via `ReadAt`, so they cost ~no RAM). Gitignored;
never in git or the image.

- On the host they live in `tools/iptools/assets/` and are bind-mounted read-only.
- `make assets` (→ `tools/iptools/download-assets.sh`) (re)downloads them using
  `IP2LOCATION_DOWNLOAD_TOKEN` from `.env`.

---

## 7. Local development

Install once on the host:
- **Go 1.26.x** — extract the tarball you downloaded:
  ```bash
  sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.26.5.linux-arm64.tar.gz
  echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc
  ```
  (No LTS; bump ~every 6 months to stay in the supported window.)
- **Tailwind + air + git hooks** — `make tools` (downloads the arch-correct
  Tailwind binary, installs air, enables the pre-push hook).
- **Deps + DBs** — `make deps` (writes `go.sum`), then `make assets`.

Run it (two terminals, or wire your own):
```bash
make css-watch      # Tailwind --watch → rebuilds styles.css on edits
make dev            # air: rebuild+restart the Go binary on .go edits (APP_ENV=dev)
```
Open **http://localhost:8080** and **http://ip.localhost:8080** — browsers route
`*.localhost` to 127.0.0.1, so host routing works with no `/etc/hosts` edits. In
dev, templates read from disk and re-parse per request, so `.html` edits show on
refresh with no rebuild (air only rebuilds on `.go` changes).

Tests: `make test` (`go test ./... -race`). The pre-push hook runs `go vet` +
`go test` and blocks a failing push.

---

## 8. Deploy

Deploys are automated. `.github/workflows/ci.yml` runs `go vet` + `go build` +
`go test -race` on every push and PR to **`master`**; a green push to `master` (or
a manual **Run workflow**) then runs the `deploy` job, which SSHes to the prod host
and fast-forwards + rebuilds:
```bash
git fetch --prune origin && git checkout master && git merge --ff-only origin/master
docker compose up -d --build
```
So merging to `master` ships to prod. The entire pipeline is keyed on `master` (the
CI triggers, the deploy ref guard, and the SSH checkout/merge), so `master` is the
project's standing default branch — don't rename it without updating all three.

Break-glass (manual deploy on the host, e.g. if Actions is down):
```bash
git pull && docker compose up -d --build && docker compose logs -f site-of-tools
```

---

## 9. MongoDB (external dependency)

The app can talk to a shared **MongoDB** server at `mongodb.corpberry.com`, with a
dedicated `site-of-tools` database. Unlike the IP2Location BINs (§6), this is a
**network dependency, not a bind-mounted file** — nothing to download or mount.

- **Config, not volumes.** `MONGODB_URI` (and optional `MONGODB_DATABASE`) live in
  `.env`, which `docker-compose` already loads via `env_file` (§5), so the value
  reaches the container with **no compose change and no new volume**. The container
  does need outbound network to reach the server.
- **Per-host secret.** `.env` is gitignored and per-host, and the deploy is a
  `git merge --ff-only` (§8) that never touches it — so add `MONGODB_URI` to the
  **prod host's `.env`** separately; it isn't shipped by the deploy. The same URI
  works from dev and prod.
- **Optional + fail-fast.** An empty `MONGODB_URI` disables Mongo cleanly
  (`ErrMongoUnavailable`); a set-but-unreachable server fails fast at open time
  (10s server-selection timeout) rather than hanging. **No feature uses Mongo yet**,
  so this is plumbing only today.
- **Provisioning.** Mongo creates a database on first write, so `site-of-tools`
  only "exists" once something writes to it. Run `make mongo-init` once from a host
  that can reach the server to create it explicitly (it adds an empty `_meta`
  collection and is idempotent).

> **Reachability caveat.** `mongodb.corpberry.com` is a Cloudflare-proxied DNS
> record, and Cloudflare's proxy does not forward raw MongoDB TCP (port 27017) — so
> the server is reachable only from hosts on its allowed network path (e.g. the
> prod host / an internal network), **not** from an arbitrary machine. Provision
> the database and run Mongo-backed work from such a host.
