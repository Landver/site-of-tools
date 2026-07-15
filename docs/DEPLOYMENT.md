# Deployment — corpberry.com

Dev and prod run on the **same host**. Prod is Docker; dev is a local Go
toolchain with live reload. No CI yet — deploy is `git pull` + `docker compose`.

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
- Docker publishes it to the **host loopback**: `127.0.0.1:8080:8080`. Off the
  public internet, still reachable from nginx.
- nginx (its own container) reaches the host via the docker bridge gateway
  `172.17.0.1`, so `proxy_pass http://172.17.0.1:8080;`.

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
  things prevent that: (1) the app is published only to host loopback (§2), so
  nginx is the sole front door; (2) Cloudflare is the only thing upstream, so
  nginx sets `CF-Connecting-IP` from Cloudflare and a client can't inject it.

---

## 5. Docker

**Dockerfile** — three stages: build CSS (Tailwind standalone, arch-aware),
build the Go binary (embeds templates + built CSS + vendored JS), ship on
distroless-static. Full file at [`../Dockerfile`](../Dockerfile); shape:

```dockerfile
# 1) CSS: Tailwind standalone binary, no Node/npm. TARGETARCH → x64/arm64.
FROM debian:12-slim AS css
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates
RUN case "$TARGETARCH" in amd64) TW=x64;; arm64) TW=arm64;; esac; \
    curl -fsSL -o /usr/local/bin/tailwindcss \
      "https://github.com/tailwindlabs/tailwindcss/releases/download/v4.3.2/tailwindcss-linux-$TW" \
    && chmod +x /usr/local/bin/tailwindcss
COPY shared ./shared && COPY site ./site && COPY iptolocation ./iptolocation
RUN tailwindcss -i shared/static/css/input.css -o shared/static/css/styles.css --minify

# 2) Go: fully static build; embeds the project incl. the built styles.css
FROM golang:1.26 AS build
COPY go.mod go.sum ./ && RUN go mod download
COPY . .
COPY --from=css /src/shared/static/css/styles.css shared/static/css/styles.css
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app .

# 3) Runtime: distroless-static (CA certs + tzdata + nonroot, ~2 MB)
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /app /app
```
`CGO_ENABLED=0` is mandatory for distroless-static; `ip2location-go/v9` is pure
Go, so it's fine. Run `make deps` (writes `go.sum`) before building.

**docker-compose.yml** — publish to loopback, env from `.env`, bind-mount the DB
assets **read-only** (they're too large to bake into the image):
```yaml
ports:    ["127.0.0.1:8080:8080"]
env_file: .env
volumes:  ["./iptolocation/assets:/assets:ro"]   # IP2LOCATION_* env → /assets/...
```

---

## 6. The DB assets

The IP2Location LITE BINs are large (DB11 92M+216M, ASN 156M+262M, plus the
1.7 GB IP2Proxy PX12 — all read via `ReadAt`, so they cost ~no RAM). Gitignored;
never in git or the image.

- On the host they live in `iptolocation/assets/` and are bind-mounted read-only.
- `make assets` (→ `iptolocation/download-assets.sh`) (re)downloads them using
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

```bash
git pull
docker compose up -d --build
docker compose logs -f site-of-tools
```
Repo note: the default branch should be **`main`** (the working copy is on
`master`). Push the initial code to `main` so the branch and PR target line up.
