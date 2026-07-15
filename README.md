# corpberry.com — site-of-tools

My personal playground: a portfolio landing page plus a growing collection of
small tools and experiments. One Go server powers the apex site and every simple
tool; each tool that grows big enough gets its own subdomain.

- **corpberry.com** — portfolio + index of tools
- **ip.corpberry.com** — IP tools: geolocation, network (ASN), and proxy/VPN lookups (first tool)

## Stack

Go 1.26 · Echo v5 · `html/template` · htmx · Alpine.js · Tailwind (standalone
CLI, no npm) · Docker (distroless). Server-rendered HTML with htmx for the
interactive bits; every endpoint also returns JSON for CLI/API callers.

## Quick start (dev)

Install **Go 1.26+** first (system-level, one time):
```bash
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.26.5.linux-arm64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc
```
Then:
```bash
git clone git@github.com:Landver/site-of-tools.git
cd site-of-tools

cp .env.example .env      # fill in IP2LOCATION_DOWNLOAD_TOKEN if you'll run `make assets`
make deps                 # go mod tidy (writes go.sum)
make tools                # Tailwind binary + air + enable git hooks
make assets               # download the IP2Location LITE .BIN databases
make css                  # build shared/static/css/styles.css

make css-watch &          # rebuild CSS on edits
make dev                  # air: live-reload the server (APP_ENV=dev)
```

Open **http://ip.localhost:8080** and **http://localhost:8080** (`*.localhost`
routes to 127.0.0.1 automatically, so subdomain routing works locally).

CLI/JSON side:
```bash
curl http://ip.localhost:8080/8.8.8.8
```

## Tests

```bash
make test          # go test ./... -race
```
A pre-push git hook (`make hooks`, also run by `make tools`) runs `go vet` +
`go test` and blocks the push if anything fails.

## Production

Runs in Docker behind nginx behind Cloudflare, on the same host.
```bash
git pull
docker compose up -d --build
```
nginx blocks live in [deploy/nginx/](deploy/nginx/); full steps in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Docs

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — design: host routing, request
  layering, content negotiation, embedding, config, testing, how to add a tool
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) — Cloudflare → nginx → Docker, ports, IP trust
- [docs/tools/iptools.md](docs/tools/iptools.md) — the first tool
- [CLAUDE.md](CLAUDE.md) — conventions for anyone (incl. AI) developing here

## Layout

```
main.go            entrypoint (single binary)
platform/          shared engine: config · app factory · renderer + negotiation
shared/            shared front-end: base partials + htmx/alpine/tailwind css
site/              apex project (corpberry.com)
iptools/           the IP tools: code · templates · assets (.BIN) · download script
deploy/nginx/      reverse-proxy server blocks
docs/              architecture & deployment
```

## Attribution

The IP tools (`ip.corpberry.com`) use the IP2Location LITE database for
[IP geolocation](https://lite.ip2location.com). This is the exact acknowledgment
IP2Location's LITE license requires, shown on the tool's own pages — the only
ones that use the data (the apex does not, so it omits the credit).
