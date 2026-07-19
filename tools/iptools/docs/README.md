# IP tools (`ip.corpberry.com`)

Small suite of IP-related tools on one subdomain, `ip.corpberry.com`. Three
pages today, switched by sub-nav:

- **IP lookup** (`/`) — geolocation + ASN + proxy/VPN for any IP; bare visit
  also inspects *your own* connection (see [Endpoints](#endpoints)).
- **Subnet calculator** (`/cidr`) — pure CIDR math, no databases.
- **Lookup history** (`/history`) — most recent user-run lookups, backed by
  MongoDB (see [Lookup history](#lookup-history)); degrades to empty page when
  Mongo off.

This is tool's design + reference doc. Straight application of layered request
pattern in
[ARCHITECTURE.md §4](../../../docs/ARCHITECTURE.md#4-request-layering-the-core-pattern--read-this),
sibling that [`botcheck`](../../botcheck/docs/README.md) borrows its
server-side IP layer from.

## Package layout (`iptools/`, self-contained)

- `geoip.go` — geo/proxy **domain** (pure Go, no HTTP): `Service`, `Result`,
  `OpenService`, `Lookup`, the `Looker` interface.
- `cidr.go` — subnet-calculator **domain** (pure CIDR math, no databases).
- `handler.go` — **transport**: `Register` + query-param parsing, then
  `platform.Respond`.
- `templates/` — `index.html`, `result.html`, `cidr.html`, `nav.html`.
- `assets/` — `.BIN` databases (gitignored, bind-mounted read-only in prod).
- `download-assets.sh` — fetches databases (run via `make assets`).

**Subdomain:** `ip.corpberry.com` (dev: `ip.localhost:8080`).

## Datasets

IP2Location **LITE** (free tier). Present on disk today:

| Dataset | Files | Size | In v1? |
|---------|-------|------|--------|
| DB11 geolocation | `ipv4/…DB11.BIN`, `ipv6/…DB11.IPV6.BIN` | 92M / 216M | ✅ |
| ASN | `asn/…LITE-ASN.BIN`, `…LITE-ASN.IPV6.BIN` | 156M / 262M | ✅ |
| IP2Proxy PX12 | `ip2proxy/…PX12.BIN` (+ CSV) | **1.7 GB** | ✅ |

IP2Proxy (proxy/VPN/threat detection) read by **separate** module,
`github.com/ip2location/ip2proxy-go/v4` (v3 panics on PX12 database — needs
≥v4). **Optional**: set `IP2PROXY_PX12` to enable proxy section, leave empty to
disable. Like geo BINs, reads via `ReadAt`, so 1.7 GB file costs ~no RAM (~9 MB
RSS observed), not full in-memory load.

## `geoip` domain service

`ip2location-go/v9` reads **both** DB11 and ASN BINs (no separate ASN module);
IP2Proxy is **separate** package, `ip2proxy-go/v4`. Key facts (verified):

- **Open once at startup, share the handle.** `*DB` is goroutine-safe (reads go
  through positional `ReadAt`, no shared offset, no globals). Never open per
  request; never use deprecated package-level `Open()/Close()` — use `OpenDB()`.
- **No mmap, no full load into RAM.** `OpenDB` reads on demand via `ReadAt`;
  200 MB+ BIN costs ~no Go heap (served from OS page cache).
- **IPv4 vs IPv6:** v4 BIN answers v4 only; v6 BIN answers **both**. We open all
  four geo handles and route by address family.
- **Proxy is optional + best-effort.** When `IP2PROXY_PX12` set, `OpenService`
  also opens single PX12 BIN (answers v4 + v6, same `ReadAt`, ~9 MB RSS); failed
  proxy lookup returns `nil`, simply omits section.

```go
// iptools/geoip.go — pure domain, no HTTP.
type Service struct{ db4, db6, asn4, asn6 *ip2location.DB; proxy *ip2proxy.DB }

func OpenService(db11v4, db11v6, asnv4, asnv6, px12 string) (*Service, error) { /* px12 optional */ }

func (s *Service) Lookup(ipStr string) (*Result, error) {
    if s == nil { return nil, ErrUnavailable }          // DBs never loaded
    p := net.ParseIP(ipStr)
    if p == nil { return nil, fmt.Errorf("%q is not a valid IP address", ipStr) }
    geoDB, asnDB := s.db6, s.asn6                        // v6 BINs answer v4 too...
    if p.To4() != nil { geoDB, asnDB = s.db4, s.asn4 }  // ...route native v4 to v4 BINs
    geo, err := geoDB.Get_all(ipStr); /* ... */
    as,  err := asnDB.Get_all(ipStr); /* ... */
    return &Result{ IP: ipStr, CountryCode: geo.Country_short, Country: geo.Country_long,
        Region: geo.Region, City: geo.City, Zip: geo.Zipcode, Timezone: geo.Timezone,
        Latitude: geo.Latitude, Longitude: geo.Longitude, ASN: as.Asn, ASName: as.As }, nil
}
```

`Result` is plain struct transport layer renders as HTML or JSON. Missing DBs
non-fatal: `OpenService` returns `ErrUnavailable`, server still boots, tool
shows friendly message. Handler depends on small `Looker` interface
(`Lookup(string) (*Result, error)`) so tests inject a fake — no BINs needed.
LITE data can return placeholder `"-"` for some fields; guard on display.

## Fields exposed

**Geolocation:** country (code + name), region, city, ZIP, timezone, latitude,
longitude, ASN, AS name. **Proxy (when PX12 loaded):** is-proxy, proxy type,
usage type, threat, provider, fraud score, ISP, domain, last-seen — nested
under `proxy` in JSON, shown as separate "proxy / network" card in HTML.

## Endpoints

Every view content-negotiated
([ARCHITECTURE.md §4](../../../docs/ARCHITECTURE.md#4-request-layering-the-core-pattern--read-this)):
browsers and htmx get HTML, everyone else gets JSON. Lookups are **query-param
only** (`?ip=…`), consistent with `/cidr?cidr=…` — no `/:ip` pretty route.

| Request | Response |
|---------|----------|
| `GET /` (browser) | Full page: own IP looked up (if routable), **connection inspector**, client-side IPv6 check — else empty form |
| `GET /?ip=…` (browser) | Full page with looked-up result |
| `GET /?ip=…` (htmx) | HTML **fragment**, result card only (`hx-target="#result"`) |
| `GET /` or `GET /?ip=…` (JSON) | Geolocation + ASN + proxy for that IP |
| `GET /cidr?cidr=…` | Subnet calculation (HTML or JSON) |
| `GET /history` | Most recent user-run lookups (HTML page, or `{"lookups":[…]}` JSON) |

So this just works:
```
$ curl 'https://ip.corpberry.com/?ip=8.8.8.8'
{"ip":"8.8.8.8","country":"United States of America","city":"Mountain View",
 "asn":"15169","as_name":"Google LLC", ...}

$ curl 'https://ip.corpberry.com/cidr?cidr=192.168.1.0/24'
{"cidr":"192.168.1.0/24","family":"IPv4","network":"192.168.1.0",
 "broadcast":"192.168.1.255","netmask":"255.255.255.0","usable_hosts":"254", ...}
```

IP-lookup form uses `hx-get="/"` (→ `GET /?ip=…`, `hx-target="#result"`) for
partial swap; subnet calculator is plain GET form — calculator is stateless
input → output, full render enough (no htmx, per CLAUDE.md rule 4).

**Connection inspector** (the "your request" card): server-computed request
facts — resolved IP and how derived (Cloudflare / X-Forwarded-For / direct),
scheme, host, User-Agent, language. TLS and HTTP version omitted (terminate
upstream); `Cookie`/`Authorization` never read. When visitor looks at own IP
(bare visit), same lookup also enriches card with ASN and proxy/VPN
attribution (`Result.ConnNetwork()` → `platform.ConnInfo.WithNetwork` —
mapping botcheck's card shares). `ip.corpberry.com` is DNS-only in Cloudflare
today, so requests arrive via nginx's `X-Forwarded-For`.

**IPv6 check** is the one genuinely client-side piece: only browser can prove
working IPv6 path (by fetching IPv6-only host), so it isn't in JSON — by
nature, not omission.

## Lookup history

`GET /history` lists most recent lookups run from tool. First MongoDB-backed
feature here, straight application of rule #5: persistence lives *below*
domain in a repository (`history.go`, `History` type), not in handler.

- **Storage.** One document per lookup in `ip_lookups` collection: queried IP,
  its country/city/ASN, `created_at`. TTL index (via
  `platform.EnsureTTLIndex`, 90 days) self-prunes, so never grows unbounded,
  same index serves newest-first sort — no second index.
- **What gets recorded.** Only *user-initiated web* lookups: successful,
  explicit `?ip=` query from browser UI. Deliberately excludes visitor's own
  auto-lookup (bare `/` visit and IPv6 self-probe, which requests JSON) and
  CLI/JSON callers — so `/history` shows what people chose to look up, not
  everyone's own address.
- **Off the request path.** `Record` writes in background goroutine, so
  recording never adds latency to (or can fail) lookup visitor is waiting on.
- **Degrades to nothing.** With Mongo disabled repository is `nil`;
  `/history` renders empty "history is off" state, JSON returns
  `{"lookups":[]}` — same nil-safe contract as absent geo database.
- **Replay.** Each row's IP links back to `/?ip=…`, past lookup re-runs in one
  click.

Engine-level **request log** (`platform.RequestLog`, `platform/requestlog.go`)
is separate, cross-cutting corpus of *every* request (all subdomains); not
part of this tool. See [ARCHITECTURE §10](../../../docs/ARCHITECTURE.md#10-out-of-scope-now-deliberately-deferred).

## Abuse protection

None in v1. Rate limiting deferred with other stateful concerns: **MongoDB now
wired** (shared client in `platform/`, now used by this tool for lookup
history), so build-it call rather than blocked one — public endpoint, revisit
rate limiting when worth it. `IPExtractor` already wired, so both request logs
and request-log corpus show real client IP.

## Attribution (required)

IP2Location LITE's license **requires specific, visible credit** on *"all
sites, advertising materials, and documentation mentioning features or the use
of this database"*. Exact acknowledgment it mandates:

> [site or product name] uses the IP2Location LITE database for
> [IP geolocation](https://lite.ip2location.com).

We render that verbatim in shared footer, but **gated on `.Attribution`
view-model flag** set only by this tool's handler — shows on IP tool pages
(which use databases), omitted on apex, which doesn't use or mention data,
falls outside clause. IP2Proxy LITE carries same acknowledgment wording, one
credit covers both.

## Later (this subdomain)

- Map proxy-type codes (VPN/TOR/DCH/PUB/WEB/SES/RES) to friendly labels.
- Map view of lat/lon; bulk lookup; ASN → prefix listing; range → minimal CIDRs.
- Rate limiting on public endpoint, now that storage wired.

*(Done since v1: proxy/VPN detection, IPv6 check, connection inspector,
subnet/CIDR calculator, Mongo-backed lookup history.)*
