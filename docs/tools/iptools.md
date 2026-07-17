# Tool: IP Tools (`ip.corpberry.com`)

A small suite of IP-related tools on one subdomain, `ip.corpberry.com`. Two pages
today (a sub-nav switches between them):

- **IP lookup** (`/`) — geolocation + ASN + proxy/VPN for any IP; on a bare visit it
  also inspects *your* connection (see [Endpoints](#endpoints)).
- **Subnet calculator** (`/cidr`) — pure CIDR math, no databases.

Layout:

- **Code + everything:** `iptools/` — self-contained: `geoip.go` (geo/proxy domain),
  `cidr.go` (subnet domain), `handler.go` (transport), `templates/`, `tests/`,
  `assets/`, `download-assets.sh`.
- **Data:** `iptools/assets/` (the `.BIN` databases; gitignored, bind-mounted).
- **DB download:** `iptools/download-assets.sh` (run via `make assets`).
- **Subdomain:** `ip.corpberry.com` (dev: `ip.localhost:8080`).

---

## Datasets

IP2Location **LITE** (free tier). Present on disk today:

| Dataset | Files | Size | In v1? |
|---------|-------|------|--------|
| DB11 geolocation | `ipv4/…DB11.BIN`, `ipv6/…DB11.IPV6.BIN` | 92M / 216M | ✅ |
| ASN | `asn/…LITE-ASN.BIN`, `…LITE-ASN.IPV6.BIN` | 156M / 262M | ✅ |
| IP2Proxy PX12 | `ip2proxy/…PX12.BIN` (+ CSV) | **1.7 GB** | ✅ |

IP2Proxy (proxy/VPN/threat detection) is read by a **separate** module,
`github.com/ip2location/ip2proxy-go/v4` (v3 panics on a PX12 database — needs
≥v4). It's **optional**: set `IP2PROXY_PX12` to enable the proxy section, leave
it empty to disable. Like the geo BINs it reads via `ReadAt`, so the 1.7 GB file
costs ~no RAM (~9 MB RSS observed), not a full in-memory load.

---

## `geoip` domain service

`ip2location-go/v9` reads **both** DB11 and ASN BINs (no separate ASN module);
IP2Proxy is a **separate** package, `ip2proxy-go/v4`. Key facts (verified):

- **Open once at startup, share the handle.** A `*DB` is goroutine-safe (reads go
  through positional `ReadAt`, no shared offset, no globals). Never open per
  request; never use the deprecated package-level `Open()/Close()` — use `OpenDB()`.
- **No mmap, no full load into RAM.** `OpenDB` reads on demand via `ReadAt`; a
  200 MB+ BIN costs ~no Go heap (served from OS page cache).
- **IPv4 vs IPv6:** the v4 BIN answers v4 only; the v6 BIN answers **both**. We
  open all four geo handles and route by address family.
- **Proxy is optional + best-effort.** When `IP2PROXY_PX12` is set, `OpenService`
  also opens the single PX12 BIN (answers v4 + v6, same `ReadAt`, ~9 MB RSS); a
  failed proxy lookup returns `nil` and simply omits the section.

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

`Result` is the plain struct the transport layer renders as HTML or JSON. Missing
DBs are non-fatal: `OpenService` returns `ErrUnavailable`, the server still boots,
and the tool shows a friendly message. The handler depends on a small `Looker`
interface (`Lookup(string) (*Result, error)`) so tests inject a fake — no BINs
needed. LITE data can return placeholder `"-"` for some fields; guard on display.

---

## Fields exposed

**Geolocation:** country (code + name), region, city, ZIP, timezone, latitude,
longitude, ASN, AS name. **Proxy (when PX12 loaded):** is-proxy, proxy type,
usage type, threat, provider, fraud score, ISP, domain, last-seen — nested under
`proxy` in JSON, shown as a separate "proxy / network" card in HTML.

---

## Endpoints

Every view is content-negotiated ([ARCHITECTURE.md §4](../ARCHITECTURE.md#4-request-layering-the-core-pattern--read-this)):
browsers and htmx get HTML, everyone else gets JSON.

Lookups are **query-param only** (`?ip=…`), consistent with `/cidr?cidr=…` — there
is no `/:ip` pretty route.

| Request | Response |
|---------|----------|
| `GET /` (browser) | Full page: your own IP looked up (if routable), the **connection inspector**, and a client-side IPv6 check — else the empty form |
| `GET /?ip=…` (browser) | Full page with the looked-up result |
| `GET /?ip=…` (htmx) | HTML **fragment**, the result card only (`hx-target="#result"`) |
| `GET /` or `GET /?ip=…` (JSON) | Geolocation + ASN + proxy for that IP |
| `GET /cidr?cidr=…` | Subnet calculation (HTML or JSON) |

So this just works:
```
$ curl 'https://ip.corpberry.com/?ip=8.8.8.8'
{"ip":"8.8.8.8","country":"United States of America","city":"Mountain View",
 "asn":"15169","as_name":"Google LLC", ...}

$ curl 'https://ip.corpberry.com/cidr?cidr=192.168.1.0/24'
{"cidr":"192.168.1.0/24","family":"IPv4","network":"192.168.1.0",
 "broadcast":"192.168.1.255","netmask":"255.255.255.0","usable_hosts":"254", ...}
```

The IP-lookup form uses `hx-get="/"` (→ `GET /?ip=…`, `hx-target="#result"`) for a
partial swap; the subnet calculator is a plain GET form — a calculator is stateless
input → output, so a full render is enough (no htmx, per CLAUDE.md rule 4).

**Connection inspector** (the "your request" card): server-computed request facts —
the resolved IP and how it was derived (Cloudflare / X-Forwarded-For / direct),
scheme, host, User-Agent, and language. TLS and HTTP version are omitted (they
terminate upstream); `Cookie`/`Authorization` are never read. `ip.corpberry.com` is
DNS-only in Cloudflare today, so requests arrive via nginx's `X-Forwarded-For`.

**IPv6 check** is the one genuinely client-side piece: only the browser can prove a
working IPv6 path (by fetching an IPv6-only host), so it isn't in the JSON — by
nature, not omission.

---

## Abuse protection

None in v1. Rate limiting is deferred with the other stateful concerns: **MongoDB
is now available** (a shared client in `platform/`, unused by this tool so far), so
it's a build-it call rather than a blocked one — it's a public endpoint, so
revisit rate limiting when we wire storage below the domain service. The
`IPExtractor` is already wired, so request logs show the real client IP.

---

## Attribution (required)

IP2Location LITE's license **requires a specific, visible credit** on *"all
sites, advertising materials, and documentation mentioning features or the use
of this database"*. The exact acknowledgment it mandates is:

> [site or product name] uses the IP2Location LITE database for
> [IP geolocation](https://lite.ip2location.com).

We render that verbatim in the shared footer, but **gated on a `.Attribution`
view-model flag** set only by this tool's handler — so it shows on the IP tool
pages (which use the databases) and is omitted on the apex, which does not use
or mention the data and therefore falls outside the clause. IP2Proxy LITE
carries the same acknowledgment wording, so one credit covers both.

---

## Later (this subdomain)

- Map proxy-type codes (VPN/TOR/DCH/PUB/WEB/SES/RES) to friendly labels.
- Map view of lat/lon; bulk lookup; ASN → prefix listing; range → minimal CIDRs.
- With Mongo (now available, not yet used here): retain/replay lookups.

*(Done since v1: proxy/VPN detection, IPv6 check, connection inspector, and the
subnet/CIDR calculator.)*
