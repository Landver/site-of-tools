# Tool: IP → Location (`ip.corpberry.com`)

The first tool. Look up geolocation + network (ASN) info for any IP address.
Lives on its own subdomain because it will grow into a small suite of IP-related
tools, not just this one lookup.

- **Code + everything:** `iptolocation/` — self-contained (`geoip.go` domain,
  `handler.go` transport, `templates/`, `tests/`, `assets/`, `download-assets.sh`).
- **Data:** `iptolocation/assets/` (the `.BIN` databases; gitignored, bind-mounted).
- **DB download:** `iptolocation/download-assets.sh` (run via `make assets`).
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
// iptolocation/geoip.go — pure domain, no HTTP.
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

## UX & endpoints (v1)

**v1 scope:** a box to type **any IP** and look it up, plus auto-detecting the
visitor's *own* IP on a bare `GET /` (via the `CF-Connecting-IP` plumbing; the
result card labels it "your address"). After v1, revisit the UI for a larger set
of `ip.` tools.

Same logic serves browser, htmx, and CLI via content negotiation ([ARCHITECTURE.md §4](../ARCHITECTURE.md#4-request-layering-the-core-pattern--read-this)):

| Request | Route | Response |
|---------|-------|----------|
| Browser navigation | `GET /` | Full page: the visitor's own IP (if routable), else the empty lookup form |
| htmx form submit (`HX-Request: true`) | `GET /?ip=…` | HTML **fragment** (result card only) |
| Browser direct hit / bookmark | `GET /{ip}` | Full page with the result |
| CLI / API | `GET /{ip}` (or `/?ip=…`), plain `curl` or `Accept: application/json` | JSON |

So this just works:
```
$ curl https://ip.corpberry.com/8.8.8.8
{"ip":"8.8.8.8","country_code":"US","country":"United States of America",
 "region":"California","city":"Mountain View","zip":"94035","timezone":"-07:00",
 "lat":37.38605,"lon":-122.08385,"asn":"15169","as_name":"Google LLC"}
```
The form does `hx-get="/"` with an `ip` field (→ `GET /?ip=…`) and
`hx-target="#result"`, swapping the result card without a full reload. Keep the
htmx-owned result region separate from any Alpine state.

---

## Abuse protection

None in v1 — deferred with the other stateful concerns until MongoDB lands (a
deliberate call; it's a public endpoint, so revisit rate limiting then). The
`IPExtractor` is already wired, so request logs show the real client IP.

---

## Attribution (required)

IP2Location LITE's license **requires a visible credit**. It's in the shared
footer (site-wide, so already covered for future tools):

> This site includes IP2Location LITE data available from
> [https://lite.ip2location.com](https://lite.ip2location.com).

---

## Later (this subdomain)

- Map proxy-type codes (VPN/TOR/DCH/PUB/WEB/SES/RES) to friendly labels.
- Map view of lat/lon; bulk lookup; reverse DNS; ASN → prefix listing.
- When Mongo lands: retain/replay lookups.
