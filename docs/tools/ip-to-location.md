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
| IP2Proxy PX12 | `ip2proxy/…PX12.BIN` (+ CSV) | **1.7 GB** | ❌ deferred |

IP2Proxy (proxy/VPN/threat detection) is deferred — 1.7 GB is a memory/ops
decision of its own. When added, it's a separate reader and likely its own
sub-feature under this subdomain.

---

## `geoip` domain service

One Go package (`github.com/ip2location/ip2location-go/v9`) reads **both** DB11
and ASN BINs — there is no separate ASN module. Key facts (verified):

- **Open once at startup, share the handle.** A `*DB` is goroutine-safe (reads go
  through positional `ReadAt`, no shared offset, no globals). Never open per
  request; never use the deprecated package-level `Open()/Close()` — use `OpenDB()`.
- **No mmap, no full load into RAM.** `OpenDB` reads on demand via `ReadAt`; a
  200 MB+ BIN costs ~no Go heap (served from OS page cache).
- **IPv4 vs IPv6:** the v4 BIN answers v4 only; the v6 BIN answers **both**. We
  open all four handles and route by address family.

```go
// iptolocation/geoip.go — pure domain, no HTTP.
type Service struct{ db4, db6, asn4, asn6 *ip2location.DB }

func OpenService(db11v4, db11v6, asnv4, asnv6 string) (*Service, error) { /* OpenDB × 4 */ }

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

Country (code + name), region, city, ZIP, timezone, latitude, longitude, ASN,
AS name. (`Latitude`/`Longitude` are `float32`; `ASN` is a string.)

---

## UX & endpoints (v1)

**v1 scope:** a box to type **any IP** and look it up. (Auto-detecting the
visitor's *own* IP is an easy follow-up — the `CF-Connecting-IP` plumbing already
exists — but not in v1. After v1, revisit the UI for a larger set of `ip.` tools.)

Same logic serves browser, htmx, and CLI via content negotiation ([ARCHITECTURE.md §4](../ARCHITECTURE.md#4-request-layering-the-core-pattern--read-this)):

| Request | Route | Response |
|---------|-------|----------|
| Browser navigation | `GET /` | Full page: the lookup form |
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

- Visitor's own IP auto-detected on load.
- IP2Proxy PX12: proxy/VPN/threat flags (mind the 1.7 GB footprint).
- Map view of lat/lon; bulk lookup; reverse DNS; ASN → prefix listing.
- When Mongo lands: retain/replay lookups.
