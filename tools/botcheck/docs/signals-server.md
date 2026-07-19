# Bot check — server-observed signals

*(part of the [botcheck docs index](README.md))* — see
[signals-client.md](signals-client.md) for client-collected half.

Split by *where signal physically comes from* — whole game is server signals
can't be forged by client, client signals can, so scorer's job is to make the
two disagree and weight the disagreement.

Go computes these off `*echo.Context` — unforgeable by client:

| Signal | Source in Go | What it tells us |
|---|---|---|
| **IP reputation** — datacenter / hosting / VPN / proxy / Tor | `iptools.Service.Lookup(ip).Proxy` (IP2Proxy **PX12**) | Hosting/proxy IPs strongest cheap bot tell (`IsProxy`, `ProxyType` VPN/TOR/DCH/…). iptools' own `Proxy` result also carries `UsageType`/`Threat`, but botcheck's handler doesn't currently read either into `Signals` |
| **IP timezone** | `iptools.Service.Lookup(ip)` → `.Timezone` (IP2Location DB11) | Anchor for `tz_mismatch` cross-check (browser TZ vs IP TZ). `.Country` also returned by lookup but not copied into `Signals` — no IP-country cross-check today |
| **Raw HTTP `User-Agent`** | `c.Request().UserAgent()` | Cross-checked vs JS `navigator.userAgent`; parsed for `HeadlessChrome`, `python-requests`, `Go-http-client`, `curl`, empty UA |
| **`Sec-CH-UA` / `Sec-CH-UA-Platform` client-hint headers** | `c.Request().Header.Get("Sec-CH-UA")` / `Get("Sec-CH-UA-Platform")` | Cross-checked vs JS `navigator.userAgentData` — spoofers routinely forget to keep header + JS hints in sync. (`Sec-CH-UA-Mobile` not read.) |
| **`Accept-Language`** | `c.Request().Header.Get("Accept-Language")` | vs `navigator.languages` (JS) only (`lang_mismatch`). Empty header separate weak tell (`accept_language_missing`, soft) — no IP-country cross-check |
| **Header presence / plausibility** | `c.Request().Header` | Missing `Accept-Encoding` (`accept_encoding_missing`) or `Accept-Language` (`accept_language_missing`); present-but-wrong `Accept` value (`accept_nav_mismatch`). Genuinely absent `Accept` header, or Chrome UA missing `Sec-CH-UA` entirely, not scored by any rule today |
| **Fingerprint corpus** — distinct IPs presenting this exact fingerprint in 30 days | `Corpus.DistinctIPs` (Mongo `botcheck_fingerprints`, 30-day TTL) | Scraping-farm catch (`fingerprint_reuse`): farm locks one fingerprint, rotates its proxy pool; one person roaming never reaches five IPs. Details in [storage.md](storage.md). |
| **Connection metadata** | shared `platform.Conn(c)` — resolved IP, how derived (Cloudflare/XFF/direct), scheme, host | Shown in "your request" card; also feeds IP lookup |

We deliberately **cannot** read HTTP header order/casing, TLS JA3/JA4, HTTP/2
frame fingerprints, or TCP/IP SYN fingerprint — nginx terminates TLS,
normalizes headers, downgrades to HTTP/1.1 before Go sees request, and
`crypto/tls` never hands raw ClientHello to handler. Documented gap (see
[roadmap/network-layer.md](roadmap/network-layer.md)), not a bug.
