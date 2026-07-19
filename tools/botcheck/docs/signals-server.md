# Bot check — server-observed signals

*(part of the [botcheck docs index](README.md))* — see
[signals-client.md](signals-client.md) for the client-collected half.

Split by *where the signal physically comes from* — the whole game is that server
signals can't be forged by the client and client signals can, so the scorer's job
is to make the two disagree and weight the disagreement.

Go computes these off `*echo.Context` — unforgeable by the client:

| Signal | Source in Go | What it tells us |
|---|---|---|
| **IP reputation** — datacenter / hosting / VPN / proxy / Tor | `iptools.Service.Lookup(ip).Proxy` (IP2Proxy **PX12**) | Hosting/proxy IPs are the strongest cheap bot tell (`IsProxy`, `ProxyType` VPN/TOR/DCH/…). iptools' own `Proxy` result also carries `UsageType`/`Threat`, but botcheck's handler doesn't currently read either into `Signals` |
| **IP timezone** | `iptools.Service.Lookup(ip)` → `.Timezone` (IP2Location DB11) | Anchor for the `tz_mismatch` cross-check (browser TZ vs IP TZ). `.Country` is returned by the lookup too but isn't copied into `Signals` — there's no IP-country cross-check today |
| **Raw HTTP `User-Agent`** | `c.Request().UserAgent()` | Cross-checked vs the JS `navigator.userAgent`; parsed for `HeadlessChrome`, `python-requests`, `Go-http-client`, `curl`, empty UA |
| **`Sec-CH-UA` / `Sec-CH-UA-Platform` client-hint headers** | `c.Request().Header.Get("Sec-CH-UA")` / `Get("Sec-CH-UA-Platform")` | Cross-checked vs the JS `navigator.userAgentData` — spoofers routinely forget to keep header + JS hints in sync. (`Sec-CH-UA-Mobile` isn't read.) |
| **`Accept-Language`** | `c.Request().Header.Get("Accept-Language")` | vs `navigator.languages` (JS) only (`lang_mismatch`). An empty header is a separate weak tell (`accept_language_missing`, soft) — there's no IP-country cross-check |
| **Header presence / plausibility** | `c.Request().Header` | Missing `Accept-Encoding` (`accept_encoding_missing`) or `Accept-Language` (`accept_language_missing`); a present-but-wrong `Accept` value (`accept_nav_mismatch`). A genuinely absent `Accept` header, or a Chrome UA missing `Sec-CH-UA` entirely, isn't scored by any rule today |
| **Fingerprint corpus** — distinct IPs presenting this exact fingerprint in 30 days | `Corpus.DistinctIPs` (Mongo `botcheck_fingerprints`, 30-day TTL) | The scraping-farm catch (`fingerprint_reuse`): a farm locks one fingerprint and rotates its proxy pool; one person roaming never reaches five IPs. Details in [storage.md](storage.md). |
| **Connection metadata** | shared `platform.Conn(c)` — resolved IP, how derived (Cloudflare/XFF/direct), scheme, host | Shown in the "your request" card; also feeds the IP lookup |

We deliberately **cannot** read HTTP header order/casing, TLS JA3/JA4, HTTP/2
frame fingerprints, or the TCP/IP SYN fingerprint — nginx terminates TLS,
normalizes headers, and downgrades to HTTP/1.1 before Go sees the request, and
`crypto/tls` never hands the raw ClientHello to a handler. This is a documented
gap (see [roadmap/network-layer.md](roadmap/network-layer.md)), not a bug.
