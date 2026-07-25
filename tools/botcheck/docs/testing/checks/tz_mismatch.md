# `tz_mismatch` — Browser timezone ≠ IP timezone

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** network · **Weight:** 25 · **Reads client signal:** yes

## What it checks

Browser timezone offset disagrees w/ egress IP timezone — shape of proxy/VPN exit in another region, or spoofed timezone. Travel & corporate VPNs can trip honestly -> one cross-check among many.

## Origin & history

Original rule — predates 2026-07-17 competitor-gap audit (G01+), so no G-item shipment story to move here; part of first working scorer.

## Test status: Investigated and closed

**False-positive concern raised & closed.** Genuine non-automated Claude-in-Chrome session scored `50/100 Suspicious` on production, entirely from this check (`-25`, browser reported `Europe/Moscow` vs IP-geolocated +02:00) plus `webrtc_ip_mismatch`. Traced to session's own network egress path disagreeing w/ its browser timezone/WebRTC address — artifact of that sandbox's topology, architecturally same shape as real corporate VPN or split-tunnel user. Resolved: repo owner independently opened production URL from ordinary Chrome session (no extension, no proxy), got clean `100/human` — timezone, egress IP, WebRTC candidate all agreed, so neither check fired. No scoring change needed. (Investigation referred to this rule as `timezone_ip_mismatch`; actual code/rule ID is `tz_mismatch`.)

## Go scorer coverage

`tests/botcheck_test.go`: `TestStealthSpoofScoresBot`, `TestServerOnlySkipsClientChecks`, `TestTimezoneOffsetComparedNotStringMatched`, `TestUnknownIPTimezoneDoesNotTripCrossCheck`; `tests/handler_test.go`: `TestPlaceholderTimezoneCleanedThroughHandler`, `TestCheckTimezoneMismatchFiresThroughHandler`; `tests/report_test.go`: `TestSubgroup`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["tz_mismatch"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
