# `tz_mismatch` — Browser timezone ≠ IP timezone

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** network · **Weight:** 25 · **Reads client signal:** yes

## What it checks

The browser's timezone offset disagrees with the timezone of the egress IP — the shape of a proxy or VPN exit in another region, or a spoofed timezone. Travel and corporate VPNs can trip this honestly, which is why it is one cross-check among many.

## Origin & history

Original rule — predates the 2026-07-17 competitor-gap audit (G01+), so there's no G-item shipment story to move here; it was part of the first working scorer.

## Test status: Investigated and closed

**False-positive concern raised and closed.** A genuine, non-automated Claude-in-Chrome session scored `50/100 Suspicious` on production, entirely from this check (`-25`, browser reported `Europe/Moscow` against an IP-geolocated +02:00) plus `webrtc_ip_mismatch`. Traced to the session's own network egress path disagreeing with its browser's timezone/WebRTC address — an artifact of that sandbox's topology, architecturally the same shape as a real corporate VPN or split-tunnel user. Resolved: the repo owner independently opened the production URL from an ordinary Chrome session (no extension, no proxy) and got a clean `100/human` reading — timezone, egress IP, and WebRTC candidate all agreed, so neither check fired. No scoring change needed. (This investigation referred to this rule by the name `timezone_ip_mismatch`; the actual code/rule ID is `tz_mismatch`.)

## Go scorer coverage

`tests/botcheck_test.go`: `TestStealthSpoofScoresBot`, `TestServerOnlySkipsClientChecks`, `TestTimezoneOffsetComparedNotStringMatched`, `TestUnknownIPTimezoneDoesNotTripCrossCheck`; `tests/handler_test.go`: `TestPlaceholderTimezoneCleanedThroughHandler`, `TestCheckTimezoneMismatchFiresThroughHandler`; `tests/report_test.go`: `TestTierScore`, `TestSubgroup`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["tz_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
