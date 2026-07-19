# `webrtc_ip_mismatch` — Public WebRTC candidate IP ≠ egress IP

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** network · **Weight:** 25 · **Reads client signal:** yes

## What it checks

The address WebRTC reports disagrees with the connection's egress IP — the shape of a proxy or VPN that tunnels HTTP but leaks the real path over WebRTC. Browsers with WebRTC disabled or mDNS-masked candidates simply yield no signal.

## Origin & history

**G09**, shipped 2026-07-18: harvests ICE candidate IPs over a public STUN server (~1.5s, mDNS `.local` candidates skipped), fires only when a **public** candidate differs from the server-observed egress IP — private/loopback/link-local/ULA/CGNAT candidates are excluded as normal NAT, only the egress address's own family is compared so dual-stack connections stay silent. Later investigated for an unrelated false-positive concern (sandbox network topology, not the rule itself) and closed — see the test status above.

## Test status: Investigated and closed

**False-positive concern raised and closed**, same incident as `tz_mismatch`: a genuine, non-automated Claude-in-Chrome session scored `50/100 Suspicious` on production, `-25` from this check (WebRTC-leaked candidate IP didn't match the HTTP egress IP) plus `-25` from `tz_mismatch`. Traced to that session's own network egress path, not a real false-positive risk — the repo owner's ordinary Chrome session (no extension, no proxy) read clean, WebRTC candidate and egress IP agreeing. No scoring change needed.

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestWebRTCIPMismatch`; `tests/handler_test.go`: `TestCheckWebRTCMismatchThroughHandler`, `TestCheckStaleV2PayloadScores100ThroughHandler`; `tests/report_test.go`: `TestExplanation`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["webrtc_ip_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
