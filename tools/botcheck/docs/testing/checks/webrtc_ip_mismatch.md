# `webrtc_ip_mismatch` — Public WebRTC candidate IP ≠ egress IP

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** network · **Weight:** 25 · **Reads client signal:** yes

## What it checks

Address WebRTC reports disagrees w/ connection's egress IP — shape of proxy or VPN that tunnels HTTP but leaks real path over WebRTC. Browsers w/ WebRTC disabled or mDNS-masked candidates yield no signal.

## Origin & history

**G09**, shipped 2026-07-18: harvests ICE candidate IPs over public STUN server (~1.5s, mDNS `.local` candidates skipped), fires only when a **public** candidate differs from server-observed egress IP — private/loopback/link-local/ULA/CGNAT candidates excluded as normal NAT, only egress address's own family compared so dual-stack connections stay silent. Later investigated for unrelated false-positive concern (sandbox network topology, not rule itself) & closed — see test status above.

## Test status: Investigated and closed

**False-positive concern raised & closed**, same incident as `tz_mismatch`: genuine, non-automated Claude-in-Chrome session scored `50/100 Suspicious` on production, `-25` from this check (WebRTC-leaked candidate IP didn't match HTTP egress IP) plus `-25` from `tz_mismatch`. Traced to that session's own network egress path, not real false-positive risk — repo owner's ordinary Chrome session (no extension, no proxy) read clean, WebRTC candidate & egress IP agreeing. No scoring change needed.

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestWebRTCIPMismatch`; `tests/handler_test.go`: `TestCheckWebRTCMismatchThroughHandler`, `TestCheckStaleV2PayloadScores100ThroughHandler`; `tests/report_test.go`: `TestExplanation`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["webrtc_ip_mismatch"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
