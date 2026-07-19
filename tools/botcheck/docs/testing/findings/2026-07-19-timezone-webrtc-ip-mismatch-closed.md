# 2026-07-19 — `timezone_ip_mismatch` + `webrtc_ip_mismatch`: sandbox artifact, confirmed non-issue (CLOSED)

*(part of [findings log](../findings-log.md), see
[botcheck docs index](../../README.md))*

Same real-Chrome-via-Claude-in-Chrome session from
[real-Chrome baseline entry](2026-07-19-chrome-runtime-real-chrome-baseline.md)
scored **50/100, "Suspicious"** on live production instance despite being a
genuine, non-automated visit (every automation/headless/consistency check
read clean — see that entry). Entire deduction came from two checks firing
together: `timezone_ip_mismatch` (-25: browser reported `Europe/Moscow`
(+03:00) against an IP-geolocated +02:00) and `webrtc_ip_mismatch` (-25:
WebRTC-leaked candidate IP didn't match HTTP egress IP). `zero_outerHeight`
also flagged but stayed no-op soft signal alone (below ≥3-cluster
threshold).

Both firing checks share one root cause: session's network egress point
differs from where its browser/OS believes it is — Claude in Chrome tool's
backing infrastructure routes traffic through a path that disagrees with
browser's own timezone and WebRTC-visible address. Architecturally same
shape as a real corporate-VPN or split-tunnel user, why this looked like a
genuine open risk when only this one sample existed.

**Resolved:** repo owner independently opened production URL from own
ordinary Chrome session (no extension, no proxy/sandbox in path) and
reported clean 100/human reading — browser timezone, egress IP, and WebRTC
candidate IP all agreed, so neither check fired. Confirms 50/100 reading
above was an artifact of Claude in Chrome sandbox's own network topology,
not evidence of false-positive risk for real users. No scoring change
needed. next-steps.md item 7 closed accordingly.
