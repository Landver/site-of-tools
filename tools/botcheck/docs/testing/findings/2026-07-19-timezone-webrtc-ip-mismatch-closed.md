# 2026-07-19 — `timezone_ip_mismatch` + `webrtc_ip_mismatch`: sandbox artifact, confirmed non-issue (CLOSED)

*(part of the [findings log](../findings-log.md), see the
[botcheck docs index](../../README.md))*

The same real-Chrome-via-Claude-in-Chrome session from the
[real-Chrome baseline entry](2026-07-19-chrome-runtime-real-chrome-baseline.md)
scored **50/100, "Suspicious"** on the live production instance despite being a
genuine, non-automated visit (every automation/headless/consistency check
read clean — see that entry). The entire deduction came from two checks
firing together: `timezone_ip_mismatch` (-25: browser reported
`Europe/Moscow` (+03:00) against an IP-geolocated +02:00) and
`webrtc_ip_mismatch` (-25: the WebRTC-leaked candidate IP didn't match the
HTTP egress IP). `zero_outerHeight` also flagged but stayed a no-op soft
signal alone (below the ≥3-cluster threshold).

Both firing checks share one root cause: the session's network egress point
differs from where its browser/OS believes it is — the Claude in Chrome
tool's backing infrastructure routes traffic through a path that disagrees
with the browser's own timezone and WebRTC-visible address. That's
architecturally the same shape as a real corporate-VPN or split-tunnel user,
which is why this looked like a genuine open risk when only this one sample
existed.

**Resolved:** the repo owner independently opened the production URL from
their own ordinary Chrome session (no extension, no proxy/sandbox in the
path) and reported a clean 100/human reading — browser timezone, egress IP,
and WebRTC candidate IP all agreed, so neither check fired. Confirms the
50/100 reading above was an artifact of the Claude in Chrome sandbox's own
network topology, not evidence of a false-positive risk for real users. No
scoring change needed. next-steps.md item 7 closed accordingly.
