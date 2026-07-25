# `netinfo_incoherent` — navigator.connection effectiveType contradicts its own rtt/downlink

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

navigator.connection derives effectiveType from the very rtt/downlink estimates it reports -> claiming faster type than its own numbers imply means object overridden by spoof. Firefox & Safari usually lack this API entirely — normal absence, reads as no signal here; network change mid-read can briefly disagree, so counts only in a cluster.

## Origin & history

**G21**, shipped 2026-07-18 (wave-2, same v4 `env` section as `matchmedia_missing`): `navigator.connection`'s `effectiveType` derived by browser from its own `rtt`/`downlink` numbers -> claiming faster type than those numbers imply means object overridden by spoof — thresholds graced to tolerate API's own rounding. Firefox & Safari usually lack this API entirely, normal absence read as no signal. Deliberately **not** built from same G21 batch: incognito detection via storage quota (G19, separately skipped as unreliable); rtt-vs-IP-geo cross-check (client RTT measures same egress path IP geolocation already describes -> ordinary VPN user would false-fire it); full Permissions-state enumeration (two-name sample already carries entropy at no extra cost); MediaCapabilities beyond EME ClearKey.

## Test status: Verified — fires correctly

Real-browser probe (`fire-branch-probe.mjs`): `connection` claiming 4g w/ slow-2g-implying rtt/downlink → fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV4Signals`, `TestNetinfoIncoherent`; `tests/handler_test.go`: `TestCheckV4SignalsThroughHandler`, `TestCheckStaleV3PayloadSkipsV4Rules`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["netinfo_incoherent"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
