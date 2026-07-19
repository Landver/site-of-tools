# `netinfo_incoherent` — navigator.connection effectiveType contradicts its own rtt/downlink

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

navigator.connection derives its effectiveType from the very rtt/downlink estimates it reports, so claiming a faster type than its own numbers imply means the object was overridden by a spoof. Firefox and Safari usually lack this API entirely — a normal absence that reads as no signal here, and a network change mid-read can briefly disagree, so it only counts in a cluster.

## Origin & history

**G21**, shipped 2026-07-18 (wave-2, same v4 `env` section as `matchmedia_missing`): `navigator.connection`'s `effectiveType` is derived by the browser from its own `rtt`/`downlink` numbers, so claiming a faster type than those numbers imply means the object was overridden by a spoof — thresholds are graced to tolerate the API's own rounding. Firefox and Safari usually lack this API entirely, a normal absence read as no signal. Deliberately **not** built from the same G21 batch: incognito detection via storage quota (that's G19, separately skipped as unreliable), an rtt-vs-IP-geo cross-check (client RTT measures the same egress path the IP geolocation already describes, so an ordinary VPN user would false-fire it), full Permissions-state enumeration (a two-name sample already carries the entropy at no extra cost), and MediaCapabilities beyond EME ClearKey.

## Test status: Verified — fires correctly

Real-browser probe (`fire-branch-probe.mjs`): `connection` claiming 4g w/ slow-2g-implying rtt/downlink → fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV4Signals`, `TestNetinfoIncoherent`; `tests/handler_test.go`: `TestCheckV4SignalsThroughHandler`, `TestCheckStaleV3PayloadSkipsV4Rules`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["netinfo_incoherent"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
