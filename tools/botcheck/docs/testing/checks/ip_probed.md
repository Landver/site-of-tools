# `ip_probed` — Egress IP probed this site for secret files

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** no (server-observed)

## What it checks

Egress IP asked this site for secret files (/.env, /.git/config, .php…) in last 30 days, which only scanners do. Address listed, never blocked: shared NAT, mobile carrier or VPN exit carries real visitors too, so stays soft & only counts as part of cluster.

## Origin

First-hand source in shared `ip_blocklist`: request log hands every probe (`platform.IsProbe`) to `iptools.BlockList.FlagProbe`, source `corpberry-honeypot`, expiring 30 days after latest probe (see [storage.md](../../storage.md)). Handler sets `Signals.IPProbed` from `BlockLookup.Probed()`. Not a "deliberate ban": weight-25 `ip_blocklisted` would drop human on shared address to 75 (`suspicious`) on one scanner's hit, so this source is excluded from `IPBlocklistDeliberate` & gets own soft rule.

## Test status: Server-side corpus rule — no browser-observable trigger

Fires from corpus lookup keyed on egress IP, not anything browser emits.

## Go scorer coverage

`tests/botcheck_test.go`: `TestIPBlocklistedRule`, `TestEveryRuleCanFire`; `tests/supplied_test.go`: `TestAddIPSignals`, `TestCoverageCounts`; `tools/iptools/tests/blocklist_test.go`: `TestFlagProbeLive`; `platform/tests/requestlog_test.go`: `TestIsProbe`, `TestRequestLogProbeHookLive`.

---

"What it checks" sourced from [`report.go`](../../../report.go) `ruleExplanations["ip_probed"]`. Update both together.
