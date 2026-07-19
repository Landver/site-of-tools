# `missing_proprietary_codecs` — Browser lacks H.264 and AAC (stripped/headless build)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

Stock desktop browsers ship H.264 and AAC support; stripped or headless Chromium builds often have neither. Linux installs with open codec packs can look similar, which is why this only counts in a cluster.

## Origin & history

Internal-backlog Layer 2 item, shipped: a browser UA reporting neither H.264 nor AAC support via `canPlayType` — stock desktop browsers ship both; stripped or headless Chromium builds often have neither. Linux installs with open codec packs can look similar, kept soft for that reason.

## Test status: Verified — fires correctly

Real-browser probe (`fire-branch-probe.mjs`): overrode `canPlayType` to reject H.264/AAC → fired. (Real Chrome-for-Testing ships both unmodified.) See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestLayer2Signals`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["missing_proprietary_codecs"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
