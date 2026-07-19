# Roadmap — quick wins (highest value, lowest cost)

*(part of the [roadmap index](README.md))*

The `Not built` / `Partial` items at `trivial`/`low` effort with real value to
a self-test tool — **all ten are shipped as of 2026-07-17** (quick-win program
complete; open work starts at the medium-effort / infra / DB-backed rows in
the [category files](README.md#category-files-the-gap-audit-by-section)).
This table was the original "why it's cheap" plan; each item's actual
implementation now lives in its check file instead of being restated here
twice.

| # | Quick win | Effort | Check(s) |
|---|---|---|---|
| G01 | Expand userAgentData high-entropy hints + platformVersion coherence | trivial | [ua_chrome_version_mismatch](../testing/checks/ua_chrome_version_mismatch.md) |
| G02 | navigator.productSub / oscpu / buildID / pdfViewerEnabled | trivial | [productsub_mismatch](../testing/checks/productsub_mismatch.md) |
| G53 | Explicit on-page scope disclosure (what the verdict does/doesn't use) | trivial | Not a scoring rule — a reporting/UX feature, see [reporting-ux.md](reporting-ux.md) |
| G04 | Deep native-function tamper / lie detection | low | [tostring_proxy](../testing/checks/tostring_proxy.md), [native_descriptor_tamper](../testing/checks/native_descriptor_tamper.md), [native_callnew_tamper](../testing/checks/native_callnew_tamper.md) |
| G03 | Broaden cross-context (worker/iframe/SW) comparison beyond UA | low | [context_ua_mismatch](../testing/checks/context_ua_mismatch.md) (+ `context_language/cores/platform/webgl_mismatch`) |
| G05 | Feature-detect true engine and compare to claimed UA | low | [engine_ua_mismatch](../testing/checks/engine_ua_mismatch.md) |
| G08 | WebGL/GPU identity vs claimed OS/UA coherence | low | [gpu_os_mismatch](../testing/checks/gpu_os_mismatch.md) |
| G36 | Good-bot allowlist + AI-agent/LLM-crawler classification | low | Not a `scoring.go` rule — see [`goodbots.go`](../../goodbots.go) and [ip-reputation.md](ip-reputation.md) |
| G06 | HTTP header value/presence consistency vs claimed browser | low | [accept_encoding_missing](../testing/checks/accept_encoding_missing.md) (+ `accept_language_missing`, `accept_nav_mismatch`) |
| G07 | WebGL vendor/renderer/feature internal inconsistency | low | [webgl_vendor_mismatch](../testing/checks/webgl_vendor_mismatch.md) |
