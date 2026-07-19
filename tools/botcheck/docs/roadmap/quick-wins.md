# Roadmap — quick wins (highest value, lowest cost)

*(part of the [roadmap index](README.md))*

The `Not built` / `Partial` items at `trivial`/`low` effort with real value to a
self-test tool — **all ten are shipped as of 2026-07-17** (the quick-win program
is complete; open work starts at the medium-effort / infra / DB-backed rows in
the [category files](README.md#category-files-the-gap-audit-by-section)). IDs
link into the full category tables.

| # | Quick win | Effort | Why it's cheap here |
|---|---|---|---|
| G01 | Expand userAgentData high-entropy hints + platformVersion coherence | trivial | We request platform ONLY. Request platformVersion + uaFullVersion + fullVersionList too and add a rule comparing UA-embedded OS version vs userAgentData.platformVersion. This is the exact Electron/spoof catch we cite in our design, made stronger for near-zero cost. |
| G02 | navigator.productSub / oscpu / buildID / pdfViewerEnabled | trivial | Drop-in client fields + consistency rules; productSub and pdfViewerEnabled are already flagged as candidates in the internal backlog (Layer 1). |
| G53 | Explicit on-page scope disclosure (what the verdict does/doesn't use) | trivial | One-paragraph trust win: say plainly we use client fingerprint + headers + IP reputation, no behavior/ML, and that VPN/privacy users may score suspicious by design. |
| G04 | Deep native-function tamper / lie detection _(shipped)_ | low | We only run the '[native code]' toString check on 4 methods. Extend it: (1) descriptor/own-property sanity on the same natives, (2) verify call/new throw correct TypeErrors, (3) add the Proxy-via-error-stack probe to catch stealth-plugin Function.toString proxies. Pure client JS, deterministic, fits our scorer — this is the single highest-leverage cheap upgrade. |
| G03 | Broaden cross-context (worker/iframe/SW) comparison beyond UA _(shipped)_ | low | We already spawn worker + iframe and compare UA. Cheaply extend the same collectors to also diff languages, hardwareConcurrency, platform, and (if collected) GPU renderer across those contexts, and add a Service Worker context. Each mismatch is a strong consistency tell we're currently leaving on the table. |
| G05 | Feature-detect true engine and compare to claimed UA | low | We compare UA vs userAgentData.platform but never feature-detect the real engine. Add a small engine-probe module and one rule (feature-detected engine family vs UA-claimed browser). Cheap, deterministic, and robust against UA spoofing. |
| G08 | WebGL/GPU identity vs claimed OS/UA coherence _(shipped)_ | low | We read UNMASKED_RENDERER only to flag software renderers (swiftshader/llvmpipe). Add a coherence rule: GPU vendor family (Apple/Intel/NVIDIA/AMD/Adreno) vs UA-claimed OS. Cheap, catches spoofed-OS anti-detect browsers our software-renderer check ignores. |
| G36 | Good-bot allowlist + AI-agent/LLM-crawler classification _(shipped)_ | low | **Shipped** in [`goodbots.go`](../../goodbots.go): an allowlist of good crawlers + AI agents, ASN-**number** corroboration for single-tenant operators, and a `good-bot` verdict for verified ones. Recognition never reduces the score by itself (no evasion). |
| G06 | HTTP header value/presence consistency vs claimed browser _(shipped)_ | low | Cheap server-side rule set; validate against the CF/nginx path first (proxies can rewrite/strip these) — same caveat that made sec_fetch_missing soft. |
| G07 | WebGL vendor/renderer/feature internal inconsistency _(shipped)_ | low | Collect the vendor string too (we only keep the renderer) and add a vendor/renderer coherence rule. |
