# Bot check — per-check reference

*(part of [testing index](../README.md), see [botcheck docs index](../../README.md))*

One file per implemented check (`tools/botcheck/scoring.go`'s `rules`, 66 total — verified by counting the `why` expander on the live result page, one per rendered check, not the historic per-rule-ID reserved-slot count in `report.go`). Each file is the single place for everything about that one check: **what it checks** (the logic, mirrored from `report.go`), **origin & history** (which `G##` roadmap item shipped it, when, why, what was tried and rejected), **test status** (verified/evaded/fixed/untested against real automation), and **Go scorer coverage** (which unit tests exercise it). Everywhere else that used to carry this per-check — `roadmap/*.md`, `changelog.md`, `findings/*.md`, `next-steps.md` — now points here instead of restating it; those files keep only what's genuinely cross-cutting (competitor comparisons, cross-framework audits, items with no shipped check yet).

One reserved rule ID with no active check yet, `system_color_headless` (see [go-test-suite.md](../../go-test-suite.md)), has no file here — nothing to report on until it lands.

## Fixed via the 2026-07-19 audit (7)

| Check | Tier | Weight |
|---|---|---|
| [`cdp_both`](cdp_both.md) | soft | 8 |
| [`cdp_main_only`](cdp_main_only.md) | soft | 8 |
| [`cdp_sw_only`](cdp_sw_only.md) | soft | 8 |
| [`gpu_os_mismatch`](gpu_os_mismatch.md) | consistency | 25 |
| [`software_renderer`](software_renderer.md) | hard | 40 |
| [`tostring_proxy`](tostring_proxy.md) | hard | 45 |
| [`webgl_vendor_mismatch`](webgl_vendor_mismatch.md) | consistency | 20 |

## Verified against real automation — mixed result (4)

| Check | Tier | Weight |
|---|---|---|
| [`bot_user_agent`](bot_user_agent.md) | hard | 60 |
| [`framework_globals`](framework_globals.md) | hard | 60 |
| [`iframe_webdriver`](iframe_webdriver.md) | hard | 60 |
| [`webdriver`](webdriver.md) | hard | 60 |

## Verified against real automation — fires correctly (4)

| Check | Tier | Weight |
|---|---|---|
| [`context_cores_mismatch`](context_cores_mismatch.md) | consistency | 20 |
| [`context_ua_mismatch`](context_ua_mismatch.md) | consistency | 35 |
| [`context_webgl_mismatch`](context_webgl_mismatch.md) | consistency | 20 |
| [`permission_impossible`](permission_impossible.md) | consistency | 25 |

## Verified against real automation — evaded, open gap (4)

| Check | Tier | Weight |
|---|---|---|
| [`chrome_late_injection`](chrome_late_injection.md) | consistency | 15 |
| [`native_callnew_tamper`](native_callnew_tamper.md) | consistency | 25 |
| [`native_descriptor_tamper`](native_descriptor_tamper.md) | consistency | 25 |
| [`navigator_proto_tamper`](navigator_proto_tamper.md) | consistency | 25 |

## Confirmed structural blind spot (1)

| Check | Tier | Weight |
|---|---|---|
| [`webdriver_sw`](webdriver_sw.md) | hard | 60 |

## Known gap, deprioritized (1)

| Check | Tier | Weight |
|---|---|---|
| [`chrome_runtime_tamper`](chrome_runtime_tamper.md) | consistency | 20 |

## Investigated, closed as non-issue (2)

| Check | Tier | Weight |
|---|---|---|
| [`tz_mismatch`](tz_mismatch.md) | consistency | 25 |
| [`webrtc_ip_mismatch`](webrtc_ip_mismatch.md) | consistency | 25 |

## Not yet tested against real automation (43)

| Check | Tier | Weight |
|---|---|---|
| [`accept_encoding_missing`](accept_encoding_missing.md) | soft | 8 |
| [`accept_language_missing`](accept_language_missing.md) | soft | 8 |
| [`accept_nav_mismatch`](accept_nav_mismatch.md) | soft | 8 |
| [`app_version_mismatch`](app_version_mismatch.md) | consistency | 15 |
| [`canvas_blank`](canvas_blank.md) | soft | 8 |
| [`canvas_unstable`](canvas_unstable.md) | consistency | 15 |
| [`ch_brands_mismatch`](ch_brands_mismatch.md) | consistency | 20 |
| [`ch_platform_mismatch`](ch_platform_mismatch.md) | consistency | 30 |
| [`context_language_mismatch`](context_language_mismatch.md) | consistency | 20 |
| [`context_platform_mismatch`](context_platform_mismatch.md) | consistency | 25 |
| [`datacenter_ip`](datacenter_ip.md) | consistency | 30 |
| [`default_geometry`](default_geometry.md) | soft | 8 |
| [`embedded_runtime`](embedded_runtime.md) | consistency | 25 |
| [`empty_languages`](empty_languages.md) | soft | 8 |
| [`empty_plugins`](empty_plugins.md) | soft | 8 |
| [`engine_ua_mismatch`](engine_ua_mismatch.md) | consistency | 30 |
| [`fingerprint_reuse`](fingerprint_reuse.md) | consistency | 25 |
| [`iframe_proxy`](iframe_proxy.md) | consistency | 30 |
| [`image_broken`](image_broken.md) | soft | 8 |
| [`implausible_hardware`](implausible_hardware.md) | soft | 8 |
| [`impossible_window`](impossible_window.md) | soft | 8 |
| [`jsengine_ua_mismatch`](jsengine_ua_mismatch.md) | consistency | 25 |
| [`lang_mismatch`](lang_mismatch.md) | consistency | 15 |
| [`language_primary_mismatch`](language_primary_mismatch.md) | consistency | 15 |
| [`low_color_depth`](low_color_depth.md) | soft | 8 |
| [`matchmedia_missing`](matchmedia_missing.md) | soft | 8 |
| [`missing_proprietary_codecs`](missing_proprietary_codecs.md) | soft | 8 |
| [`mobile_no_touch`](mobile_no_touch.md) | consistency | 20 |
| [`native_tamper`](native_tamper.md) | hard | 45 |
| [`netinfo_incoherent`](netinfo_incoherent.md) | soft | 8 |
| [`no_chrome_object`](no_chrome_object.md) | soft | 8 |
| [`no_fonts`](no_fonts.md) | soft | 8 |
| [`plugins_mimetypes_incoherent`](plugins_mimetypes_incoherent.md) | soft | 8 |
| [`productsub_mismatch`](productsub_mismatch.md) | consistency | 20 |
| [`proxy_ip`](proxy_ip.md) | consistency | 20 |
| [`screen_avail_impossible`](screen_avail_impossible.md) | soft | 8 |
| [`sec_fetch_missing`](sec_fetch_missing.md) | soft | 8 |
| [`tz_self_inconsistent`](tz_self_inconsistent.md) | consistency | 25 |
| [`ua_chrome_version_mismatch`](ua_chrome_version_mismatch.md) | consistency | 25 |
| [`ua_header_mismatch`](ua_header_mismatch.md) | consistency | 35 |
| [`ua_os_mismatch`](ua_os_mismatch.md) | consistency | 30 |
| [`vendor_mismatch`](vendor_mismatch.md) | consistency | 20 |
| [`zero_outer_height`](zero_outer_height.md) | soft | 8 |
