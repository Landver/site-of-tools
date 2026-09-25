# Tracking parameters — the strip list

**Compiled 2026-09-25.** The evidence behind A4
([01](../01-feature-inventory.md#a4-tracking-parameter-removal)) and behind the
open decision in [02 §4](../02-build-fit.md#4-what-we-are-not-matching-and-the-clearurls-decision):
hand-write the rules, embed ClearURLs' LGPL-3.0 catalog, or fetch it at runtime.

Two inputs. Vendor documentation, fetched today, for provenance. A measured copy
of the ClearURLs catalog (`data.minify.json`, 106,070 bytes, 206 providers, 733
rules, 48 globalRules, 79 exceptions, 64 redirections) for coverage and for what
adopting it would actually cost.

## 0. How to read the tables

| Column | Means |
|---|---|
| **Identifies** | click (one ad click), session (a visit or a placement), person (an individual, joinable to an identity by the vendor), affiliate (money) |
| **Scope** | `global` = the name alone is sufficient evidence; `site` = only safe with a host match |
| **Safe** | confidence that deleting it changes nothing the user wanted |
| **Src** | see [§8](#8-sources) |

Evidence marker in **Src**: **V** = primary vendor document cited. **C** =
present in the ClearURLs catalog, provenance not independently confirmed. **B** =
believed, observed in the wild, no primary document found today. Treat every
**B** row as a candidate for a bug report, not as settled.

---

## 1. The proposed table

75 rows, 74 entries — the Braze row in [§1.4](#14-email-and-marketing-automation--16)
is deliberately empty and explained there. Families (`utm_*`, `mtm_*`, `pd_rd_*`)
count as one row and are matched by prefix, not by regex; see
[§7](#7-for-us) for why this table has no regexes in it.

### 1.1 Google Ads and Analytics — 12

| Parameter | Set by | Identifies | Scope | Safe | Src |
|---|---|---|---|---|---|
| `gclid` | Google Ads auto-tagging | click | global | 99% | V [GA-VT] |
| `gclsrc` | Google Ads / gtag.js | click source (`aw.ds`, `3p.ds`) | global | 99% | B |
| `gbraid` | Google Ads, iOS web-to-app | click cohort, deliberately non-unique | global | 99% | V [GA-IOS] |
| `wbraid` | Google Ads, iOS app-to-web | click cohort | global | 99% | V [GA-IOS] |
| `dclid` | Campaign Manager 360 / DV360 | display click | global | 99% | C |
| `srsltid` | Google Merchant Center, free listings | click | global | 99% | C |
| `gad_source` | Google Ads (2023+) | click surface | global | 95% | B |
| `gad_campaignid` | Google Ads (2024+) | campaign | global | 95% | B |
| `_gl` | GA4 cross-domain linker | **person** — carries client ID + session ID across domains | global | 95% | V [GA4-XD] |
| `_ga` | GA linker, legacy form | **person** — client ID | global | 95% | C |
| `ga_*` family | GA for email, legacy | campaign | global | 95% | C |
| `gs_l` | Google web search | session, result-position log | global | 95% | C |

`_gl` is the single most consequential row in this section: Google's own
documentation says the cookies "retain the same IDs as they are passed from one
domain to another via a URL parameter (`_gl`)" [GA4-XD]. It is an identity
join, in the clear, in a link people paste into chat.

### 1.2 Meta — 11

| Parameter | Set by | Identifies | Scope | Safe | Src |
|---|---|---|---|---|---|
| `fbclid` | Meta Pixel / ad click | click, becomes the `fbc` identifier server-side | global | 99% | C |
| `fb_action_ids` | Facebook share/story | session | global | 99% | C |
| `fb_action_types` | Facebook share/story | session | global | 99% | C |
| `fb_source` | Facebook | session, click surface | global | 99% | C |
| `fb_ref` | Facebook | session, referrer slot | global | 99% | C |
| `action_object_map` | Facebook Open Graph | session | global | 99% | C |
| `action_type_map` | Facebook Open Graph | session | global | 99% | C |
| `action_ref_map` | Facebook Open Graph | session | global | 99% | C |
| `mibextid` | Meta mobile share | session | global | 95% | C |
| `__tn__` | facebook.com | session, internal surface code | site | 95% | C |
| `__cft__[0]`, `__xts__[0]` | facebook.com | session, click-tracking blob | site | 95% | C |

### 1.3 Microsoft, TikTok, X, Yandex — 14

| Parameter | Set by | Identifies | Scope | Safe | Src |
|---|---|---|---|---|---|
| `msclkid` | Microsoft Advertising auto-tagging | click — a 32-char GUID unique per click, on by default | global | 99% | V [MSFT] |
| `ttclid` | TikTok Ads | click, stored 28+ days and replayed to the Events API | global | 99% | V [TT] |
| `tt_medium` | TikTok campaign tagging | campaign | global | 90% | B |
| `tt_content` | TikTok campaign tagging | campaign | global | 90% | B |
| `_t`, `_r`, `_d` | tiktok.com share | session | site | 90% | C |
| `share_app_name`, `share_iid`, `u_code` | tiktok.com share | session | site | 90% | C |
| `twclid` | X Ads | click | global | 99% | C |
| `__twitter_impression` | X / embeds | session | global | 99% | C |
| `s` | x.com, twitter.com share sheet (`s=20`, `s=46`) | session, share surface | **site** | 85% | B |
| `t` | x.com share link | session, opaque token | **site** | 85% | B |
| `ref_src` | twitter.com embeds | session | site | 95% | C |
| `ref_url` | twitter.com embeds | session, the referring page URL | site | 95% | C |
| `yclid` | Yandex.Direct | click | global | 99% | C |
| `_openstat` | Openstat / LiveInternet | campaign blob (base64 of four fields) | global | 99% | C |

`s` and `t` are the two entries in this section that must not be global. See
[§3](#3-the-ambiguous-middle).

### 1.4 Email and marketing automation — 16

| Parameter | Set by | Identifies | Scope | Safe | Src |
|---|---|---|---|---|---|
| `mc_cid` | Mailchimp | campaign — "the Mailchimp ID for the campaign that generated the link" | global | 99% | V [MC] |
| `mc_eid` | Mailchimp | **person** — the recipient's unique email ID | global | 95% | V [MC] |
| `mc_tc` | Mailchimp | session, tracking context | global | 95% | C |
| `__hstc` | HubSpot | **person** — the main visitor cookie, contains `hubspotutk` | global | 99% | V [HS] |
| `__hssc` | HubSpot | session | global | 99% | V [HS] |
| `__hsfp` | HubSpot | **person** — device fingerprint | global | 99% | B |
| `_hsenc` | HubSpot email | **person** — encoded recipient token | global | 99% | C |
| `_hsmi` | HubSpot email | campaign, message ID | global | 99% | B |
| `hsCtaTracking` | HubSpot CTA | session, CTA GUID pair | global | 99% | C |
| `mkt_tok` | Marketo / Adobe | **person** — base64 blob carrying the lead ID and send ID | global | 99% | C |
| `_kx` | Klaviyo | **person** — "a unique encrypted value … decrypted by Klaviyo's web tracking to identify the user who clicked" | global | 99% | V [KL] |
| Braze | — | — | — | — | see note |
| `s_cid` | Adobe Campaign / Analytics | campaign | global | 95% | C |
| `s_kwcid` | Adobe Advertising | click, keyword ID | global | 95% | B |
| `ef_id` | Adobe Advertising Cloud | click | global | 95% | B |
| `sc_cid` | Adobe (SiteCatalyst) | campaign | global | 90% | B |

**Braze has no entry, and that is the finding.** Braze's click tracking rewrites
the link's *host* (`ablink.<brand>.com/ls/click?upn=…`) rather than appending a
parameter to the original URL. There is nothing for A4 to delete. It belongs to
A16 wrapper-unwrapping instead, which is the same shape as the ClearURLs
`redirections` problem in [§6](#6-the-64-redirections-are-host-changing).
`bsft_*` (Blueshift) and `vero_*` (Vero) are the same category of vendor but do
use parameters; only `vero_conv` / `vero_id` appear in the catalog.

Adobe's conventional campaign slot is `cid` — deliberately **not** in this
table. See [§2](#2-never-strip).

### 1.5 Open analytics families — 5

| Parameter | Set by | Identifies | Scope | Safe | Src |
|---|---|---|---|---|---|
| `utm_*` prefix | GA, and by now everyone | campaign (`utm_source`, `_medium`, `_campaign`, `_term`, `_content`, `_id`, `_source_platform`, `_creative_format`, `_marketing_tactic`) | global | 99% | V [MTM] |
| `mtm_*` prefix | Matomo 4+ | campaign — eight documented: `mtm_campaign`, `_source`, `_medium`, `_keyword`, `_content`, `_cid`, `_group`, `_placement` | global | 99% | V [MTM] |
| `pk_*` prefix | Piwik / Matomo 3 and below | campaign — `pk_campaign`, `_source`, `_medium`, `_keyword`, `_content`, `_cid`, `pk_kwd` | global | 99% | V [MTM] |
| `piwik_*` prefix | Piwik, legacy | campaign | global | 99% | V [MTM] |
| `matomo_*` prefix | Matomo alias | campaign | global | 99% | V [MTM] |

Matomo documents that `pk_` and `piwik_` remain supported for backwards
compatibility and that `utm_*` is also consumed, with `mtm_` winning on conflict
[MTM]. So a Matomo site emits any of three prefixes, and all three must be in
the table or the feature looks arbitrary.

### 1.6 Site-scoped — 17

These are the rows that make the case for a two-tier table. Every one of them is
a name that is a tracker on the listed host and something else elsewhere.

| Parameter | Host | Identifies | Safe | Src |
|---|---|---|---|---|
| `igshid`, `igsh` | instagram.com | session, share ID | 95% | C |
| `si` | youtube.com, youtu.be, open.spotify.com | session, share-attribution token | 80% | B |
| `feature`, `kw`, `pp` | youtube.com | session, surface | 85% | C |
| `tag` | amazon.* | **affiliate** — the Associates tag; deleting it takes money from a creator | 60% | C |
| `ref`, `ref_` | amazon.* | session, placement breadcrumb | 90% | C |
| `th`, `psc` | amazon.* | variant selector — **strips at your own risk**, these choose which child ASIN renders | 60% | C |
| `pd_rd_*`, `pf_rd_*` prefix | amazon.* | session, recommendation slot | 95% | C |
| `qid`, `sr`, `crid`, `sprefix` | amazon.* | session, search context | 95% | C |
| `linkCode`, `ascsubtag`, `creativeASIN`, `camp`, `creative` | amazon.* | affiliate attribution | 80% | C |
| `spm`, `scm*` prefix | aliexpress.*, taobao.com, tmall.com, lazada.* | session, placement path | 90% | C |
| `algo_pvid`, `algo_expid`, `ws_ab_test`, `btsid`, `gps-id`, `terminal_id`, `aff_request_id` | aliexpress.* | session, experiment arm | 90% | C |
| `trk`, `trkInfo`, `refId`, `trackingId` | linkedin.com | session, traffic-source code | 95% | C |
| `lipi`, `licu`, `lici` | linkedin.com | **person** — page-instance IDs | 95% | C |
| `originalSubdomain`, `li_fat_id` | linkedin.com | session / ad click | 90% | B |
| `share_id`, `correlation_id`, `ref_campaign`, `ref_source`, `rdt`, `_branch_match_id`, `$deep_link`, `$3p`, `$original_url` | reddit.com | session, share and Branch deep-link IDs | 95% | C |

Two more groups that the catalog does **not** cover at all, so every row is **B**:

| Parameter | Host | Identifies | Safe | Src |
|---|---|---|---|---|
| `r`, `publication_id`, `post_id`, `isFreemail`, `triedRedirect`, `showWelcomeOnShare` | substack.com and custom Substack domains | **person** — `r` is the referring subscriber | 70% | B |
| `_pos`, `_sid`, `_ss`, `_psq`, `_v`, `_fd`, `pr_prod_strat`, `pr_rec_id`, `pr_rec_pid`, `pr_ref_pid`, `pr_seq` | Shopify storefronts | session, search position and recommendation IDs | 80% | B |

Shopify's `variant` is **functional** and never strippable. `_sid` on a Shopify
storefront and `sid` as a session key are one letter apart and opposite
verdicts, which is exactly the trap [§3](#3-the-ambiguous-middle) is about.

---

## 2. Never strip

A prefix rule is one careless entry away from eating any of these. The table
below is not documentation; it should be compiled into a deny set that is
checked *before* any rule fires, with a test asserting the two sets do not
intersect.

| Parameter | Who reads it | Failure mode if deleted |
|---|---|---|
| `q` | every search box; also `google.com/url?q=` | the search is gone. On the Google redirect wrapper `q` **is** the destination — deleting it turns an unwrap into a dead link |
| `id`, `uid`, `pid`, `item`, `sku` | every CMS and REST route | wrong record, or 404 |
| `page`, `p`, `offset`, `limit`, `cursor`, `after` | pagination everywhere | silently resets to page 1; the user thinks the link was wrong |
| `token` | password reset, magic links, email confirmation, API auth | the link is dead. Usually single-use, so retrying does not recover it |
| `code` | OAuth 2.0 authorization response [RFC6749 §4.1.2] | the token exchange never happens; login loops back to the start |
| `state` | OAuth 2.0 CSRF binding [RFC6749 §10.12] | the client sees a callback it cannot bind to its request and **fails closed** — correct behaviour, incomprehensible error message |
| `redirect_uri` | OAuth 2.0 authorization request [RFC6749 §3.1.2] | `invalid_request` from the authorization server, or a silent fall-back to a registered default that is not where the user was going |
| `nonce` | OpenID Connect | ID-token validation fails |
| `session`, `sid`, `sessionid`, `jsessionid`, `PHPSESSID`, `s_id` | session-in-URL apps (old, but alive) | logged out |
| `sig`, `signature`, `hmac`, `mac` | signed links generally | signature mismatch, 403 |
| `X-Amz-Signature`, `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-Expires`, `X-Amz-SignedHeaders`, `X-Amz-Algorithm`, `X-Amz-Security-Token` | S3 presigned URLs [AWS] | **403 `SignatureDoesNotMatch`.** Worse than it looks: the canonical query string covers *every* query parameter except `X-Amz-Signature`, so deleting **any** parameter from a presigned URL — including a genuine `utm_source` someone appended — invalidates it |
| `Expires`, `Signature`, `AWSAccessKeyId` | S3 SigV2 presigned | same, 403 |
| `X-Goog-Signature`, `X-Goog-Credential`, … | GCS signed URLs | same |
| `sv`, `se`, `sp`, `sr`, `st`, `sig` | Azure Blob SAS tokens | same. Note `sp` collides with a Bing tracking parameter |
| `Key-Pair-Id`, `Policy`, `Signature` | CloudFront signed URLs | same |
| `v` | **youtube.com/watch** | `?v=` is the video ID. Strip it and the URL is the YouTube homepage. The single most quotable failure in this table |
| `t`, `start` | youtu.be, youtube.com timestamps (`?t=90`) | the deep link into the middle of a video is lost. **`t` is a tracker on x.com and a timestamp on YouTube** |
| `si` | Spotify collaborative and private playlist invites | reported to gate access on invite links: the recipient gets a permission error rather than the playlist. `si` on a plain track link is tracking; on an invite it is a capability. **B — verify before shipping any global `si` rule** |
| `u`, `id`, `e`, `c`, `hash` on `list-manage.com/unsubscribe` and friends | one-click unsubscribe endpoints | **the unsubscribe silently does nothing.** An anti-tracking tool that breaks the opt-out link is the worst possible outcome for this feature |
| `ref` on git forges (`?ref=main`) | GitLab, Gitea, GitHub raw | wrong branch or 404. ClearURLs carries **three separate exceptions** for this exact case |
| `format`, `output`, `callback`, `jsonp`, `alt` | API response shaping | wrong content type, or a JSONP call that never invokes its callback |
| `lang`, `hl`, `locale`, `gl` | localisation | wrong language. Note `gl` and `_gl` differ by an underscore |
| `cid`, `icid`, `int_cid` | Adobe's conventional campaign slot — **and** "customer id", "conversation id", "channel id" on countless apps | this is the ambiguous case that most looks safe and is not |
| `variant` | Shopify product pages | wrong product variant, wrong price |
| `share`, `dl`, `download`, `raw` | content disposition | renders instead of downloading |

---

## 3. The ambiguous middle

`ref` · `source` · `from` · `si` · `tag` · `s` · `t` · `u` · `r` · `id` · `cid` ·
`mc` · `sp` · `_sid`

A site-agnostic table keys on the parameter **name alone**. A name carries no
information about the server that will read it. `ref=facebook` is a tracker;
`ref=main` picks a git branch; `ref=1234` is a foreign key. Nothing in the string
distinguishes them, and no amount of value heuristics fixes it, because
`ref=main` and `ref=email` are the same shape.

**The catalog proves the point against itself.** ClearURLs does not put `ref_?`
in its global `rules`; it puts it in `referralMarketing`, which is **off by
default**. And it still needs **79 exceptions** to survive its own global list —
48 of them attached to `globalRules` alone. Ten of those exceptions exist purely
to protect `ref=` or `referrer=` on specific hosts: `gcsip.com`, `bugtracker.*`,
`git(lab).*`, `/-/refs/switch`, `tweakers.net/ext/lt.dsp`, `stripe.com`,
`lichess.org/login`, `like.co`, `sso.serverplan.com`, `login.meijer.com`. A rule
that needs ten hand-written carve-outs is not a global rule with bugs. It is a
site rule that was filed in the wrong drawer.

The same catalog also shows the reverse: `si` appears **only** under
`spotify.com` and `youtube`, `igshid` only under `instagram`, `s`/`t` only under
`twitter`, `tag` only under `amazon` and only as `referralMarketing`. The
vendor with 206 providers and a decade of bug reports scoped every one of these
to a host. We should not be braver than they are on day one.

**What this implies for scope.**

1. `rules.go` gets **two tiers**, not one: `Hosts == nil` means global, otherwise
   a list of registrable-domain suffixes. This is a struct field, not a second
   table, so there is one code path.
2. Nothing in the ambiguous set ships as global. Ever. It ships host-scoped or
   it does not ship.
3. A third class, **affiliate**, is listed and *off by default* — mirroring
   ClearURLs' `referralMarketing`. Stripping `gclid` costs an advertiser a data
   point. Stripping `tag` takes money from a creator who wrote a review the user
   found useful. Those are different decisions and the UI should let the user
   make the second one deliberately.
4. A4 already promises that the output "names every parameter removed and the
   rule that removed it" ([01](../01-feature-inventory.md#a4-tracking-parameter-removal)).
   That promise is what makes a wrong rule *reportable* instead of invisible, and
   it is the only reason shipping a **B**-marked rule is acceptable at all.
5. The honest scope statement for the page: *"a curated list, not a complete
   one — it will miss regional ad networks, and it will not guess about
   parameters that are functional on some sites."* That is a better claim than
   an unfalsifiable "% of trackers removed", which
   [02 §5](../02-build-fit.md#5-structurally-impossible-here) already rules out.

---

## 4. Coverage against ClearURLs

### 4.1 The number

Scoring the 74-entry table above against ClearURLs' 48 `globalRules`:

| | Count | Share |
|---|---|---|
| Global rules a hand-written table covers | **27** | **56%** |
| Global rules it would plausibly miss | **21** | 44% |

The 21 missed, with best-guess origin:

| ClearURLs global rule | Origin (best guess) |
|---|---|
| `ml_subscriber`, `ml_subscriber_hash` | MailerLite |
| `oly_anon_id`, `oly_enc_id` | Omeda |
| `vero_conv`, `vero_id` | Vero |
| `__s` | Drip |
| `wickedid` | Wicked Reports |
| `os_ehash` | Opensense |
| `rb_clickid` | unidentified |
| `wt_?z?mc`, `wtrid` | Webtrekk / Mapp |
| `Echobox` | Echobox |
| `ceneo_spo` | Ceneo (PL price comparison) |
| `otm_[a-z_]*` | Otomoto (PL) |
| `hmb_(campaign\|medium\|source)` | Humble Bundle |
| `itm_(campaign\|medium\|source)` | Piano / newsroom CMSes |
| `vn(?:_[a-z]*)+` | unidentified |
| `tracking_source` | unidentified |
| `cmpid` | generic campaign ID |
| `[a-z]?mc` | see below |

**The character of the miss matters more than the percentage.** Seventeen of the
21 are single-vendor ESP or regional-analytics products — Polish price
comparison, German Webtrekk, a Dutch newsroom convention. The head of the
distribution (Google, Meta, Microsoft, TikTok, X, Yandex, Mailchimp, HubSpot,
Marketo, Matomo, the `utm_` family) is fully covered by hand. What a hand-written
list buys you is the head; what the catalog buys you is the tail.

### 4.2 The number runs the other way too

Four parameters in the hand-written table appear **nowhere in the catalog's 733
rules**:

| Parameter | Hits in all 733 rules |
|---|---|
| `gbraid` | 0 |
| `wbraid` | 0 |
| `gclsrc` | 0 |
| `ttclid` | 0 |

`gbraid` and `wbraid` are Google's post-ATT iOS click IDs [GA-IOS]; `ttclid` is
TikTok's click ID, which TikTok's own documentation tells advertisers to persist
for 28 days or more [TT]. These are not obscure. They are the parameters a 2026
ad click actually carries, and the catalog does not know about them.

Four more are global in the hand-written table and only site-scoped or absent in
the catalog: `gad_source` (0 hits), `gad_campaignid` (0), `_hsmi` (1 hit, under
`deeplearning.ai`), `pk_*` (2 hits, under `vivaldi`). `li_fat_id` and `epik`:
0 hits each.

### 4.3 Two caveats on the comparison

**Rule count understates them.** ClearURLs' 48 are regexes, several of which
expand to many names: `utm(?:_[a-z_]*)?` is open-ended, `mc_(?:eid|cid|tc)` is
three, `fb_(?:source|ref)` is two. Comparing rule counts flatters a hand-written
name list and comparing name counts flatters a regex list. 56% is the count of
*their rules* we would satisfy, which is the number the decision actually needs.

**Some of their global rules we would decline on purpose.** `[a-z]?mc` matches a
bare `mc` and any single letter followed by `mc`. `cmpid`, `__s`, `tracking_source`
and `spm` are broad names at global scope. Adopting the global list wholesale
means adopting those *and* the 48 global exceptions that make them survivable —
and adopting the rules without the exceptions would be strictly worse than
writing nothing.

---

## 5. The licence

**Verified today.** `https://raw.githubusercontent.com/ClearURLs/Rules/master/LICENSE`
is the **GNU Lesser General Public License, Version 3, 29 June 2007** [CU-LIC].
The upstream is GitLab (`kevinroebert/ClearUrls`, rules now under the `ClearURLs`
group); the GitHub copy is a read-only mirror.

This repo is MIT. Plainly, and as an engineer rather than a lawyer:

**What embedding LGPL-3.0 data would require.**

- Keep the licence notice with the data, ship a copy of the LGPL-3.0 text, and
  state prominently that the catalog is ClearURLs' and LGPL-3.0 — on the Clean
  page, not only in a file nobody opens.
- Make the data replaceable. LGPL-3.0 §4 permits conveying a combined work under
  your own terms *provided the recipient can modify the covered part and relink*.
  For a Go binary with `CGO_ENABLED=0` there is no shared-library option, so
  §4(d)(1) — supplying the source in a form suitable for recombining — is the
  route. In practice: publish the JSON, document how to rebuild with a modified
  copy, and do not obfuscate it.
- Carry modifications forward. If we edit the catalog, those edits are LGPL-3.0.

**What it would not do.**

- **It would not make the rest of the repo LGPL.** LGPL-3.0 §4 exists precisely
  so a combined work can carry your own licence terms. MIT code around an LGPL
  component stays MIT.
- It would not require publishing our own source. The repo is public anyway, so
  this is moot here, but it is the fear people usually have and it is misplaced.
- It would not require the binary to be dynamically linked, despite the
  folklore. §4 offers relinking as one satisfying condition among alternatives.

**The genuinely unsettled part**, stated as such: the LGPL is written about
*libraries*. Whether a JSON **data file** — no code, no linking — triggers §4's
relinking machinery at all is unclear, and reasonable people disagree. That
uncertainty is itself a reason to avoid the question rather than resolve it.

Separately: the Go port [`ddlsmurf/clearurls-go`](https://pkg.go.dev/github.com/ddlsmurf/clearurls-go/clearurls)
is LGPL-3.0 **code**, not data, and pulls 13 dependencies. That is a different
and much stronger obligation than the JSON, and it also fails
[02 §1](../02-build-fit.md#1-tier-0--pure-go-stdlib-only-no-network-no-state)'s
"zero new modules".

**This is not legal advice.** It is a reading of the licence text by someone
who is not a lawyer. If the answer matters, ask one — or take the option that
does not need an answer.

---

## 6. The 64 redirections are host-changing

**Measured: 64 redirection rules across 61 providers.** Five of the 61 are the
vendor's own test fixtures (`ClearURLsTest`, `ClearURLsTest2`, `site.com`,
`site2.com`, `site3.com`), so **59 are real** — adopting wholesale also imports
someone else's test data.

Per the catalog spec, a redirection is a regex whose **first capture group is
`decodeURIComponent`'d and becomes the new URL** [CU-SPEC]. `google` additionally
sets `forceRedirection`, which the spec describes as writing the URL into the
browser's `main_frame`.

[04 §9](../04-short-links.md#9-api-contract) requires that cleaning **only ever
deletes query parameters**. Adopting ClearURLs wholesale breaks that in four
separate ways, not one:

| Mechanism | Count | What it does | Verdict |
|---|---|---|---|
| `redirections` | 59 real (64 incl. fixtures), 61 providers | replaces the entire URL with a captured substring — **different host** | incompatible |
| `rawRules` | 4, across `amazon`, `amazon search`, `bigfishgames.com`, `pantip.com` | "can refer to the entire URL and not just to individual fields" [CU-SPEC]. `\/ref=[^/?]*` deletes a **path segment**; `#lead.*` deletes the **fragment** | incompatible |
| `completeProvider` | 10 providers | "every URL that matches the urlPattern will be blocked" [CU-SPEC] — the output is *nothing* | incompatible |
| ordinary `rules` | all 733 | compile to `(?:&\|[/?#&])(?:<field>=[^&]*)` [CU-SPEC]. The delimiter class contains `/` and `#`, so a rule can delete matching text from the **path and fragment**, not only the query | incompatible as written |

The last row is the one that would be missed in review. The rules that look like
plain parameter deletions are not scoped to the query string by construction;
they are scoped by a character class that includes the path separator. Any
adoption would have to re-implement matching rather than port it, which removes
most of the labour saving that made adoption attractive.

**Providers carrying redirections**, grouped:

- **Platforms:** `google` (3 rules, plus `forceRedirection`), `facebook`,
  `messenger.com`, `instagram`, `reddit` (2), `youtube`, `duckduckgo`,
  `steamcommunity`, `vk.com`, `deviantart.com`, `t.umblr.com`, `disq.us`,
  `getpocket.com`, `curseforge.com`, `ebay`, `tokopedia.com`, `rutracker.org`,
  `mysku.ru`, `imgsrc.ru`, `bilibili`-adjacent `cc.loginfra.com`.
- **Ad tech:** `doubleclick`, `googleadservices`, `amazon-adsystem`,
  `adform.net`, `app.adjust.com`, `artefact.com`, `exactag.com`.
- **Affiliate networks (the largest group):** `awin1.com`, `admitad.com`,
  `tradedoubler.com`, `linksynergy.com`, `dpbolvw.net`, `digidip.net`,
  `skimresources.com`, `viglink.com`, `webgains.com`, `effiliation.com`,
  `flexlinkspro.com`, `partner-ads.com`, `idealo-partner.com`,
  `smartredirect.de`, `hlserve.com`, `srvtrck.com`, `signtr.website`,
  `alabout.com`, `ccbill.com`, `telekom.de`.
- **Email / mail infrastructure:** `awstrack.me`, `govdelivery.com`,
  `mailtrack.io`, `mailpanion.com`, `mozaws.net`, `mozgcp.net`.
- **Generic link cloakers:** `href.li`, `anonym.to`, `gate.sc`.

**This is not a reason to ignore them.** It is a reason to file them under
[A16](../01-feature-inventory.md#a16-known-wrapper-unwrap), which already wants
exactly this behaviour — as a *named, reported* step ("this is a
`l.facebook.com` wrapper; the real target is …") rather than a silent rewrite.
The 59 real rules are a useful *source* for A16's table, under the same licence
question as everything else here, and they must not be folded into Clean.

---

## 7. For us

**Recommendation: (a) hand-write the table. Confidence 80%**, up from the ~60%
in [02 §4](../02-build-fit.md#4-what-we-are-not-matching-and-the-clearurls-decision).
The evidence moved the number, and it moved it for reasons that are not about
licensing.

1. **The coverage gap is the tail, not the head.** 56% of their global rules,
   and the missing 44% is MailerLite, Omeda, Vero, Webtrekk, Ceneo, Otomoto.
   A visitor to `link.corpberry.com` pasting a link from their inbox meets
   `gclid`, `fbclid`, `utm_*`, `mc_eid` and `mkt_tok`. All covered.
2. **The hand-written table is better where it counts.** `gbraid`, `wbraid`,
   `gclsrc` and `ttclid` appear in **none** of the catalog's 733 rules. On the
   four click IDs that a 2026 ad click most often carries, hand-written wins
   outright.
3. **Adoption is not a data problem, it is a rewrite.** Four separate mechanisms
   ([§6](#6-the-64-redirections-are-host-changing)) violate the query-only
   invariant, including the ordinary `rules`' own delimiter class. Porting means
   re-implementing matching and then hand-filtering 733 rules, 79 exceptions and
   10 blocklist providers. The labour saving mostly evaporates.
4. **Licence uncertainty is real but secondary.** The honest position is that a
   data file probably does not trigger §4 and definitely does not infect MIT
   code — and that "probably" is not worth carrying when option (a) is this
   close on merit.

**Do not choose (b).** Embedding buys the tail at the cost of an unsettled
licence question, someone else's test fixtures, and a set of global rules
(`[a-z]?mc`, `cmpid`, `__s`) that only work alongside 48 exceptions.

**Keep (c) in reserve, documented, not built.** Structure `rules.go` so an
optional runtime loader could read a ClearURLs-format file from a configured
path — nil means off, in the repo's existing idiom — dropping `redirections`,
`rawRules` and `completeProvider` on load. Nothing LGPL enters the binary or the
repo, and anyone who wants the tail can have it. One config value and a
converter, deferred until someone asks.

### The Go table shape

Fits `rules.go` as described in
[03 §1](../03-architecture.md#1-package-layout), and feeds `Param.Tracking`
in [03 §2](../03-architecture.md#2-domain-types).

```go
// Rule is one entry in the tracking-parameter table.
//
// Matching is exact, case-insensitive on the ASCII-lowercased key — no regexes.
// ClearURLs' own "[a-z]?mc" is the argument against regexes here: a rule nobody
// can read at a glance is a rule nobody reviews, and this table's whole claim
// (A4) is that every deletion is auditable.
type Rule struct {
	Param  string   // exact parameter name, lowercase; or the prefix when Prefix
	Prefix bool     // match Param as a prefix: "utm_", "mtm_", "pd_rd_"
	Hosts  []string // nil = global. Otherwise registrable-domain suffixes.
	Origin string   // "Google Ads", "Mailchimp" — shown in the UI verbatim
	Class  Class
	Note   string   // one line, shown when this rule fires
	Doc    string   // vendor doc URL, or "" when the entry is only believed
}

// Class drives both the default behaviour and what the UI says.
type Class uint8

const (
	ClassClick     Class = iota // an ad click ID: nothing user-visible is lost
	ClassSession                // a visit, placement or share breadcrumb
	ClassPerson                 // identifies an individual — the reason A4 exists
	ClassAffiliate              // pays someone: listed, and OFF by default
)

// Removed is what Clean reports per deleted parameter. The value is echoed back
// so the removal is reversible; that is the difference between a tool and magic.
type Removed struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Origin string `json:"origin"`
	Class  string `json:"class"`
	Note   string `json:"note,omitempty"`
	Doc    string `json:"doc,omitempty"`
}
```

Five invariants worth writing down before the table is:

1. **Deny set first.** [§2](#2-never-strip) compiles to a `map[string]struct{}`
   consulted before any rule, prefix rules included.
2. **A test asserts the two sets do not intersect** — `Rule.Param` never appears
   in the deny set, and no `Prefix` rule is a prefix of a deny-set entry. Three
   lines, catches an entire class of future bug.
3. **Query only.** Clean never touches scheme, host, path or fragment. That is
   [04 §9](../04-short-links.md#9-api-contract)'s contract and the thing
   [§6](#6-the-64-redirections-are-host-changing) shows the alternative breaking.
4. **`ClassAffiliate` is off by default**, with a checkbox that says what it
   does in plain words.
5. **Host matching is on the registrable domain suffix**, so `amazon.co.uk` and
   `smile.amazon.com` both match `amazon.` — and `notamazon.com` does not.

---

## 8. Sources

| Key | Source |
|---|---|
| GA-VT | Google Ads Help, *ValueTrack parameters* — `support.google.com/google-ads/answer/6305348`. Fetched 2026-09-25: `{gclid}` is "the Google click identifier of a click that comes from your ad" |
| GA-IOS | Google Ads Help, *Updates to iOS 14 campaign measurement* — `support.google.com/google-ads/answer/10417364`; *GBRAID URL parameter* — `support.google.com/google-ads/answer/16297842`. gbraid = web-to-app, wbraid = app-to-web, both deliberately non-unique |
| GA4-XD | Google Analytics Help, *Cross-domain measurement* — `support.google.com/analytics/answer/10071811`. Fetched 2026-09-25: the cookies' IDs are "passed from one domain to another via a URL parameter (`_gl`)" |
| MSFT | Microsoft Learn, *Auto-tagging of Microsoft Click ID* — `learn.microsoft.com/en-us/advertising/msa-help/hlp_ba_proc_microsoftclickid`. 32-character GUID, unique per click, enabled by default |
| TT | TikTok Ads Manager Help, *About TikTok Click ID* — `ads.tiktok.com/help/article/tiktok-click-id`. Appended on ad click; recommended storage TTL 28 days or more |
| MC | Mailchimp Developer, *E-Commerce Documentation* — `mailchimp.com/developer/marketing/docs/e-commerce/`. `mc_cid` is "the Mailchimp ID for the campaign that generated the link" |
| HS | HubSpot Knowledge Base, *What cookies does HubSpot set in a visitor's browser* — `knowledge.hubspot.com/reports/what-cookies-does-hubspot-set-in-a-visitor-s-browser`. `__hstc` is "the main cookie for tracking visitors" and contains `hubspotutk`; `__hssc` "keeps track of sessions" |
| KL | Klaviyo Help Center, *Understanding cookies in Klaviyo* — `help.klaviyo.com/hc/en-us/articles/360034666712`. `_kx` is "a unique encrypted value … decrypted by Klaviyo's web tracking to identify the user who clicked through the URL" |
| MTM | Matomo FAQ, *How to build campaign tracking URLs* — `matomo.org/faq/reports/how-to-build-campaign-tracking-urls/`; *How do I customise the Matomo Campaign parameters?* — `matomo.org/faq/how-to/faq_120/`. Eight `mtm_` parameters; `pk_`/`piwik_` supported for backwards compatibility; `utm_` also consumed, `mtm_` wins on conflict |
| AWS | AWS docs, *Authenticating Requests: Using Query Parameters (AWS Signature Version 4)* — `docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html`. The canonical query string "must include all the query parameters except for X-Amz-Signature" |
| RFC6749 | RFC 6749, *The OAuth 2.0 Authorization Framework* — §3.1.2 (`redirect_uri`), §4.1.1–4.1.2 (`code`, `state`), §10.12 (CSRF) |
| CU | The measured catalog — ClearURLs `data.minify.json`, 106,070 bytes, retrieved 2026-09-25. Rule present; provenance not independently confirmed |
| CU-SPEC | ClearURLs documentation, *Rule catalogs* — `docs.clearurls.xyz/specs/rules`. Rules compile to `(?:&\|[/?#&])(?:<field name>=[^&]*)`; rawRules "can refer to the entire URL"; completeProvider blocks every matching URL; redirections take the first capture group and `decodeURIComponent` it |
| CU-LIC | `raw.githubusercontent.com/ClearURLs/Rules/master/LICENSE`, fetched 2026-09-25 — **GNU Lesser General Public License, Version 3, 29 June 2007** |
