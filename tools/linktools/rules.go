package linktools

import (
	"slices"
	"strings"
)

// This file is data. The two tables below are the whole of A4 and A16, and the
// evidence for every row is in docs/reports/tracking-parameter-reference.md and
// docs/reports/wrapper-formats.md. Both were compiled 2026-09-25.
//
// The tracking table is HAND-WRITTEN, deliberately. ClearURLs' catalog is
// LGPL-3.0 and this repo is MIT (report §5), but licensing is the secondary
// reason. The primary ones (report §7): its 733 rules miss `gbraid`, `wbraid`,
// `gclsrc` and `ttclid` entirely — the four click IDs a 2026 ad click most often
// carries — and four separate mechanisms in its format (`redirections`,
// `rawRules`, `completeProvider`, and the ordinary rules' `[/?#&]` delimiter
// class) rewrite the host, path or fragment, which docs/04-short-links.md §9
// forbids. Adopting it would be a re-implementation, not a data import.
//
// Report §7 also asks that this file stay shaped so an optional runtime loader
// could read a ClearURLs-format file from a configured path later. Everything
// here is plain data behind two lookup functions, so that stays possible; it is
// documented, not built.
//
// Matching is exact on the ASCII-lowercased key, or by literal prefix. No
// regexes: ClearURLs' own `[a-z]?mc` is the argument against them. A rule nobody
// can read at a glance is a rule nobody reviews, and A4's whole claim
// (docs/01-feature-inventory.md#a4) is that every deletion is auditable.

// RulesVersion is bumped by hand whenever either table changes. The extension
// caches the catalog keyed on it (docs/05-extension.md §3), so it is part of the
// API, not a comment. Date form because the tables are dated evidence.
const RulesVersion = "2026-09-25"

// catalogScope is the honest scope statement the rules page must show, verbatim
// from the report §3.5. It is shipped as data so the page and the JSON API
// cannot drift apart, and so nobody is tempted to replace it with an
// unfalsifiable "% of trackers removed" — which docs/02-build-fit.md §5 rules
// out.
const catalogScope = "A curated list, not a complete one. It will miss regional ad networks, " +
	"and it will not guess about parameters that are functional on some sites."

// Class drives the default behaviour and what the UI says about a removal.
type Class uint8

const (
	ClassClick     Class = iota // an ad click ID: nothing user-visible is lost
	ClassSession                // a visit, placement or share breadcrumb
	ClassPerson                 // identifies an individual — the reason A4 exists
	ClassAffiliate              // pays someone: listed, and OFF by default
)

func (c Class) String() string {
	switch c {
	case ClassClick:
		return "click"
	case ClassSession:
		return "session"
	case ClassPerson:
		return "person"
	case ClassAffiliate:
		return "affiliate"
	}
	return "unknown"
}

// MarshalText makes the JSON say "person", not 2. The extension and any curl
// caller read this; an integer would be a private encoding leaking into an API.
func (c Class) MarshalText() ([]byte, error) { return []byte(c.String()), nil }

// why is the one-line explanation attached to every removal, so Removal.Why is
// never empty and the user is never asked to trust a bare rule name.
func (c Class) why() string {
	switch c {
	case ClassClick:
		return "identifies a single ad click; nothing you can see depends on it"
	case ClassSession:
		return "records the visit, placement or share that brought you here"
	case ClassPerson:
		return "identifies you as an individual to the vendor that set it"
	case ClassAffiliate:
		return "attributes a sale to whoever published the link"
	}
	return "tracking"
}

// Rule is one entry in the tracking-parameter table.
//
// Hosts is the two-tier part, and it is the finding the report argues hardest
// for (§3): `ref=facebook` is a tracker, `ref=main` picks a git branch, and
// nothing in the *name* separates them. ClearURLs needs 79 exceptions to survive
// its own global list, ten of them protecting `ref` alone. So the ambiguous
// names ship host-scoped or they do not ship. One struct field, one code path.
type Rule struct {
	Param  string   `json:"param"`            // exact parameter name, lowercase; or the prefix when Prefix
	Prefix bool     `json:"prefix,omitempty"` // match Param as a prefix: "utm_", "mtm_", "pd_rd_"
	Hosts  []string `json:"hosts,omitempty"`  // nil = global; otherwise see matchHost
	Origin string   `json:"origin"`           // "Google Ads", "Mailchimp" — shown in the UI verbatim
	Class  Class    `json:"class"`
	Note   string   `json:"note,omitempty"` // one line, shown when this rule fires
	Doc    string   `json:"doc,omitempty"`  // vendor doc URL, or "" when the entry is only believed
}

// applies reports whether this rule may fire for host. An affiliate rule needs
// the caller to have asked for affiliate stripping: report §3.3 — deleting
// `gclid` costs an advertiser a data point, deleting `tag` takes money from a
// creator whose review the user found useful. Different decisions.
func (r Rule) applies(host string, affiliate bool) bool {
	if r.Class == ClassAffiliate && !affiliate {
		return false
	}
	if len(r.Hosts) == 0 {
		return true
	}
	for _, h := range r.Hosts {
		if matchHost(host, h) {
			return true
		}
	}
	return false
}

// name is what A4 promises to print beside every deletion, and what lands in
// Param.Tracking so Inspect can mark a tracker without Clean being involved.
func (r Rule) name() string {
	if r.Prefix {
		return r.Param + "* · " + r.Origin
	}
	return r.Param + " · " + r.Origin
}

// Deny is one never-strip entry. Why is the failure mode, stored as data rather
// than left in a comment because the rules page prints it: "we do not touch
// `state` — here is what breaks if anyone does" is the sentence that makes the
// table reviewable by someone who is not reading this file.
//
// The deny set is consulted BEFORE any rule, prefix rules included (report §7
// invariant 1). A test asserts the two sets do not intersect on any shared host
// (invariant 2).
type Deny struct {
	Param  string   `json:"param"`
	Prefix bool     `json:"prefix,omitempty"`
	Hosts  []string `json:"hosts,omitempty"` // nil = never strip this anywhere
	Why    string   `json:"why"`
}

// ---------------------------------------------------------------------------
// The tracking table — report §1. 95 rules covering its 74 entries: a report row
// naming five parameters ("linkCode, ascsubtag, …") is five rules here, because
// a Rule holds one name.
//
// Rows the report lists and this table deliberately omits, so nobody
// rediscovers them as gaps:
//   - amazon `th`, `psc` — variant selectors, 60% safe. They choose which child
//     ASIN renders. Wrong product beats a clean URL.
//   - substack `publication_id`, `post_id` — they read as record IDs, which is
//     exactly the shape §2 says never to guess at.
//   - Shopify's whole group (`_pos`, `_ss`, `_psq`, `pr_*`) — they are only
//     identifiable by *host*, and a Shopify storefront is an arbitrary custom
//     domain. Scoping them to `myshopify.com` would cover the minority of
//     storefronts that never set one up; global would be reckless, since `_v`
//     and `_fd` are one keystroke from anything. Needs a fetch, so it is not
//     A4's problem.
//   - `si` on open.spotify.com — report §2 has it gating access on playlist
//     invite links, marked B. It ships for YouTube only until someone drives a
//     sample.
// ---------------------------------------------------------------------------

var trackingRules = []Rule{
	// --- Google Ads and Analytics (report §1.1) ---
	{Param: "gclid", Origin: "Google Ads", Class: ClassClick, Note: "Auto-tagged onto every ad click.", Doc: "https://support.google.com/google-ads/answer/6305348"},
	{Param: "gclsrc", Origin: "Google Ads", Class: ClassClick, Note: "Names the click source (aw.ds, 3p.ds). Absent from all 733 ClearURLs rules."},
	{Param: "gbraid", Origin: "Google Ads", Class: ClassClick, Note: "iOS web-to-app click cohort, added after ATT. Absent from ClearURLs.", Doc: "https://support.google.com/google-ads/answer/16297842"},
	{Param: "wbraid", Origin: "Google Ads", Class: ClassClick, Note: "iOS app-to-web click cohort. Absent from ClearURLs.", Doc: "https://support.google.com/google-ads/answer/10417364"},
	{Param: "dclid", Origin: "Campaign Manager 360", Class: ClassClick, Note: "Display click ID."},
	{Param: "srsltid", Origin: "Google Merchant Center", Class: ClassClick, Note: "Attached to free product listings in search."},
	{Param: "gad_source", Origin: "Google Ads", Class: ClassClick, Note: "Click surface, added 2023. Absent from ClearURLs."},
	{Param: "gad_campaignid", Origin: "Google Ads", Class: ClassSession, Note: "Campaign ID, added 2024. Absent from ClearURLs."},
	{Param: "_gl", Origin: "Google Analytics 4", Class: ClassPerson, Note: "The cross-domain linker: Google's own docs say the cookies' client ID and session ID are passed between domains in this parameter.", Doc: "https://support.google.com/analytics/answer/10071811"},
	{Param: "_ga", Origin: "Google Analytics", Class: ClassPerson, Note: "Legacy linker form of the client ID."},
	{Param: "ga_", Prefix: true, Origin: "Google Analytics for email", Class: ClassSession, Note: "Legacy campaign family."},
	{Param: "gs_l", Origin: "Google Search", Class: ClassSession, Note: "Result-position log from the search page."},

	// --- Meta (report §1.2) ---
	{Param: "fbclid", Origin: "Meta", Class: ClassClick, Note: "Becomes the fbc identifier server-side, so it outlives the click."},
	{Param: "fb_action_ids", Origin: "Facebook", Class: ClassSession},
	{Param: "fb_action_types", Origin: "Facebook", Class: ClassSession},
	{Param: "fb_source", Origin: "Facebook", Class: ClassSession, Note: "Which Facebook surface the link was clicked from."},
	{Param: "fb_ref", Origin: "Facebook", Class: ClassSession},
	{Param: "action_object_map", Origin: "Facebook Open Graph", Class: ClassSession},
	{Param: "action_type_map", Origin: "Facebook Open Graph", Class: ClassSession},
	{Param: "action_ref_map", Origin: "Facebook Open Graph", Class: ClassSession},
	{Param: "mibextid", Origin: "Meta", Class: ClassSession, Note: "Added by the mobile share sheet."},
	{Param: "__tn__", Hosts: []string{"facebook.com"}, Origin: "Facebook", Class: ClassSession, Note: "Internal surface code."},
	{Param: "__cft__", Prefix: true, Hosts: []string{"facebook.com"}, Origin: "Facebook", Class: ClassSession, Note: "Click-tracking blob; the real key is __cft__[0]."},
	{Param: "__xts__", Prefix: true, Hosts: []string{"facebook.com"}, Origin: "Facebook", Class: ClassSession, Note: "Click-tracking blob; the real key is __xts__[0]."},

	// --- Microsoft, TikTok, X, Yandex (report §1.3) ---
	{Param: "msclkid", Origin: "Microsoft Advertising", Class: ClassClick, Note: "A 32-character GUID, unique per click, auto-tagged on by default.", Doc: "https://learn.microsoft.com/en-us/advertising/msa-help/hlp_ba_proc_microsoftclickid"},
	{Param: "ttclid", Origin: "TikTok Ads", Class: ClassClick, Note: "TikTok tells advertisers to store it 28 days or more and replay it to the Events API. Absent from ClearURLs.", Doc: "https://ads.tiktok.com/help/article/tiktok-click-id"},
	{Param: "tt_medium", Origin: "TikTok", Class: ClassSession},
	{Param: "tt_content", Origin: "TikTok", Class: ClassSession},
	{Param: "share_app_name", Hosts: []string{"tiktok.com"}, Origin: "TikTok", Class: ClassSession},
	{Param: "share_iid", Hosts: []string{"tiktok.com"}, Origin: "TikTok", Class: ClassSession},
	{Param: "u_code", Hosts: []string{"tiktok.com"}, Origin: "TikTok", Class: ClassSession},
	{Param: "twclid", Origin: "X Ads", Class: ClassClick},
	{Param: "__twitter_impression", Origin: "X", Class: ClassSession},
	// `s` and `t` are the report's own example of what must never be global:
	// `t` is a share token on x.com and a video timestamp on YouTube, where it
	// is in the deny set below.
	{Param: "s", Hosts: []string{"x.com", "twitter.com"}, Origin: "X share sheet", Class: ClassSession, Note: "Names the surface the link was shared from (s=20, s=46)."},
	{Param: "t", Hosts: []string{"x.com", "twitter.com"}, Origin: "X share sheet", Class: ClassSession, Note: "Opaque share token. On YouTube the same name is a timestamp and is never stripped."},
	{Param: "ref_src", Hosts: []string{"x.com", "twitter.com"}, Origin: "X embeds", Class: ClassSession},
	{Param: "ref_url", Hosts: []string{"x.com", "twitter.com"}, Origin: "X embeds", Class: ClassSession, Note: "Carries the referring page's own URL."},
	{Param: "yclid", Origin: "Yandex.Direct", Class: ClassClick},
	{Param: "_openstat", Origin: "Openstat", Class: ClassSession, Note: "Base64 of four campaign fields."},

	// --- Email and marketing automation (report §1.4) ---
	{Param: "mc_cid", Origin: "Mailchimp", Class: ClassSession, Note: "The Mailchimp ID for the campaign that generated the link.", Doc: "https://mailchimp.com/developer/marketing/docs/e-commerce/"},
	{Param: "mc_eid", Origin: "Mailchimp", Class: ClassPerson, Note: "The recipient's unique email ID: this names the person who was mailed.", Doc: "https://mailchimp.com/developer/marketing/docs/e-commerce/"},
	{Param: "mc_tc", Origin: "Mailchimp", Class: ClassSession},
	{Param: "__hstc", Origin: "HubSpot", Class: ClassPerson, Note: "HubSpot's main visitor cookie, carrying hubspotutk.", Doc: "https://knowledge.hubspot.com/reports/what-cookies-does-hubspot-set-in-a-visitor-s-browser"},
	{Param: "__hssc", Origin: "HubSpot", Class: ClassSession, Doc: "https://knowledge.hubspot.com/reports/what-cookies-does-hubspot-set-in-a-visitor-s-browser"},
	{Param: "__hsfp", Origin: "HubSpot", Class: ClassPerson, Note: "Device fingerprint."},
	{Param: "_hsenc", Origin: "HubSpot email", Class: ClassPerson, Note: "Encoded recipient token."},
	{Param: "_hsmi", Origin: "HubSpot email", Class: ClassSession, Note: "Message ID."},
	{Param: "hsctatracking", Origin: "HubSpot CTA", Class: ClassSession, Note: "CTA GUID pair."},
	{Param: "mkt_tok", Origin: "Marketo", Class: ClassPerson, Note: "Base64 blob carrying the lead ID and the send ID."},
	{Param: "_kx", Origin: "Klaviyo", Class: ClassPerson, Note: "Klaviyo's own docs: an encrypted value decrypted by their web tracking to identify the user who clicked.", Doc: "https://help.klaviyo.com/hc/en-us/articles/360034666712"},
	{Param: "s_cid", Origin: "Adobe Campaign", Class: ClassSession},
	{Param: "s_kwcid", Origin: "Adobe Advertising", Class: ClassClick, Note: "Keyword ID."},
	{Param: "ef_id", Origin: "Adobe Advertising Cloud", Class: ClassClick},
	{Param: "vero_conv", Origin: "Vero", Class: ClassSession},
	{Param: "vero_id", Origin: "Vero", Class: ClassPerson},
	{Param: "bsft_", Prefix: true, Origin: "Blueshift", Class: ClassPerson, Note: "Blueshift's email click family."},
	// Braze has no entry, and that is the finding (report §1.4): its click
	// tracking rewrites the link's HOST (ablink.<brand>.com/ls/click?upn=…)
	// rather than appending a parameter. There is nothing here to delete, so it
	// belongs to the wrapper table below, not to this one.

	// --- Open analytics families (report §1.5) ---
	// Matomo documents that a Matomo site consumes all three of its prefixes
	// plus utm_, so all of them must be here or the feature looks arbitrary.
	{Param: "utm_", Prefix: true, Origin: "Google Analytics, and by now everyone", Class: ClassSession, Note: "The campaign family: source, medium, campaign, term, content, id, source_platform, creative_format, marketing_tactic.", Doc: "https://matomo.org/faq/reports/how-to-build-campaign-tracking-urls/"},
	{Param: "mtm_", Prefix: true, Origin: "Matomo 4+", Class: ClassSession, Note: "Matomo's eight documented campaign parameters.", Doc: "https://matomo.org/faq/how-to/faq_120/"},
	{Param: "pk_", Prefix: true, Origin: "Piwik / Matomo 3", Class: ClassSession, Note: "Kept working for backwards compatibility.", Doc: "https://matomo.org/faq/how-to/faq_120/"},
	{Param: "piwik_", Prefix: true, Origin: "Piwik", Class: ClassSession},
	{Param: "matomo_", Prefix: true, Origin: "Matomo", Class: ClassSession},

	// --- Site-scoped (report §1.6) ---
	// Global, not host-scoped, and deliberately so: Instagram appends these to
	// links shared OUT of the app, so they land on third-party hosts and almost
	// never on instagram.com itself. Scoping them to instagram.com would mean
	// they never fire on the URLs people actually paste. Safe globally because
	// the names are Instagram inventions that collide with nothing.
	{Param: "igshid", Origin: "Instagram", Class: ClassSession, Note: "Share ID, added to links shared out of the app."},
	{Param: "igsh", Origin: "Instagram", Class: ClassSession, Note: "Share ID, newer form."},
	{Param: "si", Hosts: []string{"youtube.com", "youtu.be"}, Origin: "YouTube", Class: ClassSession, Note: "Share-attribution token. Not stripped on Spotify: there it is reported to gate access on playlist invites."},
	{Param: "feature", Hosts: []string{"youtube.com", "youtu.be"}, Origin: "YouTube", Class: ClassSession},
	{Param: "kw", Hosts: []string{"youtube.com"}, Origin: "YouTube", Class: ClassSession},
	{Param: "pp", Hosts: []string{"youtube.com", "youtu.be"}, Origin: "YouTube", Class: ClassSession},
	{Param: "ref", Hosts: []string{"amazon."}, Origin: "Amazon", Class: ClassSession, Note: "Placement breadcrumb. Scoped to Amazon: on a git forge the same name picks a branch."},
	{Param: "ref_", Prefix: true, Hosts: []string{"amazon."}, Origin: "Amazon", Class: ClassSession},
	{Param: "pd_rd_", Prefix: true, Hosts: []string{"amazon."}, Origin: "Amazon", Class: ClassSession, Note: "Recommendation slot."},
	{Param: "pf_rd_", Prefix: true, Hosts: []string{"amazon."}, Origin: "Amazon", Class: ClassSession, Note: "Recommendation slot."},
	{Param: "qid", Hosts: []string{"amazon."}, Origin: "Amazon", Class: ClassSession, Note: "Search-result context."},
	{Param: "crid", Hosts: []string{"amazon."}, Origin: "Amazon", Class: ClassSession, Note: "Search-result context."},
	{Param: "sprefix", Hosts: []string{"amazon."}, Origin: "Amazon", Class: ClassSession, Note: "What was typed before the search ran."},
	{Param: "tag", Hosts: []string{"amazon."}, Origin: "Amazon Associates", Class: ClassAffiliate, Note: "The Associates tag. Deleting it takes the commission from whoever wrote the review you followed."},
	{Param: "linkcode", Hosts: []string{"amazon."}, Origin: "Amazon Associates", Class: ClassAffiliate},
	{Param: "ascsubtag", Hosts: []string{"amazon."}, Origin: "Amazon Associates", Class: ClassAffiliate, Note: "Publisher's own sub-tag; often identifies the article."},
	{Param: "creativeasin", Hosts: []string{"amazon."}, Origin: "Amazon Associates", Class: ClassAffiliate},
	{Param: "trk", Hosts: []string{"linkedin.com"}, Origin: "LinkedIn", Class: ClassSession, Note: "Traffic-source code."},
	{Param: "trkinfo", Hosts: []string{"linkedin.com"}, Origin: "LinkedIn", Class: ClassSession},
	{Param: "trackingid", Hosts: []string{"linkedin.com"}, Origin: "LinkedIn", Class: ClassSession},
	{Param: "lipi", Hosts: []string{"linkedin.com"}, Origin: "LinkedIn", Class: ClassPerson, Note: "Page-instance ID, joinable to the viewing member."},
	{Param: "licu", Hosts: []string{"linkedin.com"}, Origin: "LinkedIn", Class: ClassPerson},
	{Param: "li_fat_id", Hosts: []string{"linkedin.com"}, Origin: "LinkedIn Ads", Class: ClassClick},
	{Param: "share_id", Hosts: []string{"reddit.com"}, Origin: "Reddit", Class: ClassSession},
	{Param: "ref_campaign", Hosts: []string{"reddit.com"}, Origin: "Reddit", Class: ClassSession},
	{Param: "ref_source", Hosts: []string{"reddit.com"}, Origin: "Reddit", Class: ClassSession},
	{Param: "rdt", Hosts: []string{"reddit.com"}, Origin: "Reddit", Class: ClassSession},
	{Param: "_branch_match_id", Hosts: []string{"reddit.com"}, Origin: "Branch (via Reddit)", Class: ClassSession, Note: "Deep-link match ID."},
	{Param: "spm", Hosts: []string{"aliexpress.", "taobao.com", "tmall.com", "lazada."}, Origin: "Alibaba", Class: ClassSession, Note: "Placement path through the site."},
	{Param: "algo_pvid", Hosts: []string{"aliexpress."}, Origin: "AliExpress", Class: ClassSession, Note: "Experiment arm."},
	{Param: "ws_ab_test", Hosts: []string{"aliexpress."}, Origin: "AliExpress", Class: ClassSession, Note: "Experiment arm."},
	{Param: "r", Hosts: []string{"substack.com"}, Origin: "Substack", Class: ClassPerson, Note: "The referring subscriber. Custom Substack domains are unreachable from the name alone, so this only fires on substack.com."},
	{Param: "triedredirect", Hosts: []string{"substack.com"}, Origin: "Substack", Class: ClassSession},
	{Param: "showwelcomeonshare", Hosts: []string{"substack.com"}, Origin: "Substack", Class: ClassSession},
}

// ---------------------------------------------------------------------------
// Never strip — report §2. Checked before any rule fires.
//
// A prefix rule is one careless entry away from eating any of these, and the
// failure modes are not cosmetic: a dead password-reset link, a 403 from a
// presigned URL, an unsubscribe that silently does nothing. Several entries are
// host-scoped for the same reason the tracking table is two-tier — `t` is a
// timestamp on YouTube and a share token on x.com, and both facts are true.
// ---------------------------------------------------------------------------

var denyList = []Deny{
	{Param: "q", Why: "The search is gone. On google.com/url?q= it is the destination itself, so deleting it turns an unwrap into a dead link."},
	{Param: "id", Why: "Wrong record, or a 404. Every CMS and REST route in existence uses this name."},
	{Param: "uid", Why: "Wrong record, or a 404."},
	{Param: "pid", Why: "Wrong record, or a 404."},
	{Param: "item", Why: "Wrong record, or a 404."},
	{Param: "sku", Why: "Wrong product."},
	{Param: "page", Why: "Silently resets to page 1; the reader assumes the link was wrong."},
	{Param: "p", Why: "Pagination on countless sites, and a catch-all elsewhere. Too broad to guess at."},
	{Param: "offset", Why: "Pagination resets."},
	{Param: "limit", Why: "Page size resets; a deep link into a long list stops working."},
	{Param: "cursor", Why: "Cursor pagination restarts from the beginning."},
	{Param: "after", Why: "Cursor pagination restarts from the beginning."},
	{Param: "token", Why: "The link is dead. Password resets, magic links and email confirmations are usually single-use, so retrying does not recover it."},
	{Param: "code", Why: "OAuth 2.0 authorization response (RFC 6749 §4.1.2). The token exchange never happens and login loops back to the start."},
	{Param: "state", Why: "OAuth 2.0 CSRF binding (RFC 6749 §10.12). The client cannot bind the callback to its request and fails closed, with an incomprehensible error."},
	{Param: "redirect_uri", Why: "OAuth 2.0 authorization request (RFC 6749 §3.1.2). invalid_request, or a silent fall-back to a registered default that is not where the user was going."},
	{Param: "nonce", Why: "OpenID Connect ID-token validation fails."},
	{Param: "session", Why: "Logged out."},
	{Param: "sid", Why: "Logged out. One letter from Shopify's _sid, and the opposite verdict."},
	{Param: "sessionid", Why: "Logged out."},
	{Param: "jsessionid", Why: "Logged out."},
	{Param: "phpsessid", Why: "Logged out."},
	{Param: "s_id", Why: "Logged out."},
	{Param: "sig", Why: "Signature mismatch, 403. Also an Azure SAS field."},
	{Param: "signature", Why: "Signature mismatch, 403."},
	{Param: "hmac", Why: "Signature mismatch, 403."},
	{Param: "mac", Why: "Signature mismatch, 403."},
	// S3 SigV4 presigned URLs. The canonical query string covers EVERY parameter
	// except X-Amz-Signature, so removing any parameter at all invalidates one —
	// which is why looksSigned() in clean.go refuses to remove anything from a
	// URL carrying these, not just these.
	{Param: "x-amz-", Prefix: true, Why: "403 SignatureDoesNotMatch on an S3 presigned URL.", Hosts: nil},
	{Param: "x-goog-", Prefix: true, Why: "403 on a Google Cloud Storage signed URL."},
	{Param: "awsaccesskeyid", Why: "403 on an S3 SigV2 presigned URL."},
	{Param: "expires", Why: "403 on a SigV2 presigned URL, and a cache directive elsewhere."},
	{Param: "key-pair-id", Why: "403 on a CloudFront signed URL."},
	{Param: "policy", Why: "403 on a CloudFront signed URL."},
	// Azure SAS. Scoped, because `sv`/`se`/`sp`/`st` are two-letter names that
	// would shadow real rules everywhere else; a SAS on a custom domain is
	// caught by looksSigned() instead.
	{Param: "sv", Hosts: []string{"core.windows.net"}, Why: "403 on an Azure Blob SAS URL."},
	{Param: "se", Hosts: []string{"core.windows.net"}, Why: "403 on an Azure Blob SAS URL."},
	{Param: "sp", Hosts: []string{"core.windows.net"}, Why: "403 on an Azure Blob SAS URL. Note sp is also a Bing tracking parameter."},
	{Param: "st", Hosts: []string{"core.windows.net"}, Why: "403 on an Azure Blob SAS URL."},
	{Param: "sr", Hosts: []string{"core.windows.net"}, Why: "403 on an Azure Blob SAS URL."},
	{Param: "v", Hosts: []string{"youtube.com"}, Why: "?v= is the video ID. Strip it and the URL is the YouTube homepage."},
	{Param: "t", Hosts: []string{"youtube.com", "youtu.be"}, Why: "The timestamp: ?t=90 is a deep link into the middle of the video. The same name on x.com is a share token, and is stripped there."},
	{Param: "start", Hosts: []string{"youtube.com", "youtu.be"}, Why: "The timestamp for an embed."},
	{Param: "si", Hosts: []string{"spotify.com"}, Why: "Reported to gate access on collaborative and private playlist invites: the recipient gets a permission error instead of the playlist. Believed, not confirmed — verify before ever making si global."},
	{Param: "u", Hosts: []string{"list-manage.com"}, Why: "The unsubscribe silently does nothing. An anti-tracking tool that breaks the opt-out link is the worst outcome this feature has."},
	{Param: "e", Hosts: []string{"list-manage.com"}, Why: "The unsubscribe silently does nothing."},
	{Param: "c", Hosts: []string{"list-manage.com"}, Why: "The unsubscribe silently does nothing."},
	{Param: "hash", Hosts: []string{"list-manage.com"}, Why: "The unsubscribe silently does nothing."},
	{Param: "ref", Hosts: []string{"github.com", "gitlab.com", "codeberg.org", "bitbucket.org", "gitea.com", "git.sr.ht"}, Why: "?ref=main picks a branch. Wrong branch, or a 404. ClearURLs carries three separate exceptions for this exact case."},
	{Param: "format", Why: "Wrong content type."},
	{Param: "output", Why: "Wrong content type."},
	{Param: "callback", Why: "A JSONP call that never invokes its callback."},
	{Param: "jsonp", Why: "A JSONP call that never invokes its callback."},
	{Param: "alt", Why: "Wrong response format on Google APIs."},
	{Param: "lang", Why: "Wrong language."},
	{Param: "hl", Why: "Wrong language."},
	{Param: "locale", Why: "Wrong language."},
	{Param: "gl", Why: "Wrong region. One underscore from _gl, which is stripped."},
	{Param: "cid", Why: "Adobe's conventional campaign slot, and also customer ID, conversation ID and channel ID on countless apps. The ambiguous case that most looks safe and is not."},
	{Param: "icid", Why: "Same ambiguity as cid."},
	{Param: "int_cid", Why: "Same ambiguity as cid."},
	{Param: "variant", Why: "Wrong Shopify product variant, wrong price."},
	{Param: "share", Why: "Changes content disposition on some hosts."},
	{Param: "dl", Why: "Renders instead of downloading."},
	{Param: "download", Why: "Renders instead of downloading."},
	{Param: "raw", Why: "Renders instead of serving the file."},
}

// ---------------------------------------------------------------------------
// Wrappers — docs/reports/wrapper-formats.md. Waves 1 to 4 of its ship order.
//
// Wave 5 is "never": t.co, lnkd.in and bit.ly store the mapping server-side and
// the path is an opaque database key. No amount of string work recovers those,
// so they are NOT in this table — they are A6 Trace's job, and the report's
// §2 argues that naming the boundary honestly is most of A16's value.
// ---------------------------------------------------------------------------

// Shape says where the target hides. Four shapes cover every wrapper here.
type Shape uint8

const (
	ShapeParam     Shape = iota // "?url=" — the common case
	ShapeBareQuery              // href.li, DeviantArt: RawQuery *is* the target
	ShapePathTail               // Cisco: everything after the token segment
	ShapeCustom                 // urldefense, AMP — needs code
)

func (s Shape) String() string {
	switch s {
	case ShapeParam:
		return "param"
	case ShapeBareQuery:
		return "bare-query"
	case ShapePathTail:
		return "path-tail"
	case ShapeCustom:
		return "custom"
	}
	return "unknown"
}

func (s Shape) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Decoder is how the captured string becomes a URL.
type Decoder uint8

const (
	DecodeNone        Decoder = iota // already a URL
	DecodePercent                    // QueryUnescape, once, then the ladder check
	DecodePathPercent                // PathUnescape: '+' is a plus in a path, not a space
	DecodeURLDefenseV1
	DecodeURLDefenseV2
	DecodeURLDefenseV3
	DecodeAMPPath
)

// Wrapper is one entry. Hosts are lowercased; see matchHost for the forms.
//
// Params is a SLICE, which is what lets Google (q or url) and Steam (url or u)
// be one row rather than two — and what this table will need again the next time
// a vendor renames a parameter without telling anyone.
type Wrapper struct {
	Name    string   `json:"name"`              // "Microsoft Safe Links" — shown verbatim in the note
	Hosts   []string `json:"hosts"`             //
	Path    string   `json:"path,omitempty"`    // "" = any; matched as a prefix
	Shape   Shape    `json:"shape"`             //
	Params  []string `json:"params,omitempty"`  // ShapeParam: first one present wins
	Decode  Decoder  `json:"-"`                 // implementation detail; a client cannot act on it
	Partial bool     `json:"partial,omitempty"` // Mimecast: yields a host, not a URL
	Conf    string   `json:"confidence"`        // the report's own column: high or medium
	Doc     string   `json:"doc,omitempty"`
}

var wrappers = []Wrapper{
	// --- Wave 1: the reason A16 exists. Anyone on Microsoft 365 or Proofpoint
	// meets these on every link of every day. ---
	{
		Name:  "Microsoft Safe Links",
		Hosts: []string{"*.safelinks.protection.outlook.com", "*.safelinks.protection.office365.us", "*.safelinks.protection.outlook.cn"},
		Shape: ShapeParam, Params: []string{"url"}, Decode: DecodePercent, Conf: "high",
		Doc: "https://learn.microsoft.com/en-us/defender-office-365/safe-links-about",
	},
	// data, sdata and reserved are dropped without interpretation. Microsoft has
	// never documented them and the question sat unanswered on their own forum,
	// so nothing here tries to surface a "sender" from data.
	{
		Name:  "Proofpoint urldefense v1",
		Hosts: []string{"urldefense.proofpoint.com", "urldefense.com"},
		Path:  "/v1/url",
		Shape: ShapeCustom, Decode: DecodeURLDefenseV1, Conf: "high",
	},
	{
		Name:  "Proofpoint urldefense v2",
		Hosts: []string{"urldefense.proofpoint.com", "urldefense.com"},
		Path:  "/v2/url",
		Shape: ShapeCustom, Decode: DecodeURLDefenseV2, Conf: "high",
	},
	{
		Name:  "Proofpoint urldefense v3",
		Hosts: []string{"urldefense.com", "urldefense.proofpoint.com"},
		Path:  "/v3/",
		Shape: ShapeCustom, Decode: DecodeURLDefenseV3, Conf: "high",
	},

	// --- Wave 2: highest volume outside mail. ---
	// The report cites `*.google.<tld>`, which is why the host pattern is the
	// registrable form "google." rather than a list of every ccTLD.
	{
		Name:  "Google redirect",
		Hosts: []string{"google."}, Path: "/url",
		Shape: ShapeParam, Params: []string{"q", "url"}, Decode: DecodePercent, Conf: "high",
	},
	{
		Name:  "Google AMP viewer",
		Hosts: []string{"google."}, Path: "/amp/",
		Shape: ShapeCustom, Decode: DecodeAMPPath, Conf: "medium",
	},
	{
		Name:  "Google Ads redirect",
		Hosts: []string{"google.", "googleadservices.com"},
		Shape: ShapeParam, Params: []string{"adurl"}, Decode: DecodePercent, Conf: "medium",
	},
	{
		Name:  "Meta link shim",
		Hosts: []string{"l.facebook.com", "lm.facebook.com", "l.messenger.com"},
		Shape: ShapeParam, Params: []string{"u"}, Decode: DecodePercent, Conf: "high",
		Doc: "https://engineering.fb.com/2012/09/14/security/a-faster-better-link-shim/",
	},
	{
		Name:  "Instagram link shim",
		Hosts: []string{"l.instagram.com"},
		Shape: ShapeParam, Params: []string{"u"}, Decode: DecodePercent, Conf: "medium",
	},
	{
		Name:  "YouTube redirect",
		Hosts: []string{"youtube.com"}, Path: "/redirect",
		Shape: ShapeParam, Params: []string{"q"}, Decode: DecodePercent, Conf: "high",
	},

	// --- Wave 3: same population as wave 1, different vendors. Cisco is the
	// row that proves ShapePathTail. ---
	{
		Name:  "Cisco Secure Email",
		Hosts: []string{"secure-web.cisco.com"},
		Shape: ShapePathTail, Decode: DecodePathPercent, Conf: "high",
	},
	{
		Name:  "Barracuda Link Protect",
		Hosts: []string{"linkprotect.cudasvc.com"}, Path: "/url",
		Shape: ShapeParam, Params: []string{"a"}, Decode: DecodePercent, Conf: "high",
	},
	// Mimecast is the honest half-answer: /s/<token> is opaque, and ?domain=
	// names the destination DOMAIN only, and only when the admin enabled
	// "Display URL Destination Domain". Partial results must look partial, so
	// Unwrap declines this one and Clean reports it as a note instead.
	{
		Name:  "Mimecast URL Protect",
		Hosts: []string{"mimecast.com"}, Path: "/s/",
		Shape: ShapeParam, Params: []string{"domain"}, Decode: DecodeNone, Partial: true, Conf: "medium",
		Doc: "https://mimecastsupport.zendesk.com/hc/en-us/articles/34000769379219-Targeted-Threat-Protection-URL-Protect-Embedded-Links",
	},

	// --- Wave 4: the long tail. One row each, near-zero cost. ---
	{
		Name:  "Tumblr redirect",
		Hosts: []string{"t.umblr.com"}, Path: "/redirect",
		Shape: ShapeParam, Params: []string{"z"}, Decode: DecodePercent, Conf: "high",
	},
	{
		Name:  "Reddit outbound",
		Hosts: []string{"out.reddit.com", "click.redditmail.com"},
		Shape: ShapeParam, Params: []string{"url"}, Decode: DecodePercent, Conf: "high",
	},
	// Steam moved: ?u= is reported in community posts from Aug-Sep 2025 while
	// ClearURLs still carries ?url=. Both ship, ?url= first.
	{
		Name:  "Steam link filter",
		Hosts: []string{"steamcommunity.com"}, Path: "/linkfilter",
		Shape: ShapeParam, Params: []string{"url", "u"}, Decode: DecodePercent, Conf: "medium",
	},
	{
		Name:  "VK away",
		Hosts: []string{"vk.com"}, Path: "/away.php",
		Shape: ShapeParam, Params: []string{"to"}, Decode: DecodePercent, Conf: "high",
	},
	{
		Name:  "LinkedIn interstitial",
		Hosts: []string{"linkedin.com"}, Path: "/redir/redirect",
		Shape: ShapeParam, Params: []string{"url"}, Decode: DecodePercent, Conf: "medium",
	},
	{
		Name:  "Slack redirect",
		Hosts: []string{"slack-redir.net"}, Path: "/link",
		Shape: ShapeParam, Params: []string{"url"}, Decode: DecodePercent, Conf: "medium",
	},
	// The bare-query pair: the target is the raw query string with no parameter
	// name at all, so it must never be run through a pair parser.
	{
		Name:  "href.li",
		Hosts: []string{"href.li"},
		Shape: ShapeBareQuery, Decode: DecodeNone, Conf: "high",
	},
	{
		Name:  "DeviantArt outgoing",
		Hosts: []string{"deviantart.com"}, Path: "/users/outgoing",
		Shape: ShapeBareQuery, Decode: DecodeNone, Conf: "high",
	},
}

// ---------------------------------------------------------------------------
// Lookups. Everything above is data; everything below is the three small
// functions that read it.
// ---------------------------------------------------------------------------

// Indexes, built once at package init. Go resolves package-level var order by
// dependency, so the tables above are populated before these run. Exact-name
// lookup has to be O(1): Parse calls it once per parameter on every request.
var (
	trackingByName   = indexRules(trackingRules)
	trackingPrefixes = prefixRules(trackingRules)
	denyByName       = indexDeny(denyList)
	denyPrefixes     = prefixDeny(denyList)
)

func indexRules(rs []Rule) map[string][]Rule {
	m := make(map[string][]Rule, len(rs))
	for _, r := range rs {
		if !r.Prefix {
			m[r.Param] = append(m[r.Param], r)
		}
	}
	return m
}

func prefixRules(rs []Rule) []Rule {
	var out []Rule
	for _, r := range rs {
		if r.Prefix {
			out = append(out, r)
		}
	}
	return out
}

func indexDeny(ds []Deny) map[string][]Deny {
	m := make(map[string][]Deny, len(ds))
	for _, d := range ds {
		if !d.Prefix {
			m[d.Param] = append(m[d.Param], d)
		}
	}
	return m
}

func prefixDeny(ds []Deny) []Deny {
	var out []Deny
	for _, d := range ds {
		if d.Prefix {
			out = append(out, d)
		}
	}
	return out
}

// denyReason reports why key must never be stripped on host, if it must not.
// Consulted before any rule, prefix rules included.
func denyReason(key, host string) (string, bool) {
	k := strings.ToLower(key)
	for _, d := range denyByName[k] {
		if d.covers(host) {
			return d.Why, true
		}
	}
	for _, d := range denyPrefixes {
		if strings.HasPrefix(k, d.Param) && d.covers(host) {
			return d.Why, true
		}
	}
	return "", false
}

func (d Deny) covers(host string) bool {
	if len(d.Hosts) == 0 {
		return true
	}
	for _, h := range d.Hosts {
		if matchHost(host, h) {
			return true
		}
	}
	return false
}

// lookupTracking finds the rule that would strip key on host, if any. Exact
// names win over prefixes, which is why the prefix scan runs second.
func lookupTracking(key, host string, affiliate bool) (Rule, bool) {
	k := strings.ToLower(key)
	if _, denied := denyReason(k, host); denied {
		return Rule{}, false
	}
	for _, r := range trackingByName[k] {
		if r.applies(host, affiliate) {
			return r, true
		}
	}
	for _, r := range trackingPrefixes {
		if strings.HasPrefix(k, r.Param) && r.applies(host, affiliate) {
			return r, true
		}
	}
	return Rule{}, false
}

// wrappersFor returns every wrapper covering host+path, in table order. Path is
// matched as a prefix because urldefense v3 carries the payload in the rest of
// the path.
//
// It returns a slice rather than the first hit because one host legitimately
// carries several shapes: google.<tld> is /url, /amp/ and a bare ?adurl= all at
// once, and the ?adurl= row has no path to discriminate on. Returning only the
// first match let it shadow the other two. The caller tries each until one
// actually yields a target.
func wrappersFor(host, path string) []Wrapper {
	path = strings.ToLower(path)
	var out []Wrapper
	for _, w := range wrappers {
		if w.Path != "" && !strings.HasPrefix(path, strings.ToLower(w.Path)) {
			continue
		}
		for _, h := range w.Hosts {
			if matchHost(host, h) {
				out = append(out, w)
				break
			}
		}
	}
	return out
}

// matchHost reports whether host is covered by pattern. Three forms:
//
//	"linkedin.com"     the host itself, or any subdomain of it
//	"*.safelinks.…"    identical; the "*." is documentation, not extra power
//	"amazon."          registrable-name match: the label "amazon" followed by a
//	                   public suffix, so amazon.co.uk and smile.amazon.com match
//	                   and notamazon.com and amazon.evil.com do not
//
// The trailing-dot form is report §7 invariant 5. It exists because the
// alternative — listing every Google and Amazon ccTLD — is a list that is wrong
// the week after it is written.
func matchHost(host, pattern string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || pattern == "" {
		return false
	}
	pattern = strings.TrimPrefix(strings.ToLower(pattern), "*.")
	if strings.HasSuffix(pattern, ".") {
		return matchRegistrable(host, strings.TrimSuffix(pattern, "."))
	}
	return host == pattern || strings.HasSuffix(host, "."+pattern)
}

// secondLevelSuffixes: the handful of two-label public suffixes the
// trailing-dot form needs. Shipping the full Public Suffix List for this would
// be a dependency and a megabyte; being wrong about amazon.co.uk would not be
// acceptable, and being wrong about amazon.commercial-bank.zz costs one
// unstripped parameter.
var secondLevelSuffixes = map[string]bool{
	"co": true, "com": true, "net": true, "org": true, "ac": true, "gov": true, "edu": true,
}

func matchRegistrable(host, name string) bool {
	labels := strings.Split(host, ".")
	for i, l := range labels {
		if l != name {
			continue
		}
		switch len(labels) - i - 1 {
		case 1:
			return alphaLabel(labels[i+1])
		case 2:
			return secondLevelSuffixes[labels[i+1]] && alphaLabel(labels[i+2])
		}
	}
	return false
}

// alphaLabel reports whether s could be a TLD: letters only, and short. This is
// what stops "amazon.evil.com" matching the pattern "amazon.".
func alphaLabel(s string) bool {
	if len(s) < 2 || len(s) > 24 {
		return false
	}
	for _, r := range s {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

// RuleCatalog is what GET /clean/rules serves: the whole of both tables, plus
// the version the extension caches on and the scope sentence the page must
// print. Nothing is computed here — it is the tables, verbatim.
type RuleCatalog struct {
	Version    string    `json:"version"`
	Scope      string    `json:"scope"`
	Tracking   []Rule    `json:"tracking"`
	NeverStrip []Deny    `json:"never_strip"`
	Wrappers   []Wrapper `json:"wrappers"`
}

// Rules returns the catalog. The slices are cloned so a handler, a template or
// the JSON encoder cannot reorder the package's own tables; the string fields
// inside are immutable, and the Hosts slices are shared, which is the one thing
// a caller must not write to.
func Rules() RuleCatalog {
	return RuleCatalog{
		Version:    RulesVersion,
		Scope:      catalogScope,
		Tracking:   slices.Clone(trackingRules),
		NeverStrip: slices.Clone(denyList),
		Wrappers:   slices.Clone(wrappers),
	}
}
