package linktools

import (
	"slices"
	"strings"
)

// Hand-written, not ClearURLs' catalog: that is LGPL-3.0, misses gbraid/wbraid/gclsrc/ttclid, and rewrites
// hosts and paths (report §7). Matching is exact or literal prefix, never regex, so each rule is reviewable.

// RulesVersion is bumped by hand on any table change; the extension caches the catalog keyed on it.
const RulesVersion = "2026-10-04"

// catalogScope is the scope statement the rules page shows verbatim, shipped as data so page and API agree.
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

// MarshalText makes the JSON say "person", not 2.
func (c Class) MarshalText() ([]byte, error) { return []byte(c.String()), nil }

// why explains every removal, so Removal.Why is never empty.
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

// Rule is one tracking-table entry; ambiguous names (ref) ship host-scoped or not at all (report §3).
type Rule struct {
	Param  string   `json:"param"`            // exact parameter name, lowercase; or the prefix when Prefix
	Prefix bool     `json:"prefix,omitempty"` // match Param as a prefix: "utm_", "mtm_", "pd_rd_"
	Hosts  []string `json:"hosts,omitempty"`  // nil = global; otherwise see matchHost
	Origin string   `json:"origin"`           // "Google Ads", "Mailchimp" — shown in the UI verbatim
	Class  Class    `json:"class"`
	Note   string   `json:"note,omitempty"` // one line, shown when this rule fires
	Doc    string   `json:"doc,omitempty"`  // vendor doc URL, or "" when the entry is only believed
}

// applies reports whether this rule may fire for host; affiliate rules only when asked (report §3.3).
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

// name is printed beside every deletion and lands in Param.Tracking for Inspect.
func (r Rule) name() string {
	if r.Prefix {
		return r.Param + "* · " + r.Origin
	}
	return r.Param + " · " + r.Origin
}

// Deny is a never-strip entry, consulted before any rule (prefixes too); Why is printed on the rules page.
type Deny struct {
	Param  string   `json:"param"`
	Prefix bool     `json:"prefix,omitempty"`
	Hosts  []string `json:"hosts,omitempty"` // nil = never strip this anywhere
	Why    string   `json:"why"`
}

// Tracking table (report §1). Deliberately omitted: amazon th/psc (variant selectors), substack
// publication_id/post_id (record IDs), Shopify's _pos/_ss/_psq/pr_* (custom domains need a fetch),
// and si on Spotify (reported to gate playlist invites).

var trackingRules = []Rule{
	// --- Google Ads and Analytics (report §1.1) ---
	{Param: "gclid", Origin: "Google Ads", Class: ClassClick, Note: "Auto-tagged onto every ad click.", Doc: "https://support.google.com/google-ads/answer/6305348"},
	{Param: "gclsrc", Origin: "Google Ads", Class: ClassClick, Note: "Names the click source (aw.ds, 3p.ds)."},
	{Param: "gbraid", Origin: "Google Ads", Class: ClassClick, Note: "iOS web-to-app click cohort, added after Apple's tracking prompt (ATT).", Doc: "https://support.google.com/google-ads/answer/16297842"},
	{Param: "wbraid", Origin: "Google Ads", Class: ClassClick, Note: "iOS app-to-web click cohort.", Doc: "https://support.google.com/google-ads/answer/10417364"},
	{Param: "dclid", Origin: "Campaign Manager 360", Class: ClassClick, Note: "Display click ID."},
	{Param: "srsltid", Origin: "Google Merchant Center", Class: ClassClick, Note: "Attached to free product listings in search."},
	{Param: "gad_source", Origin: "Google Ads", Class: ClassClick, Note: "Click surface, added 2023."},
	{Param: "gad_campaignid", Origin: "Google Ads", Class: ClassSession, Note: "Campaign ID, added 2024."},
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
	{Param: "ttclid", Origin: "TikTok Ads", Class: ClassClick, Note: "TikTok tells advertisers to store it 28 days or more and replay it to the Events API.", Doc: "https://ads.tiktok.com/help/article/tiktok-click-id"},
	{Param: "tt_medium", Origin: "TikTok", Class: ClassSession},
	{Param: "tt_content", Origin: "TikTok", Class: ClassSession},
	{Param: "share_app_name", Hosts: []string{"tiktok.com"}, Origin: "TikTok", Class: ClassSession},
	{Param: "share_iid", Hosts: []string{"tiktok.com"}, Origin: "TikTok", Class: ClassSession},
	{Param: "u_code", Hosts: []string{"tiktok.com"}, Origin: "TikTok", Class: ClassSession},
	{Param: "twclid", Origin: "X Ads", Class: ClassClick},
	{Param: "__twitter_impression", Origin: "X", Class: ClassSession},
	// `t` is a share token on x.com but a timestamp on YouTube (deny set), so neither s nor t can be global.
	{Param: "s", Hosts: []string{"x.com", "twitter.com"}, Origin: "X share sheet", Class: ClassSession, Note: "Names the surface the link was shared from (s=20, s=46)."},
	{Param: "t", Hosts: []string{"x.com", "twitter.com"}, Origin: "X share sheet", Class: ClassSession, Note: "Opaque share token. On YouTube the same name is a timestamp and is never removed."},
	{Param: "ref_src", Hosts: []string{"x.com", "twitter.com"}, Origin: "X embeds", Class: ClassSession},
	{Param: "ref_url", Hosts: []string{"x.com", "twitter.com"}, Origin: "X embeds", Class: ClassSession, Note: "Carries the referring page's own URL."},
	{Param: "yclid", Origin: "Yandex.Direct", Class: ClassClick},
	{Param: "_openstat", Origin: "Openstat", Class: ClassSession, Note: "Base64 of four campaign fields."},

	// --- Email and marketing automation (report §1.4) ---
	{Param: "mc_cid", Origin: "Mailchimp", Class: ClassSession, Note: "The Mailchimp ID for the campaign that generated the link.", Doc: "https://mailchimp.com/developer/marketing/docs/e-commerce/"},
	{Param: "mc_eid", Origin: "Mailchimp", Class: ClassPerson, Note: "Your subscriber ID in the sender's Mailchimp list.", Doc: "https://mailchimp.com/developer/marketing/docs/e-commerce/"},
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
	// No Braze entry: its tracking rewrites the host (ablink.<brand>.com) instead of adding a parameter.

	// --- Open analytics families (report §1.5) ---
	{Param: "utm_", Prefix: true, Origin: "Google Analytics, and by now everyone", Class: ClassSession, Note: "The campaign family: source, medium, campaign, term, content, id, source_platform, creative_format, marketing_tactic.", Doc: "https://matomo.org/faq/reports/how-to-build-campaign-tracking-urls/"},
	{Param: "mtm_", Prefix: true, Origin: "Matomo 4+", Class: ClassSession, Note: "Matomo's eight documented campaign parameters.", Doc: "https://matomo.org/faq/how-to/faq_120/"},
	{Param: "pk_", Prefix: true, Origin: "Piwik / Matomo 3", Class: ClassSession, Note: "Kept working for backwards compatibility.", Doc: "https://matomo.org/faq/how-to/faq_120/"},
	{Param: "piwik_", Prefix: true, Origin: "Piwik", Class: ClassSession},
	{Param: "matomo_", Prefix: true, Origin: "Matomo", Class: ClassSession},

	// --- Site-scoped (report §1.6) ---
	// Instagram's are global on purpose: they ride links shared out of the app, so they land on other hosts.
	{Param: "igshid", Origin: "Instagram", Class: ClassSession, Note: "Share ID, added to links shared out of the app."},
	{Param: "igsh", Origin: "Instagram", Class: ClassSession, Note: "Share ID, newer form."},
	{Param: "si", Hosts: []string{"youtube.com", "youtu.be"}, Origin: "YouTube", Class: ClassSession, Note: "Share-attribution token. Not removed on Spotify: there it is reported to gate access on playlist invites."},
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
	{Param: "tag", Hosts: []string{"amazon."}, Origin: "Amazon Associates", Class: ClassAffiliate, Note: "Removing it takes their commission."},
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

// Never strip (report §2), checked before any rule: failures here are dead reset links and 403s.

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
	{Param: "sid", Why: "Removing it logs you out."},
	{Param: "sessionid", Why: "Logged out."},
	{Param: "jsessionid", Why: "Logged out."},
	{Param: "phpsessid", Why: "Logged out."},
	{Param: "s_id", Why: "Logged out."},
	{Param: "sig", Why: "Signature mismatch, 403. Also an Azure SAS field."},
	{Param: "signature", Why: "Signature mismatch, 403."},
	{Param: "hmac", Why: "Signature mismatch, 403."},
	{Param: "mac", Why: "Signature mismatch, 403."},
	// S3 SigV4 signs every parameter but X-Amz-Signature, so looksSigned() refuses to remove anything at all.
	{Param: "x-amz-", Prefix: true, Why: "403 SignatureDoesNotMatch on an S3 presigned URL.", Hosts: nil},
	{Param: "x-goog-", Prefix: true, Why: "403 on a Google Cloud Storage signed URL."},
	{Param: "awsaccesskeyid", Why: "403 on an S3 SigV2 presigned URL."},
	{Param: "expires", Why: "403 on a SigV2 presigned URL, and a cache directive elsewhere."},
	{Param: "key-pair-id", Why: "403 on a CloudFront signed URL."},
	{Param: "policy", Why: "403 on a CloudFront signed URL."},
	// Azure SAS is host-scoped as two-letter names shadow real rules; looksSigned() catches custom domains.
	{Param: "sv", Hosts: []string{"core.windows.net"}, Why: "403 on an Azure Blob SAS URL."},
	{Param: "se", Hosts: []string{"core.windows.net"}, Why: "403 on an Azure Blob SAS URL."},
	{Param: "sp", Hosts: []string{"core.windows.net"}, Why: "403 on an Azure Blob SAS URL. Note sp is also a Bing tracking parameter."},
	{Param: "st", Hosts: []string{"core.windows.net"}, Why: "403 on an Azure Blob SAS URL."},
	{Param: "sr", Hosts: []string{"core.windows.net"}, Why: "403 on an Azure Blob SAS URL."},
	{Param: "v", Hosts: []string{"youtube.com"}, Why: "?v= is the video ID. Remove it and the URL is the YouTube homepage."},
	{Param: "t", Hosts: []string{"youtube.com", "youtu.be"}, Why: "The timestamp: ?t=90 is a deep link into the middle of the video. The same name on x.com is a share token, and is removed there."},
	{Param: "start", Hosts: []string{"youtube.com", "youtu.be"}, Why: "The timestamp for an embed."},
	{Param: "si", Hosts: []string{"spotify.com"}, Why: "Reported to gate access on collaborative and private playlist invites: the recipient gets a permission error instead of the playlist. Reported, not confirmed."},
	{Param: "u", Hosts: []string{"list-manage.com"}, Why: "The unsubscribe link silently stops working."},
	{Param: "e", Hosts: []string{"list-manage.com"}, Why: "The unsubscribe silently does nothing."},
	{Param: "c", Hosts: []string{"list-manage.com"}, Why: "The unsubscribe silently does nothing."},
	{Param: "hash", Hosts: []string{"list-manage.com"}, Why: "The unsubscribe silently does nothing."},
	{Param: "ref", Hosts: []string{"github.com", "gitlab.com", "codeberg.org", "bitbucket.org", "gitea.com", "git.sr.ht"}, Why: "?ref=main picks a branch: without it, the wrong branch, or a 404."},
	{Param: "format", Why: "Wrong content type."},
	{Param: "output", Why: "Wrong content type."},
	{Param: "callback", Why: "A JSONP call that never invokes its callback."},
	{Param: "jsonp", Why: "A JSONP call that never invokes its callback."},
	{Param: "alt", Why: "Wrong response format on Google APIs."},
	{Param: "lang", Why: "Wrong language."},
	{Param: "hl", Why: "Wrong language."},
	{Param: "locale", Why: "Wrong language."},
	{Param: "gl", Why: "Wrong region. One underscore from _gl, which is removed."},
	{Param: "cid", Why: "Adobe's conventional campaign slot, and also customer ID, conversation ID and channel ID on countless apps. The ambiguous case that most looks safe and is not."},
	{Param: "icid", Why: "Same ambiguity as cid."},
	{Param: "int_cid", Why: "Same ambiguity as cid."},
	{Param: "variant", Why: "Wrong Shopify product variant, wrong price."},
	{Param: "share", Why: "Changes content disposition on some hosts."},
	{Param: "dl", Why: "Renders instead of downloading."},
	{Param: "download", Why: "Renders instead of downloading."},
	{Param: "raw", Why: "Renders instead of serving the file."},
}

// Wrappers (wrapper report waves 1-4); t.co, lnkd.in and bit.ly map server-side, so they are Trace's job.

// Shape says where the target hides.
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

// Wrapper is one entry (hosts lowercase, forms in matchHost); Params is a slice so renames stay one row.
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
	// --- Wave 1: Microsoft 365 and Proofpoint users meet these on every link. ---
	{
		Name:  "Microsoft Safe Links",
		Hosts: []string{"*.safelinks.protection.outlook.com", "*.safelinks.protection.office365.us", "*.safelinks.protection.outlook.cn"},
		Shape: ShapeParam, Params: []string{"url"}, Decode: DecodePercent, Conf: "high",
		Doc: "https://learn.microsoft.com/en-us/defender-office-365/safe-links-about",
	},
	// data, sdata and reserved are dropped uninterpreted: Microsoft never documented them.
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

	// --- Wave 3: same population as wave 1, different vendors. ---
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
	// Mimecast's ?domain= names only the destination DOMAIN (when the admin enabled it), so it stays partial.
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
	// Steam moved from ?url= to ?u= (community reports, Aug-Sep 2025); both ship, ?url= first.
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
	// The bare-query pair: the target is the raw query with no name, so never run it through a pair parser.
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

// Lookups: everything below reads the tables above.

// Built at init after the tables (Go orders package vars by dependency); exact lookup is O(1) per parameter.
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

// denyReason reports why key must never be stripped on host; consulted before any rule.
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

// lookupTracking finds the rule that would strip key on host; exact names win over prefixes.
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

// wrappersFor returns every wrapper covering host+path (path as a prefix, for urldefense v3), not just the
// first: google.<tld> carries /url, /amp/ and a path-less ?adurl=, which would shadow the other two.
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

// matchHost: "linkedin.com" matches it and its subdomains ("*." prefix is documentation only); "amazon."
// matches the label plus a public suffix (amazon.co.uk, smile.amazon.com, not amazon.evil.com), since a
// list of every ccTLD is wrong the week after it is written.
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

// secondLevelSuffixes stands in for the Public Suffix List: a miss costs one unstripped parameter.
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

// alphaLabel reports whether s could be a TLD; it stops "amazon.evil.com" matching "amazon.".
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

// RuleCatalog is what GET /clean/rules serves: both tables verbatim, the version and the scope sentence.
type RuleCatalog struct {
	Version    string    `json:"version"`
	Scope      string    `json:"scope"`
	Tracking   []Rule    `json:"tracking"`
	NeverStrip []Deny    `json:"never_strip"`
	Wrappers   []Wrapper `json:"wrappers"`
}

// Rules clones the tables against reordering; the Hosts slices inside are shared and must not be written.
func Rules() RuleCatalog {
	return RuleCatalog{
		Version:    RulesVersion,
		Scope:      catalogScope,
		Tracking:   slices.Clone(trackingRules),
		NeverStrip: slices.Clone(denyList),
		Wrappers:   slices.Clone(wrappers),
	}
}

type RuleMatches struct {
	Param      string `json:"param"`
	Tracking   []Rule `json:"tracking"`
	NeverStrip []Deny `json:"never_strip"`
}

// Matches lists the rules naming param as Clean's lookup does.
func (c RuleCatalog) Matches(param string) RuleMatches {
	k := strings.ToLower(strings.TrimSpace(param))
	out := RuleMatches{Param: k, Tracking: []Rule{}, NeverStrip: []Deny{}}
	names := func(p string, prefix bool) bool {
		if prefix {
			return strings.HasPrefix(k, p)
		}
		return k == p
	}
	for _, prefix := range []bool{false, true} {
		for _, r := range c.Tracking {
			if r.Prefix == prefix && names(r.Param, prefix) {
				out.Tracking = append(out.Tracking, r)
			}
		}
		for _, d := range c.NeverStrip {
			if d.Prefix == prefix && names(d.Param, prefix) {
				out.NeverStrip = append(out.NeverStrip, d)
			}
		}
	}
	return out
}
