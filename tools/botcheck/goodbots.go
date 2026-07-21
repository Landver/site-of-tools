package botcheck

import "strings"

// Good-bot / AI-agent classification (ROADMAP G36). Splits 2 things old scorer
// conflated: *malicious* automated client (curl, headless scraper) vs *known*
// crawler/AI-company agent (Googlebot, GPTBot, ClaudeBot). Latter still bots — no
// fingerprint posted, low human-likeness score — but report names them instead of
// lumping w/ abuse.
//
// Hard rule: **no evasion**. Recognising a User-Agent must never by itself cut
// suspicion → any scraper would just wear "Googlebot" to escape. So good-bot
// *downgrade* ("good-bot" verdict) granted only when egress network corroborates
// operator — only for operators crawling from single-tenant ASN outsider can't
// rent (see goodBots). Everything else: recognised-but-unverified — labelled, but
// penalised same as before.

// Bot kinds — label shown for a recognised client.
const (
	BotSearchCrawler = "search-crawler"
	BotAIAgent       = "ai-agent"
)

// BotIdentity is the classification of a recognised good bot / AI agent. Verified
// true only when egress ASN owner corroborates operator (classifyGoodBot);
// unverified identity labelled but still scored as automation.
type BotIdentity struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`     // BotSearchCrawler | BotAIAgent
	Verified bool   `json:"verified"` // egress network corroborates operator
}

// goodBot is one allowlist row. asns = operator's single-tenant CRAWLER ASN
// number(s) — exact autonomous system crawler egresses from, outsider can't
// originate traffic from. Set ONLY for operators whose crawler ASN distinct from
// any public cloud they resell; nil for:
//   - multi-tenant hyperscaler crawlers (Googlebot on Google's AS15169, Bingbot on
//     Microsoft's AS8075): crawler shares ASN w/ GCP/Azure tenants → membership
//     proves only "on operator's cloud", not "is the crawler";
//   - cloud-hosted AI agents (GPTBot/ClaudeBot on Azure/AWS): egress cloud
//     provider's ASN, never operator's → can neither corroborate nor safely flag
//     spoof (genuine agent would be falsely accused).
//
// ASN NUMBER, not owner NAME: owner-name substring ("yandex") also matches
// operator's rentable public cloud (Yandex Cloud, "Yandex.Cloud LLC") → would let
// scraper on rented VM verify itself. Number is crawler's alone. No-ASN entries
// stay recognised-but-unverified; closing gap needs published IP-range check, not
// bundled yet — documented follow-up.
type goodBot struct {
	token string // lowercase substring to find in UA
	name  string
	kind  string
	asns  []string // single-tenant crawler ASN number(s); nil ⇒ recognised-only
}

// goodBots is the allowlist, scanned in order (token match gates everything; ASN
// consulted only after a token already matched). Verified-capable rows first, then
// recognised-only. Each ASN must be operator's CRAWLER autonomous system, NOT a
// cloud brand it resells — re-verify against live IP2Location ASN BIN before adding
// one (wrong number = safe false negative; cloud ASN = evasion). Crawler ASNs as
// of 2026-07: Yandex AS13238 (Yandex Cloud separate AS200350), Baidu AS55967, Apple
// AS714/AS6185, Naver AS23576 (Naver Cloud Platform separate), Seznam AS43037,
// Anthropic AS399358, Meta AS32934, ByteDance AS396986.
var goodBots = []goodBot{
	// ── Verifiable: single-tenant crawler ASNs (distinct from any resold cloud) ──
	{"yandexbot", "YandexBot", BotSearchCrawler, []string{"13238"}},
	{"baiduspider", "Baiduspider", BotSearchCrawler, []string{"55967"}},
	{"applebot", "Applebot", BotSearchCrawler, []string{"714", "6185"}},
	{"seznambot", "SeznamBot", BotSearchCrawler, []string{"43037"}},
	{"yeti", "Yeti (Naver)", BotSearchCrawler, []string{"23576"}}, // token generic → gated on "naver.me/bot"
	{"claude-user", "Claude-User (Anthropic)", BotAIAgent, []string{"399358"}},
	{"meta-externalagent", "Meta-ExternalAgent", BotAIAgent, []string{"32934"}},
	{"meta-externalfetcher", "Meta-ExternalFetcher", BotAIAgent, []string{"32934"}},
	{"bytespider", "Bytespider (ByteDance)", BotAIAgent, []string{"396986"}},

	// ── Recognised only: multi-tenant cloud, no single-tenant ASN to check ──────
	{"googlebot", "Googlebot", BotSearchCrawler, nil},
	{"google-extended", "Google-Extended", BotAIAgent, nil},
	{"google-cloudvertexbot", "Google-CloudVertexBot", BotAIAgent, nil},
	{"bingbot", "Bingbot", BotSearchCrawler, nil},
	{"amazonbot", "Amazonbot", BotSearchCrawler, nil},
	{"gptbot", "GPTBot (OpenAI)", BotAIAgent, nil},
	{"oai-searchbot", "OAI-SearchBot (OpenAI)", BotAIAgent, nil},
	{"chatgpt-user", "ChatGPT-User (OpenAI)", BotAIAgent, nil},
	{"claudebot", "ClaudeBot (Anthropic)", BotAIAgent, nil},
	{"claude-searchbot", "Claude-SearchBot (Anthropic)", BotAIAgent, nil},
	{"anthropic-ai", "anthropic-ai (Anthropic)", BotAIAgent, nil},
	{"perplexitybot", "PerplexityBot", BotAIAgent, nil},
	{"perplexity-user", "Perplexity-User", BotAIAgent, nil},
	{"ccbot", "CCBot (Common Crawl)", BotAIAgent, nil},
	{"cohere-ai", "cohere-ai", BotAIAgent, nil},
	{"diffbot", "Diffbot", BotAIAgent, nil},
	{"mistralai-user", "MistralAI-User", BotAIAgent, nil},
	{"duckduckbot", "DuckDuckBot", BotSearchCrawler, nil},
	{"duckassistbot", "DuckAssistBot", BotAIAgent, nil},
}

// matchGoodBot returns the first allowlist entry whose token appears in ua
// (case-insensitively), or nil. "yeti" is a generic word → additionally requires
// the crawler's self-identifying "naver.me/bot" marker — a false-positive reducer
// only, never a verification control (that's the ASN's job).
func matchGoodBot(ua string) *goodBot {
	l := strings.ToLower(ua)
	for i := range goodBots {
		g := &goodBots[i]
		if !strings.Contains(l, g.token) {
			continue
		}
		if g.token == "yeti" && !strings.Contains(l, "naver.me/bot") {
			continue
		}
		return g
	}
	return nil
}

// normalizeASN strips a leading "AS"/"as" prefix + surrounding space from an ASN
// string → "AS13238" and "13238" both compare equal to the bare numbers in goodBots.
func normalizeASN(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == 'A' || s[0] == 'a') && (s[1] == 'S' || s[1] == 's') {
		s = s[2:]
	}
	return strings.TrimSpace(s)
}

// classifyGoodBot identifies a recognised good bot / AI agent from the UA and, for
// a verifiable operator, corroborates it against the egress ASN NUMBER. Verified
// granted IFF the entry lists crawler ASNs and egress ASN is exactly one of them.
// Every other case (declared-only cloud agent, empty/unknown ASN, or off-network
// ASN — incl. the operator's own rentable public cloud, a different ASN) stays
// unverified. So a UA claim alone never escapes the bot penalty, a rented VM can't
// verify itself, and a genuine cloud-hosted agent is never mislabelled a spoof.
// nil ⇒ not a recognised bot.
func classifyGoodBot(ua, asn string) *BotIdentity {
	g := matchGoodBot(ua)
	if g == nil {
		return nil
	}
	verified := false
	if egress := normalizeASN(asn); egress != "" {
		for _, a := range g.asns {
			if egress == a {
				verified = true
				break
			}
		}
	}
	return &BotIdentity{Name: g.name, Kind: g.kind, Verified: verified}
}
