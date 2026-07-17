package botcheck

import "strings"

// Good-bot / AI-agent classification (ROADMAP G36). We separate two things the old
// scorer conflated: a *malicious* automated client (curl, a headless scraper) and a
// *known* crawler or AI-company agent (Googlebot, GPTBot, ClaudeBot). The latter are
// still bots — they post no fingerprint and score low on human-likeness — but the
// report names them instead of lumping them with abuse.
//
// The one hard rule is **no evasion**: recognising a User-Agent must never, by
// itself, reduce suspicion, or any scraper would just wear "Googlebot" to escape.
// So a good-bot *downgrade* (the "good-bot" verdict) is granted only when the egress
// network corroborates the operator — and only for operators that crawl from a
// single-tenant ASN an outsider can't rent (see goodBots). Everything else is
// recognised-but-unverified: labelled, but still penalised exactly as before.

// Bot kinds — the label shown for a recognised client.
const (
	BotSearchCrawler = "search-crawler"
	BotAIAgent       = "ai-agent"
)

// BotIdentity is the classification of a recognised good bot / AI agent. Verified is
// true only when the egress ASN owner corroborates the operator (classifyGoodBot);
// an unverified identity is labelled but still scored as automation.
type BotIdentity struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`     // BotSearchCrawler | BotAIAgent
	Verified bool   `json:"verified"` // egress network corroborates the operator
}

// goodBot is one allowlist row. asns is the operator's single-tenant CRAWLER ASN
// number(s) — the exact autonomous system the crawler egresses from, which an
// outsider cannot originate traffic from. It is set ONLY for operators whose crawler
// ASN is distinct from any public cloud they resell, and left nil for:
//   - multi-tenant hyperscaler crawlers (Googlebot on Google's AS15169, Bingbot on
//     Microsoft's AS8075): the crawler shares its ASN with GCP/Azure tenants, so
//     membership proves only "on the operator's cloud", not "is the crawler";
//   - cloud-hosted AI agents (GPTBot/ClaudeBot on Azure/AWS): they egress the cloud
//     provider's ASN, never the operator's, so it can neither corroborate nor, safely,
//     flag a spoof (a genuine agent would be falsely accused).
//
// It is the ASN NUMBER, not the owner NAME: an owner-name substring ("yandex") also
// matches the operator's rentable public cloud (Yandex Cloud, "Yandex.Cloud LLC"),
// which would let a scraper on a rented VM verify itself. The number is the crawler's
// alone. Those without an ASN stay recognised-but-unverified; closing the gap needs a
// published IP-range check we don't bundle yet — a documented follow-up.
type goodBot struct {
	token string // lowercase substring to find in the UA
	name  string
	kind  string
	asns  []string // single-tenant crawler ASN number(s); nil ⇒ recognised-only
}

// goodBots is the allowlist, scanned in order (the token match gates everything; the
// ASN is consulted only after a token already matched). Verified-capable rows first,
// then recognised-only. Each ASN must be the operator's CRAWLER autonomous system,
// NOT a cloud brand it resells — re-verify against the live IP2Location ASN BIN
// before adding one (a wrong number is a safe false negative; a cloud ASN would be an
// evasion). Crawler ASNs as of 2026-07: Yandex AS13238 (Yandex Cloud is a separate
// AS200350), Baidu AS55967, Apple AS714/AS6185, Naver AS23576 (Naver Cloud Platform
// is separate), Seznam AS43037, Anthropic AS399358, Meta AS32934, ByteDance AS396986.
var goodBots = []goodBot{
	// ── Verifiable: single-tenant crawler ASNs (distinct from any resold cloud) ──
	{"yandexbot", "YandexBot", BotSearchCrawler, []string{"13238"}},
	{"baiduspider", "Baiduspider", BotSearchCrawler, []string{"55967"}},
	{"applebot", "Applebot", BotSearchCrawler, []string{"714", "6185"}},
	{"seznambot", "SeznamBot", BotSearchCrawler, []string{"43037"}},
	{"yeti", "Yeti (Naver)", BotSearchCrawler, []string{"23576"}}, // token is generic — gated on "naver.me/bot"
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
// (case-insensitively), or nil. "yeti" is a generic word, so it additionally
// requires the crawler's self-identifying "naver.me/bot" marker — a false-positive
// reducer only, never a verification control (that is the ASN's job).
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

// normalizeASN strips a leading "AS"/"as" prefix and surrounding space from an ASN
// string, so "AS13238" and "13238" both compare equal to the bare numbers in goodBots.
func normalizeASN(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == 'A' || s[0] == 'a') && (s[1] == 'S' || s[1] == 's') {
		s = s[2:]
	}
	return strings.TrimSpace(s)
}

// classifyGoodBot identifies a recognised good bot / AI agent from the UA and, for a
// verifiable operator, corroborates it against the egress ASN NUMBER. Verified is
// granted IFF the entry lists crawler ASNs and the egress ASN is exactly one of them.
// Every other case (declared-only cloud agent, empty/unknown ASN, or an off-network
// ASN — including the operator's own rentable public cloud, which is a different ASN)
// stays unverified. So a UA claim alone never escapes the bot penalty, a rented VM
// can't verify itself, and a genuine cloud-hosted agent is never mislabelled a spoof.
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
