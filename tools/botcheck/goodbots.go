package botcheck

import "strings"

// No evasion: a UA match alone never lowers suspicion; only a corroborating egress ASN grants "good-bot".

const (
	BotSearchCrawler = "search-crawler"
	BotAIAgent       = "ai-agent"
)

// BotIdentity names a recognised good bot or AI agent; unverified ones still score as automation.
type BotIdentity struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`     // BotSearchCrawler | BotAIAgent
	Verified bool   `json:"verified"` // egress network corroborates operator
}

// goodBot.asns holds only the operator's single-tenant crawler ASNs, matched by number: an owner name
// ("yandex") also matches its rentable cloud. nil for crawlers on shared clouds (Googlebot, GPTBot).
type goodBot struct {
	token string // lowercase substring to find in UA
	name  string
	kind  string
	asns  []string // single-tenant crawler ASN number(s); nil ⇒ recognised-only
}

// Verify a new ASN in the live IP2Location ASN BIN: a wrong number only misses; a cloud ASN lets VMs verify.
var goodBots = []goodBot{
	// ── Verifiable: single-tenant crawler ASNs (distinct from resold cloud) ──
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

// matchGoodBot: the "naver.me/bot" gate only cuts false positives; verification is the ASN's job.
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

// normalizeASN makes "AS13238" and "13238" compare equal.
func normalizeASN(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == 'A' || s[0] == 'a') && (s[1] == 'S' || s[1] == 's') {
		s = s[2:]
	}
	return strings.TrimSpace(s)
}

// classifyGoodBot returns nil for an unrecognised UA; Verified needs the egress ASN in the entry's list.
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
