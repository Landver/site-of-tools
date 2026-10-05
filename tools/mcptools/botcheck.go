package mcptools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/botcheck"
	"github.com/Landver/site-of-tools/tools/iptools"
)

type botScoreArgs struct {
	Fingerprint json.RawMessage `json:"fingerprint,omitempty" jsonschema:"the JSON the bot check collector produced in the browser under test, unchanged, its v version stamp included"`
	HTTP        *botHTTPArgs    `json:"http,omitempty" jsonschema:"that browser's request headers; one left out counts as not sent"`
	IP          string          `json:"ip,omitempty" jsonschema:"the address that browser connects from, e.g. 203.0.113.7"`
	Detailed    bool            `json:"detailed,omitempty" jsonschema:"list every check, not only the ones that fired"`
}

type botHTTPArgs struct {
	UserAgent       string `json:"user_agent,omitempty" jsonschema:"User-Agent"`
	Accept          string `json:"accept,omitempty" jsonschema:"Accept"`
	AcceptLanguage  string `json:"accept_language,omitempty" jsonschema:"Accept-Language"`
	AcceptEncoding  string `json:"accept_encoding,omitempty" jsonschema:"Accept-Encoding"`
	SecCHUA         string `json:"sec_ch_ua,omitempty" jsonschema:"Sec-CH-UA"`
	SecCHUAPlatform string `json:"sec_ch_ua_platform,omitempty" jsonschema:"Sec-CH-UA-Platform"`
	SecFetchMode    string `json:"sec_fetch_mode,omitempty" jsonschema:"Sec-Fetch-Mode"`
}

var errNothingToScore = errors.New("Nothing to score: pass fingerprint (the JSON the bot check collector produced in the browser), " +
	"http (that browser's request headers), ip (the address it connects from), or any mix of them.")

type botTools struct {
	geo iptools.Looker
	chk iptools.Checker
}

func botSpecs(d Deps) []toolSpec {
	t := botTools{geo: d.Geo, chk: d.Blocklist}
	return []toolSpec{{
		toolset: "botcheck",
		tool: &mcp.Tool{
			Name:  "botcheck_score",
			Title: "Bot check score",
			Description: "Score how automated a browser looks from what you supply: the fingerprint botcheck.corpberry.com's collector produced in it, its HTTP headers, its IP address, or any mix. " +
				fmt.Sprintf("Each of the %d checks fires, passes or is skipped for want of data, ", len(botcheck.Evaluate(botcheck.Signals{}).Checks)) +
				"and coverage counts them per tier, so a call with headers alone says how little it could judge. " +
				"score runs from 100 (human) to 0, verdict is human, suspicious, bot or good-bot, and bot names a recognised crawler or AI agent; only fired checks are listed unless detailed is true. " +
				`Example: http {"user_agent": "curl/8.7.1", "accept": "*/*"}. ` + thirdParty,
			InputSchema: inputSchema[botScoreArgs](anyObject("fingerprint")),
			Annotations: readOnly(true),
		},
		deadline: upstreamDeadline,
		limiter:  d.BotLimits.Check,
		cap:      d.BotLimits.CheckCap,
		narrow:   "Leave detailed off.",
		add:      handle(t.score),
	}}
}

// anyObject makes prop a free-form JSON object, keeping its description.
func anyObject(prop string) func(*jsonschema.Schema) {
	return func(s *jsonschema.Schema) {
		s.Properties[prop] = &jsonschema.Schema{Type: "object", Description: s.Properties[prop].Description}
	}
}

// score is GET / and POST /check over what the caller supplied instead of
// what its own request carries. The corpus is never read or written: a
// synthetic payload must not train it.
func (t botTools) score(ctx context.Context, _ *mcp.CallToolRequest, a botScoreArgs) (any, error) {
	ip := strings.TrimSpace(a.IP)
	if len(a.Fingerprint) == 0 && a.HTTP == nil && ip == "" {
		return nil, errNothingToScore
	}
	sig := botcheck.Signals{Now: time.Now(), CorpusSkipped: true}
	if len(a.Fingerprint) > 0 {
		if err := collectorPayload(a.Fingerprint, &sig); err != nil {
			return nil, err
		}
		sig.ClientCollected = true
	}
	if h := a.HTTP; h != nil {
		botcheck.AddHTTPSignals(&sig, botcheck.HTTPSignals{
			UserAgent: h.UserAgent, Accept: h.Accept, AcceptLanguage: h.AcceptLanguage, AcceptEncoding: h.AcceptEncoding,
			SecCHUA: h.SecCHUA, SecCHUAPlatform: h.SecCHUAPlatform, SecFetchMode: h.SecFetchMode,
		})
	}
	var attribution []platform.Credit
	if ip != "" {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, fmt.Errorf("ip: %q is not an IP address", ip)
		}
		res := botcheck.AddIPSignals(ctx, &sig, addr.String(), t.geo, t.chk)
		attribution = credits(platform.CreditIP2Location, platform.CreditSpamhaus)
		if res != nil && res.Shodan != nil && !res.Shodan.Skipped {
			attribution = append(attribution, credits(platform.CreditShodan)...)
		}
	}
	out, err := object(botcheck.Evaluate(sig))
	if err != nil {
		return nil, err
	}
	if !a.Detailed {
		fired := []any{}
		checks, _ := out["checks"].([]any)
		for _, c := range checks {
			if row, ok := c.(map[string]any); ok && row["triggered"] == true {
				fired = append(fired, row)
			}
		}
		out["checks"] = fired
	}
	if attribution != nil {
		out["attribution"] = attribution
	}
	return out, nil
}

// collectorPayload decodes a fingerprint as POST /check binds one, but
// strictly: without its v stamp the rules' version gates can't be applied,
// and a field the collector never sends is a hand-built payload's mistake.
func collectorPayload(raw json.RawMessage, sig *botcheck.Signals) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(sig); err != nil {
		return fmt.Errorf("fingerprint: %s; pass the collector's JSON unchanged", strings.TrimPrefix(err.Error(), "json: "))
	}
	if sig.CollectorV < 1 {
		return errors.New("fingerprint has no v version stamp, so it isn't a collector payload: " +
			"pass the JSON the bot check collector produced, unchanged")
	}
	return nil
}
