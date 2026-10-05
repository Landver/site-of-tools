package mcptools

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Landver/site-of-tools/platform"
)

// Deadlines per cost class (docs/02-security-and-ops.md §4). Rates and caps
// are not set here: every tool spends its REST twin's Limits.
const (
	quickDeadline    = 5 * time.Second // pure, resolve, and every method but tools/call
	heavyDeadline    = 15 * time.Second
	fetchDeadline    = 20 * time.Second
	upstreamDeadline = 25 * time.Second // dns, dns-walk, upstream: the RDAP/CT client alone allows 20 s
)

// toolSpec is one tool: its contract, the toolset that serves it, the budget it
// shares with its REST twin, and how its handler is added to a server.
type toolSpec struct {
	toolset  string
	tool     *mcp.Tool
	deadline time.Duration
	limiter  platform.Limiter
	// breaker is a budget every client shares, spent after limiter, like the
	// REST twin's global breaker; its refusal reads as busy. Nil for none.
	breaker platform.Limiter
	cap     *platform.Cap // nil: no bound on calls in flight
	narrow  string        // how to ask for less, when a result is over the hard cap
	add     func(*mcp.Server, *mcp.Tool)
}

// handle adapts a typed handler for toolSpec.add: a result becomes
// structuredContent plus the same JSON as text, an error an isError result
// carrying its message. Input is validated against the schema first.
func handle[In any](f func(context.Context, *mcp.CallToolRequest, In) (any, error)) func(*mcp.Server, *mcp.Tool) {
	return func(s *mcp.Server, t *mcp.Tool) {
		mcp.AddTool(s, t, func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
			out, err := f(ctx, req, in)
			return nil, out, err
		})
	}
}

// readOnly is the hint set of a tool that changes nothing; open marks one that
// reaches past this server. All four are set: the spec's defaults read as
// destructive and open-world.
func readOnly(open bool) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true,
		DestructiveHint: jsonschema.Ptr(false), OpenWorldHint: jsonschema.Ptr(open)}
}

// acts is the hint set of a tool that is not read-only: one whose call can
// change something, here or wherever it reaches.
func acts(destructive, idempotent, open bool) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{IdempotentHint: idempotent,
		DestructiveHint: jsonschema.Ptr(destructive), OpenWorldHint: jsonschema.Ptr(open)}
}

// object is v's JSON as an object, numbers kept exact, for a projection that
// drops or reshapes the REST body's fields by their JSON names.
func object(v any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errNotObject
	}
	return m, nil
}

// toolset is one public endpoint, /mcp/<name>: its heading, the subdomain its
// REST twins live on, and the data sources its results credit.
type toolset struct {
	name, title, host string
	credits           []string
}

var toolsets = []toolset{
	{"ip", "IP Tools", "ip", []string{platform.CreditIP2Location, platform.CreditSpamhaus, platform.CreditShodan}},
	{"dns", "DNS Tools", "dns", []string{platform.CreditIP2Location, platform.CreditSpamhaus, platform.CreditCrtSh, platform.CreditRDAP}},
	{"link", "Link Tools", "link", nil},
	{"cipher", "Cipher Tools", "cipher", nil},
	{"botcheck", "Bot check", "botcheck", []string{platform.CreditIP2Location, platform.CreditSpamhaus, platform.CreditShodan}},
	{"site", "corpberry.com", "", nil},
}

// ownerEndpoint is /mcp/owner: the owner's tools, behind MCP_OWNER_KEY.
const ownerEndpoint = "owner"

// Coverage statuses.
const (
	StatusTool     = "tool"     // served by Tools
	StatusPlanned  = "planned"  // to be served by Tools in a later floor
	StatusExcluded = "excluded" // deliberately not a tool, for Reason
)

// Route is a REST route: its subdomain ("" for the apex), method and path as
// Echo registers them.
type Route struct{ Host, Method, Path string }

// Decision is what MCP does with one REST route.
type Decision struct {
	Status string
	Tools  []string
	Reason string
}

// Coverage maps every REST route of every subdomain to its decision. A test
// builds each Register and fails on a route without an entry, or an entry
// without a route.
func Coverage() map[Route]Decision { return maps.Clone(coverage) }

func served(tools ...string) Decision  { return Decision{Status: StatusTool, Tools: tools} }
func planned(tools ...string) Decision { return Decision{Status: StatusPlanned, Tools: tools} }
func excluded(reason string) Decision  { return Decision{Status: StatusExcluded, Reason: reason} }

const (
	get, post, del = http.MethodGet, http.MethodPost, http.MethodDelete
	cipherShell    = "A page shell for the in-browser engine; the op it posts to is a tool."
)

var coverage = map[Route]Decision{
	{"", get, "/"}:              excluded("The apex JSON tool catalog: tools/list, the server instructions and the landing page's JSON replace it."),
	{"", get, "/blog"}:          planned("site_blog"),
	{"", get, "/blog/:slug"}:    planned("site_blog"),
	{"", get, "/blog/feed.xml"}: excluded("RSS; site_blog covers the posts."),

	{"ip", get, "/"}:        served("ip_lookup"),
	{"ip", get, "/cidr"}:    served("ip_cidr"),
	{"ip", get, "/history"}: excluded("D9: addresses other visitors looked up on the web page; no agent task needs them."),

	{"botcheck", get, "/"}:               planned("botcheck_score"),
	{"botcheck", post, "/check"}:         planned("botcheck_score"),
	{"botcheck", get, "/botcheck-sw.js"}: excluded("The in-browser collector's service worker; botcheck_score scores what a collector produced."),

	{"dns", get, "/"}:            served("dns_lookup"),
	{"dns", get, "/consistency"}: served("dns_consistency"),
	{"dns", get, "/trace"}:       served("dns_trace"),
	{"dns", get, "/domain"}:      served("dns_domain_info"),
	{"dns", get, "/email"}:       served("dns_email_auth"),

	{"link", get, "/"}:                  served("link_inspect"),
	{"link", get, "/clean"}:             served("link_clean"),
	{"link", get, "/clean/rules"}:       served("link_tracking_rules"),
	{"link", get, "/diff"}:              served("link_diff"),
	{"link", get, "/curl"}:              served("link_curl_parse", "link_curl_build"),
	{"link", post, "/curl"}:             served("link_curl_parse"),
	{"link", get, "/extract"}:           served("link_extract"),
	{"link", post, "/extract"}:          served("link_extract"),
	{"link", get, "/utm"}:               served("link_utm"),
	{"link", get, "/encode"}:            served("link_percent_encode"),
	{"link", get, "/trace"}:             served("link_redirect_chain"),
	{"link", get, "/s/:code"}:           served("link_short_resolve"),
	{"link", get, "/short"}:             served("link_short_list"),
	{"link", post, "/short"}:            served("link_short_create"),
	{"link", del, "/short/:code"}:       served("link_short_revoke"),
	{"link", get, "/encoding"}:          excluded("A static reference document with no JSON form."),
	{"link", get, "/extension/privacy"}: excluded("The browser extension's privacy policy, a static document."),

	{"cipher", post, "/jwt/decode"}:      planned("cipher_jwt_decode"),
	{"cipher", post, "/jwt/sign"}:        planned("cipher_jwt_sign"),
	{"cipher", post, "/hash"}:            planned("cipher_hash"),
	{"cipher", post, "/hmac"}:            planned("cipher_hmac"),
	{"cipher", post, "/password/hash"}:   planned("cipher_password_hash"),
	{"cipher", post, "/password/verify"}: planned("cipher_password_verify"),
	{"cipher", post, "/encrypt"}:         planned("cipher_encrypt"),
	{"cipher", post, "/keys/generate"}:   planned("cipher_keys_generate"),
	{"cipher", post, "/keys/inspect"}:    planned("cipher_keys_inspect"),
	{"cipher", post, "/cert"}:            planned("cipher_cert"),
	{"cipher", post, "/totp"}:            planned("cipher_totp"),
	{"cipher", post, "/random"}:          planned("cipher_random"),
	{"cipher", post, "/encode"}:          planned("cipher_encode"),
	{"cipher", post, "/encode/basic"}:    planned("cipher_basic_auth"),
	{"cipher", post, "/identify"}:        planned("cipher_identify"),
	{"cipher", get, "/"}:                 excluded(cipherShell),
	{"cipher", get, "/hash"}:             excluded(cipherShell),
	{"cipher", get, "/hmac"}:             excluded(cipherShell),
	{"cipher", get, "/password"}:         excluded(cipherShell),
	{"cipher", get, "/encrypt"}:          excluded(cipherShell),
	{"cipher", get, "/keys"}:             excluded(cipherShell),
	{"cipher", get, "/cert"}:             excluded(cipherShell),
	{"cipher", get, "/totp"}:             excluded(cipherShell),
	{"cipher", get, "/random"}:           excluded(cipherShell),
	{"cipher", get, "/encode"}:           excluded(cipherShell),
	{"cipher", get, "/identify"}:         excluded(cipherShell),
}
