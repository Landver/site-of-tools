package mcptools

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Landver/site-of-tools/tools/linktools"
)

type linkInspectArgs struct {
	URL string `json:"url" jsonschema:"the URL to take apart, e.g. https://example.com/p?id=7"`
}

type linkCleanArgs struct {
	URL            string `json:"url" jsonschema:"the URL to clean"`
	Unwrap         *bool  `json:"unwrap,omitempty" jsonschema:"unwrap a redirect wrapper to its destination first"`
	StripAffiliate bool   `json:"strip_affiliate,omitempty" jsonschema:"also remove affiliate tags, which pay whoever recommended the link"`
	Sort           bool   `json:"sort,omitempty" jsonschema:"sort the parameters left by name"`
}

type linkRulesArgs struct {
	Param string `json:"param,omitempty" jsonschema:"a parameter name, e.g. ref"`
	URL   string `json:"url,omitempty" jsonschema:"a URL whose parameters to judge"`
	Full  bool   `json:"full,omitempty" jsonschema:"the whole rule table"`
}

type linkDiffArgs struct {
	URLA string `json:"url_a" jsonschema:"the first URL"`
	URLB string `json:"url_b" jsonschema:"the second URL"`
}

type linkTraceArgs struct {
	URL     string `json:"url" jsonschema:"the URL to follow; https:// is assumed when it has no scheme"`
	Persona string `json:"persona,omitempty" jsonschema:"the user agent to present as"`
}

type linkCurlParseArgs struct {
	Command string `json:"command" jsonschema:"the curl command, backslash line continuations and all"`
}

type linkCurlBuildArgs struct {
	URL             string `json:"url" jsonschema:"the URL to fetch"`
	Persona         string `json:"persona,omitempty" jsonschema:"send this client's User-Agent"`
	FollowRedirects bool   `json:"follow_redirects,omitempty" jsonschema:"add -L to follow redirects"`
	ShowHeaders     bool   `json:"show_headers,omitempty" jsonschema:"add -i to print the response headers"`
}

type linkExtractArgs struct {
	Text     string `json:"text" jsonschema:"the HTML, Markdown or plain text"`
	Detailed bool   `json:"detailed,omitempty" jsonschema:"list up to 2,000 links, each with its byte positions in the text"`
}

// The UTM tags are pointers: absent keeps the URL's own tag, "" removes it.
type linkUTMArgs struct {
	URL         string  `json:"url" jsonschema:"the URL to tag"`
	UTMSource   *string `json:"utm_source,omitempty" jsonschema:"where the traffic comes from, e.g. newsletter"`
	UTMMedium   *string `json:"utm_medium,omitempty" jsonschema:"how it arrives, e.g. email"`
	UTMCampaign *string `json:"utm_campaign,omitempty" jsonschema:"the campaign, e.g. spring-launch"`
	UTMTerm     *string `json:"utm_term,omitempty" jsonschema:"the paid search keyword"`
	UTMContent  *string `json:"utm_content,omitempty" jsonschema:"which link it was, when a campaign has several"`
}

type linkEncodeArgs struct {
	Value string `json:"value" jsonschema:"the value to encode and decode"`
}

type linkResolveArgs struct {
	Code string `json:"code" jsonschema:"a short link's code, or its whole short URL"`
}

// extractRows is how many distinct links a concise link_extract lists.
const extractRows = 30

type linkTools struct {
	svc   *linktools.Service
	trace *linktools.Tracer
	short *linktools.Shortener
	log   *slog.Logger
}

func linkSpecs(d Deps, log *slog.Logger) []toolSpec {
	t := linkTools{svc: d.Link, trace: d.Tracer, short: d.Short, log: log}
	lim := d.LinkLimits
	var personas []string
	for _, p := range linktools.Personas() {
		personas = append(personas, p.Key)
	}
	var specs []toolSpec
	pure := func(name, title, desc, narrow string, schema any, add func(*mcp.Server, *mcp.Tool)) {
		specs = append(specs, toolSpec{
			toolset: "link",
			tool: &mcp.Tool{Name: name, Title: title, Description: desc, InputSchema: schema,
				Annotations: readOnly(false)},
			deadline: quickDeadline,
			limiter:  lim.Pure,
			narrow:   narrow,
			add:      add,
		})
	}
	if t.svc != nil {
		pure("link_inspect", "Inspect a URL",
			"Take a URL apart without fetching it: scheme, host (Unicode and punycode), port, path segments, "+
				"and every query and fragment parameter in order, decoded layer by layer (percent, base64, JSON, JWT), "+
				"with repeated keys kept and each tracker's rule named. "+
				"notes flag what a reader would miss, such as a dangerous scheme, credentials before the host or an ambiguous +. "+
				"To remove the trackers use link_clean; to compare two URLs, link_diff. Example: url https://example.com/p?utm_source=x&id=7.",
			"Pass a shorter URL.", inputSchema[linkInspectArgs](minLength("url", 1)), handle(t.inspect))
		pure("link_clean", "Clean a URL",
			"Remove tracking parameters from a URL and name the rule behind each removal, without fetching anything. "+
				"By default it first unwraps redirect wrappers such as Outlook Safe Links, Google redirects and urldefense to the real destination; "+
				"affiliate tags stay unless strip_affiliate is true. "+
				"output is byte for byte the input when nothing was removed. "+
				"To ask why a parameter is or isn't removed, use link_tracking_rules. Example: url https://example.com/?utm_source=news&fbclid=abc&id=7.",
			"Pass a shorter URL.", inputSchema[linkCleanArgs](minLength("url", 1), defaultTo("unwrap", true)), handle(t.clean))
		pure("link_tracking_rules", "Tracking rules",
			"Look up the tracking-parameter rules link_clean applies. "+
				"param (e.g. ref or utm_source) returns every rule and never-strip entry naming it, with the hosts each is limited to; "+
				"url returns what link_clean would do with each of that URL's parameters, and why; "+
				"full: true returns the whole table (about 20 KB), as the JSON API serves it. "+
				"With none of them it returns the table's version, scope and size. Pass at most one of param, url and full.",
			"", inputSchema[linkRulesArgs](), handle(t.rules))
		pure("link_diff", "Compare two URLs",
			"Compare two URLs part by part and parameter by parameter: what was added, removed, changed or only moved, "+
				"with differences of spelling rather than meaning (host case, a default port, escape case) marked cosmetic. "+
				"identical is true when the two mean the same thing. "+
				"Use it to find why one link behaves differently from another. "+
				"Example: url_a https://example.com/?a=1&b=2, url_b https://example.com/?b=2&a=3.",
			"Pass shorter URLs.", inputSchema[linkDiffArgs](minLength("url_a", 1), minLength("url_b", 1)), handle(t.diff))
		pure("link_curl_parse", "Take apart a curl command",
			"Take a curl command apart, including a browser's Copy as cURL: its URL (inspected as link_inspect does), "+
				"the method and why it is that one, every header in order, and the size of any body, whose content is never echoed. "+
				"Nothing is run or fetched. For the reverse, use link_curl_build. "+
				"Example: command curl -H 'Accept: application/json' https://api.example.com/v1/items.",
			"Pass a shorter command.", inputSchema[linkCurlParseArgs](minLength("command", 1)), handle(t.curlParse))
		pure("link_curl_build", "Build a curl command",
			"Turn a URL into a curl command, single-quoted so it is safe to paste into a shell. "+
				"persona adds that client's User-Agent (left out, curl sends its own), follow_redirects adds -L and show_headers adds -i. "+
				"For taking a command apart, use link_curl_parse. Example: url https://example.com/search?q=a&page=2.",
			"", inputSchema[linkCurlBuildArgs](minLength("url", 1), oneOf("persona", personas)), handle(t.curlBuild))
		pure("link_extract", "Extract links",
			"Pull every link out of pasted HTML, Markdown or plain text, such as a newsletter before it is sent: "+
				"deduplicated in the order first seen, counted, with anchor text and flags for links that should stop a send "+
				"(a javascript: link, credentials before the host, text that shows one host and links to another). Nothing is fetched. "+
				"Lists the first 30 distinct links, with unique counting them all; detailed: true lists up to 2,000 with their byte positions. "+thirdParty,
			"Leave detailed off, or pass less text.", inputSchema[linkExtractArgs](minLength("text", 1)), handle(t.extract))
		pure("link_utm", "Build a campaign URL",
			"Add or change a URL's UTM campaign tags. "+
				"A tag you pass replaces the URL's own, an empty string removes it, and one you leave out is kept as it is. "+
				"tags says where each tag came from (set, replaced or kept) and notes flag what trips analytics tools, such as capitals or a +. "+
				"Example: url https://example.com/landing, utm_source newsletter, utm_medium email.",
			"", inputSchema[linkUTMArgs](minLength("url", 1)), handle(t.utm))
		pure("link_percent_encode", "Encode and decode",
			"Encode one value every way a URL can carry it, and decode it every way it might already be encoded: "+
				"percent-encoding by query rules (a space becomes +) and by path rules (a space becomes %20) side by side, "+
				"base64 and base64url, HTML entities, and each layer of a value encoded more than once. "+
				"Use it to see why a value breaks inside a URL. Example: value a b+c/d.",
			"Pass a shorter value.", inputSchema[linkEncodeArgs](minLength("value", 1)), handle(t.encode))
	}
	if t.trace != nil {
		specs = append(specs, toolSpec{
			toolset: "link",
			tool: &mcp.Tool{
				Name:  "link_redirect_chain",
				Title: "Trace a redirect chain",
				Description: "Follow a URL's HTTP redirects hop by hop from this server: each hop's status, timing, Location, Server and Content-Type " +
					"and whether it set a cookie, where the chain ends, and notes when it goes on by JavaScript or meta refresh. It returns no page body. " +
					"It visits the URL, so never trace a one-time login, unsubscribe or email-verification link: the visit can use it up. " +
					"persona sets the user agent, to see what a crawler or link unfurler is shown. Example: url https://example.com/old-page. " + thirdParty,
				InputSchema: inputSchema[linkTraceArgs](minLength("url", 1),
					oneOf("persona", personas), defaultTo("persona", personas[0])),
				Annotations: acts(false, false, true),
			},
			deadline: fetchDeadline,
			limiter:  lim.Fetch,
			cap:      lim.FetchCap,
			add:      handle(t.redirectChain),
		})
	}
	if t.short != nil {
		specs = append(specs, toolSpec{
			toolset: "link",
			tool: &mcp.Tool{
				Name:  "link_short_resolve",
				Title: "Resolve a short link",
				Description: "Say where one of corpberry.com's own short links leads, without following it or counting a visit. " +
					"Pass the code or the whole short URL, e.g. " + t.short.ShortURL("q4-report") + ". " +
					"An expired, revoked or unknown code answers no such link. For any other short link or redirect, use link_redirect_chain.",
				InputSchema: inputSchema[linkResolveArgs](minLength("code", 1)),
				Annotations: readOnly(false),
			},
			deadline: quickDeadline,
			limiter:  lim.Resolve,
			breaker:  lim.ResolveGlobal,
			add:      handle(t.resolve),
		})
	}
	return specs
}

// wrongTool refuses, as REST's pages do, a curl command or text with links in
// it passed as a URL, naming the tool that takes it.
func wrongTool(raw string) error {
	switch linktools.WrongTool(raw) {
	case linktools.ToolCurl:
		return errors.New("That looks like a curl command, not a URL. Take it apart with link_curl_parse.")
	case linktools.ToolExtract:
		return errors.New("That looks like text with links in it, not one URL. Pull them out with link_extract.")
	}
	return nil
}

func (t linkTools) inspect(_ context.Context, _ *mcp.CallToolRequest, a linkInspectArgs) (any, error) {
	if err := wrongTool(a.URL); err != nil {
		return nil, err
	}
	return t.svc.Parse(a.URL)
}

func (t linkTools) clean(_ context.Context, _ *mcp.CallToolRequest, a linkCleanArgs) (any, error) {
	if err := wrongTool(a.URL); err != nil {
		return nil, err
	}
	return t.svc.Clean(a.URL, linktools.CleanOptions{
		Unwrap: a.Unwrap == nil || *a.Unwrap, StripAffiliate: a.StripAffiliate, Sort: a.Sort,
	})
}

// rules: param, url and full each ask a different question of the table, so
// they don't combine.
func (t linkTools) rules(_ context.Context, _ *mcp.CallToolRequest, a linkRulesArgs) (any, error) {
	cat := linktools.Rules()
	asked := 0
	for _, set := range []bool{a.Param != "", a.URL != "", a.Full} {
		if set {
			asked++
		}
	}
	switch {
	case asked > 1:
		return nil, errors.New("pass at most one of param, url and full")
	case a.Full:
		return cat, nil
	case a.Param != "":
		return cat.Matches(a.Param), nil
	case a.URL != "":
		if err := wrongTool(a.URL); err != nil {
			return nil, err
		}
		return cat.Verdict(a.URL)
	}
	return cat.Summary(), nil
}

func (t linkTools) diff(_ context.Context, _ *mcp.CallToolRequest, a linkDiffArgs) (any, error) {
	for _, u := range []string{a.URLA, a.URLB} {
		if err := wrongTool(u); err != nil {
			return nil, err
		}
	}
	return t.svc.Diff(a.URLA, a.URLB)
}

func (t linkTools) redirectChain(ctx context.Context, _ *mcp.CallToolRequest, a linkTraceArgs) (any, error) {
	if err := wrongTool(a.URL); err != nil {
		return nil, err
	}
	return t.trace.Trace(ctx, a.URL, a.Persona)
}

func (t linkTools) curlParse(_ context.Context, _ *mcp.CallToolRequest, a linkCurlParseArgs) (any, error) {
	return t.svc.ParseCurl(a.Command)
}

func (t linkTools) curlBuild(_ context.Context, _ *mcp.CallToolRequest, a linkCurlBuildArgs) (any, error) {
	if err := wrongTool(a.URL); err != nil {
		return nil, err
	}
	line, err := t.svc.ToCurl(a.URL, linktools.CurlOptions{
		Persona: a.Persona, FollowRedirects: a.FollowRedirects, ShowHeaders: a.ShowHeaders,
	})
	if err != nil {
		return nil, err
	}
	return map[string]string{"curl": line}, nil
}

// extract is GET/POST /extract; concise drops each link's positions and lists
// the first extractRows links, with a note saying how many there are.
func (t linkTools) extract(_ context.Context, _ *mcp.CallToolRequest, a linkExtractArgs) (any, error) {
	res, err := t.svc.Extract(strings.TrimSpace(a.Text))
	if err != nil {
		return nil, err
	}
	out, err := object(res)
	if err != nil || a.Detailed {
		return out, err
	}
	urls, _ := out["urls"].([]any)
	for _, u := range urls {
		if row, ok := u.(map[string]any); ok {
			delete(row, "positions")
		}
	}
	if len(urls) > extractRows {
		out["urls"] = urls[:extractRows]
		notes, _ := out["notes"].([]any)
		out["notes"] = append(notes, linktools.Note{Severity: linktools.SevInfo,
			Title:  fmt.Sprintf("The first %d of %d links", extractRows, len(urls)),
			Detail: "Pass detailed: true for all of them, with their positions in the text."})
	}
	return out, nil
}

func (t linkTools) utm(_ context.Context, _ *mcp.CallToolRequest, a linkUTMArgs) (any, error) {
	if err := wrongTool(a.URL); err != nil {
		return nil, err
	}
	changes := map[string]string{}
	for key, v := range map[string]*string{
		"utm_source": a.UTMSource, "utm_medium": a.UTMMedium, "utm_campaign": a.UTMCampaign,
		"utm_term": a.UTMTerm, "utm_content": a.UTMContent,
	} {
		if v != nil {
			changes[key] = *v
		}
	}
	return t.svc.BuildUTM(a.URL, changes)
}

func (t linkTools) encode(_ context.Context, _ *mcp.CallToolRequest, a linkEncodeArgs) (any, error) {
	return linktools.EncodeAll(a.Value), nil
}

// resolve answers what GET /s/:code would redirect to, without the redirect
// or its hit. Expired, revoked and unknown read alike, as they do there.
func (t linkTools) resolve(ctx context.Context, _ *mcp.CallToolRequest, a linkResolveArgs) (any, error) {
	code, ok := linktools.CodeFromShortURL(a.Code, t.short.ShortURL(""))
	if !ok {
		if strings.ContainsAny(a.Code, "./:") {
			return nil, fmt.Errorf("Not a corpberry.com short link (%s). To see where any other link leads, use link_redirect_chain.",
				t.short.ShortURL("<code>"))
		}
		return nil, linktools.ErrLinkNotFound
	}
	l, err := t.short.Resolve(ctx, code)
	switch {
	case errors.Is(err, linktools.ErrLinkNotFound):
		return nil, linktools.ErrLinkNotFound
	case err != nil:
		return nil, publicError(t.log, "link_short_resolve", err)
	}
	return map[string]string{"code": l.Code, "short": t.short.ShortURL(l.Code), "target": l.Target}, nil
}

// publicError is err as linktools.PublicError lets a caller see it. A store
// failure becomes its fixed sentence and only the log gets the detail, which
// can name hosts and connection strings.
func publicError(log *slog.Logger, tool string, err error) error {
	code, msg := linktools.PublicError(err)
	if code == http.StatusInternalServerError {
		log.Error("mcp: link storage error", "tool", tool, "err", err.Error())
	}
	return errors.New(msg)
}
