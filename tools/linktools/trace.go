package linktools

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"

	"github.com/Landver/site-of-tools/platform"
)

// Bounds on one trace. Every value is from docs/06-security-and-abuse.md §3;
// they exist because this route makes the box fetch a URL a stranger chose, so
// the cost of a request has to be bounded by something other than goodwill.
const (
	maxHops = 10 // above every legitimate chain
	// hopTimeout is also the dial, TLS-handshake and response-header timeout: a
	// chain of ten slow hops is a slowloris aimed at us, not at the target.
	hopTimeout = 5 * time.Second
	// totalTimeout is the fallback wall clock when NewTracer is given none.
	totalTimeout = 15 * time.Second
	// maxLocation bounds a Location header we are willing to resolve.
	maxLocation = 2048
	// maxHeaderBytes: Go's default is 10 MB. 10 hops x 10 MB x burst 5 x N
	// source IPs is a free bandwidth amplifier pointed at this box.
	maxHeaderBytes = 64 << 10
	// maxBodyScan: the only bytes of any body we ever read, and only on the
	// hop that ends the chain, for meta-refresh and JS-redirect detection.
	maxBodyScan = 64 << 10
)

// traceAccept is the one Accept value sent on every hop. Fixed, never derived
// from the caller, because the header set is an allowlist (doc §2).
const traceAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

// Chain is one traced redirect chain. Pure data: handler.go renders it as HTML
// or JSON without knowing how it was produced.
type Chain struct {
	Input string `json:"input"`
	Hops  []Hop  `json:"hops,omitempty"`
	// Final is the last URL the chain actually REACHED. It is deliberately
	// empty whenever the chain demonstrably continues somewhere we did not
	// follow — a JavaScript redirect, a meta refresh, a Refresh header, a
	// non-HTTP scheme, the hop cap, a loop, a refusal. Reporting a
	// pre-redirect URL as the destination is the wrong answer in the
	// security-relevant direction (docs/02-build-fit.md §5), so in those cases
	// the Note names the target instead and this stays blank.
	Final   string `json:"final,omitempty"`
	Notes   []Note `json:"notes,omitempty"`
	Persona string `json:"persona,omitempty"`
	Elapsed int64  `json:"elapsed_ms"`
}

// Hop is one request/response pair in the chain.
type Hop struct {
	Index    int    `json:"index"`
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Location string `json:"location,omitempty"`
	// ElapsedMS covers the whole hop: dial, TLS, request, response headers.
	ElapsedMS int64 `json:"elapsed_ms"`
	// SetCookie records that the response set a cookie, for the per-hop marker
	// stolen from wheregoes.com (docs/reports/wheregoes-com.md). It is a bool
	// on purpose: the value is never read, stored or sent anywhere. There is no
	// cookie jar (doc §2 rule 4).
	SetCookie   bool   `json:"set_cookie,omitempty"`
	Server      string `json:"server,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Notes       []Note `json:"notes,omitempty"`
}

// Persona is a user-agent we are willing to present as (feature A17, stolen
// from httpstatus.io's 27-entry selector).
//
// The point is not novelty, it is honesty: "what does Googlebot see here" and
// "what do I see" are different questions, and when the browser persona gets a
// 403 and Googlebot gets a 200 the tool can state that the target discriminates
// by user agent instead of reporting a dead link
// (docs/reports/httpstatus-io.md, docs/02-build-fit.md §5).
type Persona struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	UA   string `json:"ua"`
}

// personas: the selector, default first. Short list on purpose — these are the
// agents whose answer actually differs in practice (search crawlers, the link
// unfurlers, an AI crawler, and a bare HTTP client).
var personas = []Persona{
	{"browser", "Browser (Chrome, macOS)", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"},
	{"googlebot", "Googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
	{"bingbot", "Bingbot", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"},
	{"twitterbot", "Twitterbot", "Twitterbot/1.0"},
	{"slackbot", "Slackbot (link expanding)", "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)"},
	{"facebook", "Facebook crawler", "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"},
	{"gptbot", "GPTBot", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1; +https://openai.com/gptbot"},
	{"curl", "curl", "curl/8.7.1"},
}

// Personas returns the selector's entries, default first. A copy, so a
// template or handler cannot reorder or rewrite the table it renders from.
func Personas() []Persona { return append([]Persona(nil), personas...) }

// personaFor resolves a key from the query string. Unknown and empty both fall
// back to the default rather than erroring: a bad ?ua= is not worth a 400.
func personaFor(key string) Persona {
	key = strings.ToLower(strings.TrimSpace(key))
	for _, p := range personas {
		if p.Key == key {
			return p
		}
	}
	return personas[0]
}

// Tracer walks a redirect chain. Concrete pointer, nil-receiver-safe: a nil
// *Tracer means the feature is switched off and Trace returns ErrDisabled, so
// the handler answers 503 (docs/03-architecture.md §2). Held as a pointer, not
// an interface, because a nil pointer inside an interface is not == nil and the
// 503 branch would never run.
type Tracer struct {
	guard *platform.EgressGuard
	// gated is guard.DialContext: the SSRF gate, running in Dialer.Control on
	// the literal address the kernel is about to connect to. That placement is
	// the point — there is no check-then-connect window for DNS rebinding to
	// exploit (platform/netgate.go, doc §2).
	gated  func(context.Context, string, string) (net.Conn, error)
	client *http.Client
	total  time.Duration

	// allowLoopback is a test-only seam. The gate rejects loopback, which is
	// exactly where httptest servers live. Per-instance and unexported, so it
	// is race-free without a mutex and nothing outside this package can reach
	// it — docs/07-testing.md §4 chose this over dnstools' package-level
	// resolverOverride for that reason. Never set in production.
	allowLoopback bool
	// direct is the ungated dialer the seam uses. Unreachable unless
	// allowLoopback is set AND the address is loopback.
	direct *net.Dialer
}

// NewTracer builds the tracer. timeout is the TOTAL wall clock for one chain,
// not per hop. A nil guard disables the feature: fail closed, because the guard
// is the whole of the SSRF defence.
func NewTracer(guard *platform.EgressGuard, timeout time.Duration) *Tracer {
	if guard == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = totalTimeout
	}
	t := &Tracer{
		guard:  guard,
		gated:  guard.DialContext(hopTimeout),
		total:  timeout,
		direct: &net.Dialer{Timeout: hopTimeout},
	}
	t.client = &http.Client{
		// Walk the chain by hand, one request at a time, so every hop is a
		// fresh gated dial and every hop is recorded (doc §2).
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		// No cookie jar. Ever (doc §2 rule 4). Explicit because the zero value
		// is the correct one and a later "tidy up" should have to delete a
		// commented line rather than silently add one.
		Jar: nil,
		// No client-wide deadline: each hop carries its own context timeout and
		// the caller's context carries the total.
		Timeout: 0,
		Transport: &http.Transport{
			// Proxy is nil DELIBERATELY, not by omission. With
			// http.ProxyFromEnvironment (which dnstools/email.go still carries)
			// and HTTP_PROXY/HTTPS_PROXY set, DialContext is handed the
			// PROXY's address, so the gate validates the proxy while the
			// attacker-chosen hostname travels to the target inside a CONNECT.
			// The gate is then completely bypassed. docker-compose.yml loads
			// .env wholesale, so such a variable is invisible in the repo, and
			// Go caches the environment read in a sync.Once. Doc §2(a).
			Proxy:       nil,
			DialContext: t.dialContext,
			// A Dialer.Control hook only fires when a dial actually happens.
			// http.Transport serves a matching authority from the idle pool
			// with no dial at all, so hop 2 of pub.evil.com -> int.evil.com
			// (A -> 10.0.0.5, one certificate covering both) could be answered
			// with neither the address nor the port check running. Trace is one
			// request per hop at 1/s, so pooling buys nothing and this costs
			// nothing. Doc §2(b).
			DisableKeepAlives: true,
			// HTTP/2 is not attempted for the same reason: it coalesces
			// several authorities onto one connection, which is the same
			// bypass with a second mechanism. Every host that speaks h2 also
			// speaks HTTP/1.1, and a single request per hop gains nothing.
			ForceAttemptHTTP2:      false,
			MaxResponseHeaderBytes: maxHeaderBytes,
			ResponseHeaderTimeout:  hopTimeout,
			TLSHandshakeTimeout:    hopTimeout,
			ExpectContinueTimeout:  time.Second,
			// TLS is verified. InsecureSkipVerify is absent on purpose and must
			// stay absent: a certificate failure is a FINDING we report, never
			// a reason to retry over http (doc §3).
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	return t
}

// dialContext is the transport's dialer. Everything goes through the egress
// gate; the loopback branch is the test seam and is dead code in production,
// where allowLoopback is false and nothing exported can change it.
func (t *Tracer) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if t.allowLoopback {
		if host, _, err := net.SplitHostPort(address); err == nil && isLoopbackHost(host) {
			return t.direct.DialContext(ctx, network, address)
		}
	}
	return t.gated(ctx, network, address)
}

// Trace walks the redirect chain from raw, at most maxHops deep.
//
// The error return is for input that is not traceable at all (empty, oversized,
// unparseable, wrong scheme). Everything discovered during the walk — a refused
// destination, a TLS failure, a loop, a bot wall — comes back as a *Chain with
// notes, because those are findings about the URL and the page's whole job is
// showing them. Only a nil *Tracer returns ErrDisabled.
func (t *Tracer) Trace(ctx context.Context, raw string, persona string) (ch *Chain, err error) {
	if t == nil {
		return nil, ErrDisabled
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("no URL given")
	}
	if len(raw) > maxInput {
		return nil, fmt.Errorf("URL is %d bytes; the limit is %d", len(raw), maxInput)
	}
	p := personaFor(persona)
	cur, startNotes, err := parseTarget(raw)
	if err != nil {
		return nil, err
	}

	// Total wall clock. Each hop takes its own 5s slice out of this, so a chain
	// of slow-but-not-timing-out hops still ends on schedule (doc §3).
	ctx, cancel := context.WithTimeout(ctx, t.total)
	defer cancel()

	ch = &Chain{Input: raw, Persona: p.Key, Notes: startNotes}
	began := time.Now()
	defer func() { ch.Elapsed = time.Since(began).Milliseconds() }()

	seen := map[string]bool{}
	for {
		if len(ch.Hops) >= maxHops {
			ch.Notes = append(ch.Notes, Note{SevWarn, fmt.Sprintf("Stopped after %d hops", maxHops),
				"The chain was still going. Every legitimate redirect chain is far shorter than this, so it is either a loop or something is generating hops deliberately."})
			return ch, nil
		}
		seen[cur.String()] = true

		hop := Hop{Index: len(ch.Hops) + 1, URL: cur.String()}
		// The gate runs in two places because a dialer hook only fires when a
		// dial happens (doc §2(b)). This is the second place: scheme, host and
		// port are judged here, above the transport, before anything is sent.
		if err := t.check(cur); err != nil {
			hop.Notes = append(hop.Notes, Note{SevFail, "Refused before connecting", refusalDetail(err)})
			ch.Hops = append(ch.Hops, hop)
			return ch, nil
		}

		loc := t.step(ctx, &hop, cur, p)
		ch.Hops = append(ch.Hops, hop)
		if loc == "" {
			// Terminal hop. step has already attached whatever it found; Final
			// stays empty when the chain plainly continues elsewhere.
			if !continuesElsewhere(hop.Notes) {
				ch.Final = hop.URL
			}
			return ch, nil
		}

		next, note := resolveNext(cur, loc)
		if note != nil {
			ch.Notes = append(ch.Notes, *note)
			return ch, nil
		}
		// An https -> http step is flagged, not taken silently: from here on the
		// chain, and anything in the URL, is on the wire in clear (doc §2 rule 5).
		if strings.EqualFold(cur.Scheme, "https") && strings.EqualFold(next.Scheme, "http") {
			ch.Notes = append(ch.Notes, Note{SevWarn, "HTTPS downgraded to HTTP",
				fmt.Sprintf("Hop %d left HTTPS for plain HTTP. Everything from here, including anything carried in the URL, travels unencrypted.", hop.Index)})
		}
		if seen[next.String()] {
			ch.Notes = append(ch.Notes, Note{SevFail, "Redirect loop",
				fmt.Sprintf("The chain returns to %s, which it already visited. It does not terminate.", next.String())})
			return ch, nil
		}
		cur = next
	}
}

// step performs one hop, fills in the response fields and notes, and returns
// the Location to follow — empty when the chain ends here.
func (t *Tracer) step(ctx context.Context, hop *Hop, u *url.URL, p Persona) string {
	// Per-hop deadline, inside the total. Cancelled only after the body has
	// been read, since cancelling the context kills the body reader too.
	hopCtx, cancel := context.WithTimeout(ctx, hopTimeout)
	defer cancel()
	began := time.Now()
	defer func() { hop.ElapsedMS = time.Since(began).Milliseconds() }()

	// GET, not HEAD: too many servers answer HEAD differently, or not at all,
	// and a redirect chain measured with HEAD is not the chain a browser walks
	// (doc §3). The body is closed unread unless this hop ends the chain.
	req, err := http.NewRequestWithContext(hopCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		hop.Notes = append(hop.Notes, Note{SevFail, "Could not build the request", err.Error()})
		return ""
	}
	// Headers are BUILT FRESH from a fixed allowlist on every hop, never
	// carried forward (doc §2). In particular:
	//   - no Referer. Go's own client sets one on redirects it follows; a
	//     hand-rolled walk that copies headers forward would hand the pasted
	//     URL, tokens and all, to every subsequent attacker-chosen host.
	//   - no Authorization, on any hop, to any host. There is nothing to
	//     "drop on the first cross-host hop" because it is never set, and
	//     parseTarget stripped userinfo so net/http cannot derive one either.
	req.Header = http.Header{
		"User-Agent": {p.UA},
		"Accept":     {traceAccept},
	}

	resp, err := t.client.Do(req)
	if err != nil {
		hop.Notes = append(hop.Notes, transportNote(ctx, err))
		return ""
	}
	defer resp.Body.Close()

	hop.Status = resp.StatusCode
	hop.Server = resp.Header.Get("Server")
	hop.ContentType = resp.Header.Get("Content-Type")
	// Recorded, never kept: this is the per-hop cookie marker, not a jar.
	hop.SetCookie = len(resp.Header.Values("Set-Cookie")) > 0

	if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		hop.Location = loc
		return loc
	}

	// The chain ends at this hop, so this is the one place a body is read —
	// capped, and only when it could carry a redirect we would otherwise miss.
	var body []byte
	if wantsBody(hop.ContentType, resp.StatusCode) {
		body, _ = io.ReadAll(io.LimitReader(resp.Body, maxBodyScan))
	}
	t.explain(hop, resp, body, p)
	return ""
}

// explain attaches the findings that make a terminal hop readable: the two
// refresh mechanisms, the JavaScript redirect we cannot follow, and a refusal
// that is not a dead link.
func (t *Tracer) explain(hop *Hop, resp *http.Response, body []byte, p Persona) {
	// The Refresh HTTP HEADER, not only the <meta> tag. It is widely honoured
	// and easy to miss, and answering "chain complete" on a 200 that carries
	// `Refresh: 0;url=...` is wrong in the security-relevant direction
	// (doc §9). Named, never followed.
	if target, ok := parseRefresh(resp.Header.Get("Refresh")); ok {
		hop.Notes = append(hop.Notes, Note{SevWarn, "Refresh header, not a redirect",
			fmt.Sprintf("This response is %d, but it carries a Refresh header pointing at %s. Browsers honour it, so the chain does not end here. We name it rather than following it.", hop.Status, absolute(hop.URL, target))})
	} else if resp.Header.Get("Refresh") != "" {
		hop.Notes = append(hop.Notes, Note{SevWarn, "Refresh header, not a redirect",
			"This response carries a Refresh header with no target, which reloads this same URL. The chain does not settle here."})
	}

	if target, ok := metaRefresh(body); ok {
		detail := "This page meta-refreshes to " + absolute(hop.URL, target) + ". It is a redirect a browser follows and an HTTP client does not, so the chain does not end here."
		if target == "" {
			detail = "This page carries a <meta http-equiv=\"refresh\"> with no target, which reloads itself."
		}
		hop.Notes = append(hop.Notes, Note{SevWarn, "Meta refresh, not a redirect", detail})
	}

	// JavaScript redirects need a JS engine, which this tool deliberately does
	// not have (docs/02-build-fit.md §5). Detect and NAME it; never present the
	// pre-redirect URL as the destination.
	if what, ok := jsRedirect(body); ok {
		hop.Notes = append(hop.Notes, Note{SevWarn, "JavaScript redirect, which we cannot follow",
			fmt.Sprintf("The page runs %s. Following it needs a browser; this is an HTTP client, so the real destination is unknown rather than this URL.", what)})
	}

	switch {
	case hop.Status == http.StatusTooManyRequests:
		hop.Notes = append(hop.Notes, Note{SevWarn, "The target rate-limited this request",
			"HTTP 429. The link is not dead; the server declined to answer this client right now."})
	case hop.Status == http.StatusForbidden || hop.Status == http.StatusServiceUnavailable ||
		hop.Status == http.StatusUnauthorized:
		detail := fmt.Sprintf("HTTP %d to an automated request from a datacentre address. That reads as the target refusing us, not as a dead link.", hop.Status)
		if vendor, ok := botWall(resp.Header, body); ok {
			detail = fmt.Sprintf("HTTP %d with %s. That is bot protection turning away an automated client, not evidence that the link is broken.", hop.Status, vendor)
		}
		if p.Key == personas[0].Key {
			detail += " Re-running as Googlebot or Slackbot shows whether the target discriminates by user agent."
		} else {
			detail += fmt.Sprintf(" This run presented as %s.", p.Name)
		}
		hop.Notes = append(hop.Notes, Note{SevWarn, "The target refused an automated request", detail})
	}
}

// check enforces scheme, host and port above the transport.
//
// Not redundant with the dialer gate: a Control hook only fires on a real dial
// (doc §2(b)), and checking here also turns a refusal into a stated finding
// instead of an opaque dial error.
func (t *Tracer) check(u *url.URL) error {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("%w: scheme %q is not http or https", platform.ErrBlockedAddress, u.Scheme)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = defaultPorts[scheme]
	}
	if t.allowLoopback && isLoopbackHost(host) {
		return nil
	}
	if err := t.guard.AllowHost(host); err != nil {
		return err
	}
	// 80 and 443 only. This is a first-class control, not an anti-scanning
	// nicety: a source-IP-allowlisted service on a public address (the Mongo
	// host) passes the routable check and would be dialled from the one source
	// IP its firewall trusts. Doc §2(c), and threat #13 on the Hetzner account.
	return t.guard.AllowPort(port)
}

// parseTarget turns the pasted string into a URL we are willing to start from.
func parseTarget(raw string) (*url.URL, []Note, error) {
	var notes []Note
	u, err := url.Parse(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("not a URL: %w", err)
	}
	if !strings.Contains(raw, "://") && !isHTTPScheme(u.Scheme) {
		// "example.com/x" is what people paste. Assume https and say so,
		// rather than refusing on a technicality.
		if u2, err2 := url.Parse("https://" + raw); err2 == nil && u2.Host != "" {
			u = u2
			notes = append(notes, Note{SevInfo, "No scheme given", "Traced as https://" + raw + "."})
		}
	}
	if !isHTTPScheme(u.Scheme) {
		return nil, nil, fmt.Errorf("only http and https can be traced; this is %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, nil, fmt.Errorf("no host to trace")
	}
	if stripUserinfo(u) {
		notes = append(notes, Note{SevWarn, "Credentials in the URL were dropped",
			"Everything before the @ was removed before fetching. It is a username, not the destination, and net/http would otherwise have turned it into an Authorization header sent to the host that follows."})
	}
	return u, notes, nil
}

// resolveNext resolves a Location against the URL that issued it, returning a
// note instead when the chain ends there.
func resolveNext(cur *url.URL, loc string) (*url.URL, *Note) {
	if len(loc) > maxLocation {
		return nil, &Note{SevFail, "Location header is too long",
			fmt.Sprintf("%d bytes; the limit is %d. Not resolved.", len(loc), maxLocation)}
	}
	// url.Parse, NOT url.ParseRequestURI: the latter reads the
	// protocol-relative "//evil.tld/x" as a PATH, leaving Host empty and
	// returning no error, so a naive check sees a same-host relative redirect
	// where a browser sees a jump to evil.tld. ResolveReference then applies
	// RFC 3986 §5 properly for relative, absolute and protocol-relative forms
	// alike (doc §2 rule 1).
	ref, err := url.Parse(strings.TrimSpace(loc))
	if err != nil {
		return nil, &Note{SevFail, "Location header is not a URL",
			fmt.Sprintf("%v. The chain cannot be followed past here.", err)}
	}
	next := cur.ResolveReference(ref)
	if !isHTTPScheme(next.Scheme) {
		return nil, &Note{SevWarn, "Chain ends at a non-HTTP scheme",
			fmt.Sprintf("The last hop redirects to a %q URL, which is handed to an app or the browser rather than fetched. It is shown as text and was not followed.", next.Scheme)}
	}
	if next.Host == "" {
		return nil, &Note{SevFail, "Location header has no host", "The redirect target could not be resolved to an absolute URL."}
	}
	stripUserinfo(next)
	return next, nil
}

// transportNote turns a client error into something a reader can act on. A TLS
// failure in particular is a finding, never a reason to retry over http.
func transportNote(ctx context.Context, err error) Note {
	switch {
	case errors.Is(err, platform.ErrBlockedAddress), errors.Is(err, platform.ErrBlockedPort):
		return Note{SevFail, "Refused before connecting", refusalDetail(err)}
	case ctx.Err() != nil:
		return Note{SevFail, "Ran out of time",
			"The total time budget for the whole chain was used up before this hop answered."}
	case errors.Is(err, context.DeadlineExceeded):
		return Note{SevFail, "This hop timed out",
			fmt.Sprintf("No response within %s. The chain stops here; it is not finished.", hopTimeout)}
	}
	var certErr *tls.CertificateVerificationError
	var hostErr x509.HostnameError
	var authErr x509.UnknownAuthorityError
	var invErr x509.CertificateInvalidError
	var recErr tls.RecordHeaderError
	if errors.As(err, &certErr) || errors.As(err, &hostErr) || errors.As(err, &authErr) ||
		errors.As(err, &invErr) || errors.As(err, &recErr) {
		return Note{SevFail, "TLS verification failed",
			fmt.Sprintf("%v. This is the finding, not an obstacle: the trace stops rather than retrying over plain HTTP or ignoring the certificate.", err)}
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return Note{SevFail, "The host does not resolve",
			fmt.Sprintf("DNS lookup for %s failed. The chain stops here.", dnsErr.Name)}
	}
	return Note{SevFail, "The request failed", err.Error()}
}

// refusalDetail states a gate refusal in the reader's terms. The underlying
// error names the address or port, which is exactly what a person checking a
// suspicious link wants to see.
func refusalDetail(err error) string {
	switch {
	case errors.Is(err, platform.ErrBlockedPort):
		return fmt.Sprintf("%v. Only ports 80 and 443 are ever dialled, so this tool cannot be pointed at anything else.", err)
	case errors.Is(err, platform.ErrBlockedAddress):
		return fmt.Sprintf("%v. Private, loopback, link-local and reserved addresses, this service's own hosts, and anything not publicly routable are all refused.", err)
	}
	return err.Error()
}

// continuesElsewhere reports whether a terminal hop's notes say the chain does
// not actually settle here — the condition for leaving Chain.Final empty.
func continuesElsewhere(notes []Note) bool {
	for _, n := range notes {
		switch n.Title {
		case "Refresh header, not a redirect", "Meta refresh, not a redirect",
			"JavaScript redirect, which we cannot follow", "Refused before connecting",
			"TLS verification failed", "The host does not resolve", "This hop timed out",
			"Ran out of time", "The request failed", "Could not build the request":
			return true
		}
	}
	return false
}

// wantsBody decides whether this terminal hop's body is worth the 64 KB. HTML
// and an absent Content-Type can carry a refresh or a redirect script; a
// refusal page is worth reading whatever it claims to be.
func wantsBody(contentType string, status int) bool {
	if status == http.StatusForbidden || status == http.StatusServiceUnavailable ||
		status == http.StatusUnauthorized || status == http.StatusTooManyRequests {
		return true
	}
	ct := strings.ToLower(strings.TrimSpace(contentType))
	return ct == "" || strings.HasPrefix(ct, "text/html") || strings.HasPrefix(ct, "application/xhtml")
}

// metaRefresh finds <meta http-equiv="refresh"> in the head.
//
// Tokenised rather than regexped: the input is attacker-controlled markup, and
// x/net/html is already a direct dependency. Stops at <body>, so a 64 KB scan
// is bounded by the head in practice.
func metaRefresh(body []byte) (string, bool) {
	if len(body) == 0 {
		return "", false
	}
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		switch z.Next() {
		case html.ErrorToken:
			return "", false
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			switch string(name) {
			case "body":
				return "", false
			case "meta":
			default:
				continue
			}
			var equiv, content string
			for hasAttr {
				var k, v []byte
				k, v, hasAttr = z.TagAttr()
				switch strings.ToLower(string(k)) {
				case "http-equiv":
					equiv = strings.ToLower(strings.TrimSpace(string(v)))
				case "content":
					content = string(v)
				}
			}
			if equiv == "refresh" {
				target, _ := parseRefresh(content)
				return target, true
			}
		}
	}
}

// parseRefresh reads the "5; url=..." form shared by the Refresh header and the
// meta tag. Returns false when there is no target, which is a self-reload.
func parseRefresh(v string) (string, bool) {
	if v == "" {
		return "", false
	}
	_, rest, ok := strings.Cut(v, ";")
	if !ok {
		return "", false
	}
	rest = strings.TrimSpace(rest)
	if len(rest) < 3 || !strings.EqualFold(rest[:3], "url") {
		return "", false
	}
	rest = strings.TrimSpace(rest[3:])
	rest, ok = strings.CutPrefix(rest, "=")
	if !ok {
		return "", false
	}
	rest = strings.Trim(strings.TrimSpace(rest), `"'`)
	if rest == "" || len(rest) > maxLocation {
		return "", false
	}
	return rest, true
}

// jsRedirectTargets: the objects a navigation is assigned to.
var jsRedirectTargets = []string{"location.href", "window.location", "document.location",
	"top.location", "self.location", "parent.location"}

// jsRedirect heuristically spots a navigation performed by script, returning
// the construct found.
//
// Heuristic on purpose, and the note says so: a call is unambiguous, an
// assignment less so, and ordinary page script does touch location. Being
// slightly over-eager is the right failure direction here, because the cost of
// a false positive is a hedge on the page and the cost of a false negative is
// reporting a redirect shim's own URL as the destination.
func jsRedirect(body []byte) (string, bool) {
	if len(body) == 0 {
		return "", false
	}
	s := strings.ToLower(string(body))
	for _, call := range []string{"location.replace(", "location.assign("} {
		if strings.Contains(s, call) {
			return call + "...)", true
		}
	}
	for _, target := range jsRedirectTargets {
		if assignedTo(s, target) {
			return target + " = ...", true
		}
	}
	return "", false
}

// assignedTo reports whether needle is followed by a single '=', i.e. an
// assignment rather than a comparison.
func assignedTo(s, needle string) bool {
	for i := 0; i < len(s); {
		j := strings.Index(s[i:], needle)
		if j < 0 {
			return false
		}
		k := i + j + len(needle)
		i = k
		for k < len(s) && (s[k] == ' ' || s[k] == '\t' || s[k] == '\n' || s[k] == '\r') {
			k++
		}
		if k < len(s) && s[k] == '=' && (k+1 >= len(s) || s[k+1] != '=') {
			return true
		}
	}
	return false
}

// botWallHeaders: response headers only a bot-protection edge emits.
var botWallHeaders = map[string]string{
	"cf-mitigated":          "Cloudflare",
	"cf-ray":                "Cloudflare",
	"x-datadome":            "DataDome",
	"x-datadome-cid":        "DataDome",
	"x-iinfo":               "Imperva",
	"x-sucuri-id":           "Sucuri",
	"x-akamai-transformed":  "Akamai",
	"x-amz-cf-id":           "CloudFront",
	"x-perimeterx-blocking": "PerimeterX",
}

// botWallCookies / botWallBody: the second and third tells, for edges that do
// not announce themselves in a header.
var botWallCookies = map[string]string{
	"__cf_bm": "Cloudflare", "cf_clearance": "Cloudflare", "datadome": "DataDome",
	"incap_ses": "Imperva", "visid_incap": "Imperva", "reese84": "Imperva",
	"ak_bmsc": "Akamai", "_px": "PerimeterX",
}

var botWallBody = map[string]string{
	"just a moment":                 "Cloudflare's interstitial",
	"attention required":            "Cloudflare's block page",
	"cf-browser-verification":       "Cloudflare's browser check",
	"checking your browser":         "a browser check",
	"enable javascript and cookies": "a JavaScript and cookie check",
	"captcha":                       "a CAPTCHA",
	"verify you are human":          "a human-verification page",
	"request unsuccessful":          "an Imperva block page",
	"access denied":                 "an access-denied page",
}

// botWall names the bot-protection product behind a refusal, when it can.
//
// The point is the framing, not the attribution: a 403 or 503 here means the
// target declined to answer an automated request from a datacentre address
// (docs/02-build-fit.md §5). Reporting that as a dead link is a wrong answer.
func botWall(h http.Header, body []byte) (string, bool) {
	for name, vendor := range botWallHeaders {
		if h.Get(name) != "" {
			return vendor, true
		}
	}
	if srv := strings.ToLower(h.Get("Server")); srv != "" {
		for _, vendor := range []string{"cloudflare", "akamai", "imperva", "sucuri", "datadome"} {
			if strings.Contains(srv, vendor) {
				return strings.ToUpper(vendor[:1]) + vendor[1:], true
			}
		}
	}
	for _, c := range h.Values("Set-Cookie") {
		lc := strings.ToLower(c)
		for prefix, vendor := range botWallCookies {
			if strings.HasPrefix(lc, prefix) {
				return vendor, true
			}
		}
	}
	if len(body) > 0 {
		lb := strings.ToLower(string(body))
		for needle, what := range botWallBody {
			if strings.Contains(lb, needle) {
				return what, true
			}
		}
	}
	return "", false
}

// absolute resolves a refresh target against the hop that carried it, so the
// note names a whole URL rather than "/d". Falls back to the raw text: this
// feeds a note, never a fetch, so an unresolvable target is shown as written.
func absolute(base, target string) string {
	if target == "" {
		return target
	}
	b, err := url.Parse(base)
	if err != nil {
		return target
	}
	ref, err := url.Parse(strings.TrimSpace(target))
	if err != nil {
		return target
	}
	return b.ResolveReference(ref).String()
}

func isHTTPScheme(s string) bool {
	s = strings.ToLower(s)
	return s == "http" || s == "https"
}

// stripUserinfo removes credentials from a URL before it is fetched or shown,
// reporting whether there were any.
//
// Two reasons, both load-bearing: net/http's send() turns URL userinfo into a
// Basic Authorization header, which doc §2 rule 3 forbids outright; and a
// password must never be echoed back into the page (doc §8).
func stripUserinfo(u *url.URL) bool {
	if u.User == nil {
		return false
	}
	u.User = nil
	return true
}

// isLoopbackHost backs the test seam only. It is not part of the egress
// decision: the gate in platform/netgate.go is, and this never widens it except
// when allowLoopback has been set from inside this package's own tests.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Unmap().IsLoopback()
}
