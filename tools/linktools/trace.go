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

// This route fetches a URL a stranger chose, so every cost of one trace is bounded here.
const (
	maxHops = 10 // above every legitimate chain
	// hopTimeout also bounds dial, TLS and headers: ten slow hops would be a slowloris aimed at us.
	hopTimeout = 5 * time.Second
	// totalTimeout is the fallback wall clock when NewTracer is given none.
	totalTimeout = 15 * time.Second
	maxLocation  = 2048
	// maxHeaderValue, maxErrorText bound target-chosen text a hop or note quotes.
	maxHeaderValue = 256
	maxErrorText   = 300
	// maxHeaderBytes: Go's 10 MB default times hops, burst and IPs is a free bandwidth amplifier.
	maxHeaderBytes = 64 << 10
	// maxBodyScan: the only body bytes ever read, on the final hop, for refresh and JS redirects.
	maxBodyScan = 64 << 10
)

// traceAccept is fixed, never taken from the caller: the header set is an allowlist.
const traceAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

type Chain struct {
	Input string `json:"input"`
	Hops  []Hop  `json:"hops,omitempty"`
	// Final is the last URL actually reached, empty whenever the chain demonstrably continues
	// unfollowed (JS, refresh, loop, refusal): a pre-redirect URL as destination is the dangerous answer.
	Final string `json:"final,omitempty"`
	// FinalStatus is the status Final answered with: a 404 is still where it ends.
	FinalStatus int    `json:"final_status,omitempty"`
	FinalReason string `json:"-"`
	Notes       []Note `json:"notes,omitempty"`
	Persona     string `json:"persona,omitempty"`
	Elapsed     int64  `json:"elapsed_ms"`
}

// Hop is one request/response pair in the chain.
type Hop struct {
	Index  int    `json:"index"`
	URL    string `json:"url"`
	Status int    `json:"status"`
	// Reason is the status code's standard name ("Moved Permanently").
	Reason   string `json:"reason,omitempty"`
	Location string `json:"location,omitempty"`
	// ElapsedMS covers the whole hop: dial, TLS, request, response headers.
	ElapsedMS int64 `json:"elapsed_ms"`
	// SetCookie is a bool on purpose: the value is never read, stored or sent; there is no cookie jar.
	SetCookie   bool   `json:"set_cookie,omitempty"`
	Server      string `json:"server,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Notes       []Note `json:"notes,omitempty"`
}

// Persona exists so a target that refuses browsers but serves Googlebot isn't called a dead link.
type Persona struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	UA   string `json:"ua"`
}

// personas, default first: only agents whose answer actually differs in practice.
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

// Personas returns a copy, so a caller can't reorder or rewrite the table it renders from.
func Personas() []Persona { return append([]Persona(nil), personas...) }

// lookupPersona is the one lookup curl and Trace share, so both claim the same agent for a key.
func lookupPersona(key string) (Persona, bool) {
	key = strings.TrimSpace(key)
	for _, p := range personas {
		if strings.EqualFold(p.Key, key) {
			return p, true
		}
	}
	return Persona{}, false
}

// personaFor falls back to the default for an unknown key: a bad ?ua= is not worth a 400.
func personaFor(key string) Persona {
	if p, ok := lookupPersona(key); ok {
		return p
	}
	return personas[0]
}

// Tracer is nil-safe (nil means off, 503) and a pointer: a nil inside an interface isn't == nil.
type Tracer struct {
	guard *platform.EgressGuard
	// gated checks the literal address in Dialer.Control, leaving no window for DNS rebinding.
	gated  func(context.Context, string, string) (net.Conn, error)
	client *http.Client
	total  time.Duration

	// allowLoopback is a test-only seam (httptest serves loopback), per-instance so it needs no mutex.
	allowLoopback bool
	// direct is ungated, reachable only with allowLoopback set and a loopback address.
	direct *net.Dialer
}

// NewTracer's timeout covers the whole chain. A nil guard turns it off: the guard is the SSRF defence.
func NewTracer(guard *platform.EgressGuard, timeout time.Duration) *Tracer {
	if guard == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = totalTimeout
	}
	tr := guard.Transport(hopTimeout)
	t := &Tracer{
		guard:  guard,
		gated:  tr.DialContext,
		total:  timeout,
		direct: &net.Dialer{Timeout: hopTimeout},
	}
	tr.DialContext = t.dialContext
	// No HTTP/2: it coalesces authorities onto one connection, bypassing the guard's dial.
	tr.ForceAttemptHTTP2 = false
	tr.MaxResponseHeaderBytes = maxHeaderBytes
	tr.ResponseHeaderTimeout = hopTimeout
	tr.TLSHandshakeTimeout = hopTimeout
	tr.ExpectContinueTimeout = time.Second
	// Never InsecureSkipVerify: a certificate failure is a finding we report.
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	t.client = &http.Client{
		// Walk by hand, so every hop is a fresh gated dial and gets recorded.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		// No cookie jar, ever; explicit so a later tidy-up has to delete a commented line.
		Jar: nil,
		// Each hop's context has its own timeout and the caller's carries the total.
		Timeout:   0,
		Transport: tr,
	}
	return t
}

// dialContext gates every dial; the loopback branch is the test seam, dead in production.
func (t *Tracer) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if t.allowLoopback {
		if host, _, err := net.SplitHostPort(address); err == nil && isLoopbackHost(host) {
			return t.direct.DialContext(ctx, network, address)
		}
	}
	return t.gated(ctx, network, address)
}

// Trace errors only on untraceable input; anything found on the walk is a note on the Chain.
func (t *Tracer) Trace(ctx context.Context, raw string, persona string) (ch *Chain, err error) {
	if t == nil {
		return nil, ErrDisabled
	}
	raw, err = readURL(raw)
	if err != nil {
		return nil, err
	}
	p := personaFor(persona)
	cur, startNotes, err := parseTarget(raw)
	if err != nil {
		return nil, err
	}

	// Each hop's slice comes out of this, so slow-but-alive hops still end on schedule.
	ctx, cancel := context.WithTimeout(ctx, t.total)
	defer cancel()

	ch = &Chain{Input: raw, Persona: p.Key, Notes: startNotes}
	began := time.Now()
	defer func() { ch.Elapsed = time.Since(began).Milliseconds() }()
	defer ch.liftLastHop()

	seen := map[string]bool{}
	for {
		if len(ch.Hops) >= maxHops {
			ch.Notes = append(ch.Notes, Note{SevWarn, fmt.Sprintf("Stopped after %d hops", maxHops),
				"The chain was still going. Every legitimate redirect chain is far shorter than this, so it is either a loop or something is generating hops deliberately."})
			return ch, nil
		}
		seen[cur.String()] = true

		hop := Hop{Index: len(ch.Hops) + 1, URL: cur.String()}
		// A dialer hook only fires on a dial, so scheme, host and port are judged here first too.
		if err := t.check(cur); err != nil {
			hop.Notes = append(hop.Notes, Note{SevFail, "Refused before connecting", refusalDetail(err)})
			ch.Hops = append(ch.Hops, hop)
			return ch, nil
		}

		loc := t.step(ctx, &hop, cur, p)
		ch.Hops = append(ch.Hops, hop)
		if loc == "" {
			if !continuesElsewhere(hop.Notes) {
				ch.Final, ch.FinalStatus, ch.FinalReason = hop.URL, hop.Status, hop.Reason
			}
			return ch, nil
		}

		next, note := resolveNext(cur, loc)
		if note != nil {
			ch.Notes = append(ch.Notes, *note)
			return ch, nil
		}
		// Flagged, not taken silently: from here on the URL travels in clear.
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

// liftLastHop promotes the last hop's warnings to findings and flags a chain ending at an error page.
func (ch *Chain) liftLastHop() {
	if ch == nil || len(ch.Hops) == 0 {
		return
	}
	last := ch.Hops[len(ch.Hops)-1]
	lifted := false
	for _, n := range last.Notes {
		if n.Severity != SevFail && n.Severity != SevWarn {
			continue
		}
		lifted = true
		dup := false
		for _, have := range ch.Notes {
			dup = dup || have.Title == n.Title
		}
		if !dup {
			ch.Notes = append(ch.Notes, n)
		}
	}
	if lifted || ch.Final == "" || ch.FinalStatus < 400 {
		return
	}
	status := strings.TrimSpace(fmt.Sprintf("%d %s", ch.FinalStatus, ch.FinalReason))
	if ch.FinalStatus >= 500 {
		ch.Notes = append(ch.Notes, Note{SevWarn, "Ends at a server error",
			"The last page answered " + status + ". The site may be down for now: try again later."})
		return
	}
	ch.Notes = append(ch.Notes, Note{SevWarn, "Ends at an error page",
		"The last page answered " + status + ": the link is broken, or the site turns this kind of visitor away. Asking as someone else tells the two apart."})
}

// Unlisted is the hop's notes not already among findings, by title.
func (h Hop) Unlisted(findings []Note) []Note {
	var out []Note
	for _, n := range h.Notes {
		listed := false
		for _, f := range findings {
			listed = listed || f.Title == n.Title
		}
		if !listed {
			out = append(out, n)
		}
	}
	return out
}

// step performs one hop and returns the Location to follow, empty when the chain ends here.
func (t *Tracer) step(ctx context.Context, hop *Hop, u *url.URL, p Persona) string {
	// Cancelled only after the body is read: cancelling the context kills the body reader too.
	hopCtx, cancel := context.WithTimeout(ctx, hopTimeout)
	defer cancel()
	began := time.Now()
	defer func() { hop.ElapsedMS = time.Since(began).Milliseconds() }()

	// GET, not HEAD: servers answer HEAD differently or not at all, so it isn't the browser's chain.
	req, err := http.NewRequestWithContext(hopCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		hop.Notes = append(hop.Notes, Note{SevFail, "Could not build the request", err.Error()})
		return ""
	}
	// Built fresh from an allowlist every hop: no Referer (it would hand the pasted URL to every later
	// host) and no Authorization (parseTarget stripped userinfo, so net/http can't derive one).
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
	hop.Reason = http.StatusText(resp.StatusCode)
	hop.Server = platform.Clip(resp.Header.Get("Server"), maxHeaderValue)
	hop.ContentType = platform.Clip(resp.Header.Get("Content-Type"), maxHeaderValue)
	// Recorded, never kept: this is the per-hop cookie marker, not a jar.
	hop.SetCookie = len(resp.Header.Values("Set-Cookie")) > 0

	if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		hop.Location = platform.Clip(loc, maxLocation)
		return loc
	}

	// The only body ever read: capped, on the final hop, when it could carry a missed redirect.
	var body []byte
	if wantsBody(hop.ContentType, resp.StatusCode) {
		body, _ = io.ReadAll(io.LimitReader(resp.Body, maxBodyScan))
	}
	t.explain(hop, resp, body, p)
	return ""
}

// explain names what a terminal hop hides: refreshes, JS redirects, refusals that aren't dead links.
func (t *Tracer) explain(hop *Hop, resp *http.Response, body []byte, p Persona) {
	// The Refresh header too, not just <meta>: easy to miss, and browsers honour it. Named, never followed.
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

	// No JS engine by design: name the redirect, never present this URL as the destination.
	if what, ok := jsRedirect(body); ok {
		hop.Notes = append(hop.Notes, Note{SevWarn, "JavaScript redirect, not followed",
			fmt.Sprintf("The page runs %s. Following it needs a browser, so the real destination is unknown: it is not this URL.", what)})
	}

	switch {
	case hop.Status == http.StatusTooManyRequests:
		hop.Notes = append(hop.Notes, Note{SevWarn, "The target rate-limited this request",
			"HTTP 429. The link is not dead; the server declined to answer this client right now."})
	case hop.Status == http.StatusForbidden || hop.Status == http.StatusServiceUnavailable ||
		hop.Status == http.StatusUnauthorized:
		detail := fmt.Sprintf("HTTP %d to an automated request from a datacentre address. That reads as a refusal, not a dead link.", hop.Status)
		if vendor, ok := botWall(resp.Header, body); ok {
			detail = fmt.Sprintf("HTTP %d with %s. That is bot protection turning away an automated client, not evidence that the link is broken.", hop.Status, vendor)
		}
		if p.Key == personas[0].Key {
			detail += " Re-running as Googlebot or Slackbot shows whether the target discriminates by user agent."
		} else {
			detail += fmt.Sprintf(" This run asked as %s.", p.Name)
		}
		hop.Notes = append(hop.Notes, Note{SevWarn, "The target refused an automated request", detail})
	}
}

// check isn't redundant with the dialer gate: that fires only on a dial, and this states the refusal.
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
	// 80/443 only: an IP-allowlisted public service (the Mongo host) would otherwise trust our dial.
	return t.guard.AllowPort(port)
}

// parseTarget turns the pasted string into a URL we are willing to start from.
func parseTarget(raw string) (*url.URL, []Note, error) {
	var notes []Note
	u, err := url.Parse(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("not a valid URL: %w", parseReason(err))
	}
	if !strings.Contains(raw, "://") && !isHTTPScheme(u.Scheme) {
		// "example.com/x" is what people paste: assume https and say so.
		if u2, err2 := url.Parse("https://" + raw); err2 == nil && u2.Host != "" {
			u = u2
			notes = append(notes, Note{SevInfo, "No scheme", "Traced as https://" + raw + "."})
		}
	}
	if u.Scheme == "" {
		return nil, nil, fmt.Errorf("not a whole link: paste all of it, starting with http:// or https://")
	}
	if !isHTTPScheme(u.Scheme) {
		return nil, nil, fmt.Errorf("trace only follows http and https links, and this one is %s", u.Scheme)
	}
	if u.Host == "" {
		return nil, nil, fmt.Errorf("no host to trace")
	}
	if stripUserinfo(u) {
		notes = append(notes, Note{SevWarn, "Credentials in the URL were dropped",
			"Everything before the @ was removed before fetching: it is a username, not the destination, and sending it would hand it to that host as a login."})
	}
	return u, notes, nil
}

// resolveNext returns a note instead of a URL when the chain ends at loc.
func resolveNext(cur *url.URL, loc string) (*url.URL, *Note) {
	if len(loc) > maxLocation {
		return nil, &Note{SevFail, "Location header is too long",
			fmt.Sprintf("%d bytes; the limit is %d. Not resolved.", len(loc), maxLocation)}
	}
	// url.Parse, NOT url.ParseRequestURI: the latter reads "//evil.tld/x" as a path with no host,
	// so a check would see a same-host redirect where a browser jumps to evil.tld.
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

// transportNote: a TLS failure is a finding, never a reason to retry over http.
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
			clipCause(err) + ". This is the finding, not an obstacle: the trace stops rather than retrying over plain HTTP or ignoring the certificate."}
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return Note{SevFail, "The host does not resolve",
			fmt.Sprintf("DNS lookup for %s failed. The chain stops here.", dnsErr.Name)}
	}
	return Note{SevFail, "The request failed", clipCause(err)}
}

// clipCause clips only the target's text, not net/http's `Get "<hop URL>": ` prefix.
func clipCause(err error) string {
	msg := err.Error()
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		if cause := ue.Err.Error(); strings.HasSuffix(msg, cause) {
			return msg[:len(msg)-len(cause)] + platform.Clip(cause, maxErrorText)
		}
	}
	return platform.Clip(msg, maxErrorText)
}

// refusalDetail states a gate refusal in the reader's terms, naming the address or port.
func refusalDetail(err error) string {
	switch {
	case errors.Is(err, platform.ErrBlockedPort):
		return "Port " + afterColon(err) + " isn't allowed. Trace only connects to ports 80 and 443."
	case errors.Is(err, platform.ErrBlockedAddress):
		return afterColon(err) + " isn't on the public internet (not publicly routable), so Trace won't contact it. Private, loopback and reserved addresses, and this site's own hosts, are always refused."
	}
	return err.Error()
}

// afterColon is the port or address an egress-guard error names.
func afterColon(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 {
		return msg[i+2:]
	}
	return "That address"
}

// continuesElsewhere: the terminal hop's notes say the chain doesn't settle, so Final stays empty.
func continuesElsewhere(notes []Note) bool {
	for _, n := range notes {
		switch n.Title {
		case "Refresh header, not a redirect", "Meta refresh, not a redirect",
			"JavaScript redirect, not followed", "Refused before connecting",
			"TLS verification failed", "The host does not resolve", "This hop timed out",
			"Ran out of time", "The request failed", "Could not build the request":
			return true
		}
	}
	return false
}

// wantsBody: HTML or no Content-Type may hide a redirect; a refusal page is worth reading regardless.
func wantsBody(contentType string, status int) bool {
	if status == http.StatusForbidden || status == http.StatusServiceUnavailable ||
		status == http.StatusUnauthorized || status == http.StatusTooManyRequests {
		return true
	}
	ct := strings.ToLower(strings.TrimSpace(contentType))
	return ct == "" || strings.HasPrefix(ct, "text/html") || strings.HasPrefix(ct, "application/xhtml")
}

// metaRefresh tokenises (the markup is hostile) and stops at <body>, so the scan is bounded by the head.
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

// parseRefresh reads "5; url=..."; false when there is no target, which is a self-reload.
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

// jsRedirect is a heuristic that errs eager: missing one would name a shim as the destination.
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

// assignedTo: needle followed by a single '=', an assignment rather than a comparison.
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

// botWallCookies and botWallBody catch edges that don't announce themselves in a header.
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

// botWall names the product behind a refusal, so it reads as bot protection, not a dead link.
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

// absolute feeds a note, never a fetch, so an unresolvable target is shown as written.
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

// stripUserinfo: net/http turns userinfo into Basic auth, and a password must never be echoed back.
func stripUserinfo(u *url.URL) bool {
	if u.User == nil {
		return false
	}
	u.User = nil
	return true
}

// isLoopbackHost backs the test seam only; it never widens the gate in platform/netgate.go.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Unmap().IsLoopback()
}
