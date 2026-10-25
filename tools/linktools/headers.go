package linktools

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Landver/site-of-tools/platform"
)

// ErrFetchFailed: the caller's URL didn't answer, the target's failure rather than the input's, so a 502.
var ErrFetchFailed = errors.New("could not fetch the URL")

// HeaderRow is a single key-value header with a categorized badge.
type HeaderRow struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Category string `json:"category"` // "caching", "security", "cors", "cookies", "standard"
}

// ETagSimulation captures the result of sending an If-None-Match conditional request.
type ETagSimulation struct {
	SentETag      string `json:"sent_etag"`
	StatusCode    int    `json:"status_code"`
	StatusText    string `json:"status_text"`
	Revalidated   bool   `json:"revalidated"` // true if 304 Not Modified
	BytesReceived int    `json:"bytes_received"`
	Detail        string `json:"detail"`
}

// HeadersReport is the top-level result returned to both HTML/htmx and JSON callers.
type HeadersReport struct {
	Input          string           `json:"input"`
	IsLiveURL      bool             `json:"is_live_url"`
	TargetURL      string           `json:"target_url,omitempty"`
	StatusCode     int              `json:"status_code,omitempty"` // 0: a paste with no status line
	StatusText     string           `json:"status_text,omitempty"`
	Proto          string           `json:"proto,omitempty"`
	LatencyMS      int64            `json:"latency_ms,omitempty"`
	Persona        string           `json:"persona,omitempty"`
	Headers        []HeaderRow      `json:"headers"`
	Cache          CacheAnalysis    `json:"cache"`
	Security       SecurityAnalysis `json:"security"`
	ETagSimulation *ETagSimulation  `json:"etag_simulation,omitempty"`
	TotalFindings  int              `json:"total_findings"`
	FailCount      int              `json:"fail_count"`
	WarnCount      int              `json:"warn_count"`
	OKCount        int              `json:"ok_count"`
	InfoCount      int              `json:"info_count"`
}

// HeaderCategory returns the conceptual domain of a given header name.
func HeaderCategory(name string) string {
	n := strings.ToLower(name)
	switch n {
	case "cache-control", "cdn-cache-control", "cloudflare-cdn-cache-control", "surrogate-control",
		"age", "expires", "pragma", "etag", "last-modified", "vary":
		return "caching"
	case "content-security-policy", "content-security-policy-report-only", "cross-origin-opener-policy",
		"cross-origin-embedder-policy", "cross-origin-resource-policy", "permissions-policy", "feature-policy",
		"strict-transport-security", "x-content-type-options", "x-frame-options", "referrer-policy",
		"clear-site-data", "expect-ct":
		return "security"
	case "access-control-allow-origin", "access-control-allow-credentials", "access-control-allow-headers",
		"access-control-allow-methods", "access-control-expose-headers", "access-control-max-age", "timing-allow-origin":
		return "cors"
	case "set-cookie":
		return "cookies"
	default:
		return "standard"
	}
}

// newHeadersReport audits h; ProbeHeaders adds what only a live fetch knows.
func newHeadersReport(input, proto string, status int, statusText string, h http.Header) *HeadersReport {
	r := &HeadersReport{
		Input: input, Proto: proto, StatusCode: status, StatusText: statusText,
		Headers: headerRows(h), Cache: AnalyzeCache(status, h), Security: AnalyzeSecurity(h),
	}
	findings := slices.Concat(r.Cache.Findings, r.Security.Findings)
	r.TotalFindings = len(findings)
	for _, f := range findings {
		switch f.Severity {
		case SevFail:
			r.FailCount++
		case SevWarn:
			r.WarnCount++
		case SevOK:
			r.OKCount++
		case SevInfo:
			r.InfoCount++
		}
	}
	return r
}

// headerRows clips values as Trace does, since they are a third party's text; a repeated header keeps its order.
func headerRows(h http.Header) []HeaderRow {
	var rows []HeaderRow
	for name, values := range h {
		cat := HeaderCategory(name)
		for _, v := range values {
			rows = append(rows, HeaderRow{Name: name, Value: platform.Clip(v, maxHeaderValue), Category: cat})
		}
	}
	slices.SortStableFunc(rows, func(a, b HeaderRow) int {
		return cmp.Or(cmp.Compare(categoryOrder(a.Category), categoryOrder(b.Category)), strings.Compare(a.Name, b.Name))
	})
	return rows
}

// ProbeHeaders fetches raw through the guarded client and audits the response headers; an ETag on a
// 200 earns a second, conditional GET to see whether the server revalidates.
func (t *Tracer) ProbeHeaders(ctx context.Context, raw, persona string) (*HeadersReport, error) {
	if t == nil {
		return nil, ErrDisabled
	}
	raw, err := readURL(raw)
	if err != nil {
		return nil, err
	}
	target, _, err := parseTarget(raw)
	if err != nil {
		return nil, err
	}
	if err := t.check(target); err != nil {
		return nil, probeError(err)
	}

	ctx, cancel := context.WithTimeout(ctx, t.total)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	p := personaFor(persona)
	req.Header = http.Header{"User-Agent": {p.UA}, "Accept": {traceAccept}}

	began := time.Now()
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, probeError(err)
	}
	latency := time.Since(began).Milliseconds()
	resp.Body.Close()

	r := newHeadersReport(raw, resp.Proto, resp.StatusCode, http.StatusText(resp.StatusCode), resp.Header)
	r.IsLiveURL, r.TargetURL, r.LatencyMS, r.Persona = true, target.String(), latency, p.Key
	if etag := strings.TrimSpace(resp.Header.Get("ETag")); etag != "" && resp.StatusCode == http.StatusOK {
		r.ETagSimulation = t.simulateETag(ctx, req, etag)
	}
	return r, nil
}

// probeError: a gate refusal is the input's fault, anything else the target's.
func probeError(err error) error {
	if errors.Is(err, platform.ErrBlockedAddress) || errors.Is(err, platform.ErrBlockedPort) {
		return errors.New(refusalDetail(err))
	}
	return fmt.Errorf("%w: %s", ErrFetchFailed, clipCause(err))
}

// simulateETag repeats req with If-None-Match: a 304 shows conditional revalidation works.
func (t *Tracer) simulateETag(ctx context.Context, req *http.Request, etag string) *ETagSimulation {
	ctx, cancel := context.WithTimeout(ctx, hopTimeout)
	defer cancel()
	cond := req.Clone(ctx)
	cond.Header.Set("If-None-Match", etag)

	sim := &ETagSimulation{SentETag: etag}
	resp, err := t.client.Do(cond)
	if err != nil {
		sim.StatusText = "Connection Failed"
		sim.Detail = "The conditional request failed: " + clipCause(err)
		return sim
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

	sim.StatusCode, sim.StatusText, sim.BytesReceived = resp.StatusCode, http.StatusText(resp.StatusCode), len(body)
	sim.Revalidated = resp.StatusCode == http.StatusNotModified
	switch resp.StatusCode {
	case http.StatusNotModified:
		sim.Detail = "Server returned 304 Not Modified. Conditional caching is working correctly according to RFC 9110 §13.1.2."
	case http.StatusOK:
		sim.Detail = fmt.Sprintf("Server answered HTTP 200 OK instead of 304 Not Modified. It ignored If-None-Match and sent %d bytes of body.", len(body))
	default:
		sim.Detail = fmt.Sprintf("Server answered unexpected HTTP %d %s.", resp.StatusCode, sim.StatusText)
	}
	return sim
}

// ErrRequestHeaders: the paste holds what a browser sent, which says nothing of what the server answered.
var ErrRequestHeaders = errors.New("That paste has request headers in it")

// requestOnly names headers only a client sends; one either side may send is left out.
var requestOnly = map[string]bool{
	"accept": true, "accept-language": true, "authorization": true, "cookie": true, "dnt": true,
	"host": true, "if-match": true, "if-modified-since": true, "if-none-match": true, "origin": true,
	"range": true, "referer": true, "sec-gpc": true, "upgrade-insecure-requests": true, "user-agent": true,
}

// requestPseudo are the HTTP/2 and HTTP/3 pseudo-headers DevTools shows on a request.
var requestPseudo = map[string]bool{"method": true, "path": true, "authority": true, "scheme": true, "protocol": true}

func isRequestHeader(name string) bool {
	n := strings.ToLower(name)
	return requestOnly[n] || strings.HasPrefix(n, "sec-fetch-") || strings.HasPrefix(n, "sec-ch-") ||
		strings.HasPrefix(n, "access-control-request-")
}

// ParseRawHeaders parses pasted response headers (curl -i, DevTools). A paste with request headers in it
// is refused: audited as an answer, it could only report every response header as missing.
func ParseRawHeaders(raw string) (*HeadersReport, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("no headers pasted")
	}

	headers := make(http.Header)
	var status int
	var statusText, proto string
	var sent []string
	note := func(name string) {
		if !slices.Contains(sent, name) {
			sent = append(sent, name)
		}
	}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if f := strings.Fields(line); len(f) == 3 && strings.HasPrefix(f[2], "HTTP/") && !strings.ContainsRune(f[0], ':') {
			note(f[0] + " request line")
			continue
		}
		if p, rest, ok := strings.Cut(line, " "); ok && strings.HasPrefix(p, "HTTP/") {
			code, text, _ := strings.Cut(strings.TrimSpace(rest), " ")
			if c, ok := statusCode(code); ok {
				proto, status, statusText = p, c, cmp.Or(text, http.StatusText(c))
				continue
			}
		}
		if pseudo, ok := strings.CutPrefix(line, ":"); ok {
			name, val, _ := strings.Cut(pseudo, ":")
			if c, ok := statusCode(val); ok && name == "status" {
				status, statusText = c, http.StatusText(c)
			} else if requestPseudo[name] {
				note(":" + name)
			}
			continue
		}

		key, val, ok := strings.Cut(line, ":")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			continue
		}
		if isRequestHeader(key) {
			note(http.CanonicalHeaderKey(key))
		}
		headers.Add(key, strings.TrimSpace(val))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading headers: %w", err)
	}

	if len(sent) > 0 {
		return nil, fmt.Errorf("%w (%s): a browser sends those, and this tool audits what the server sends back. "+
			"Copy only the Response Headers block from DevTools, or run curl -I on the URL.",
			ErrRequestHeaders, strings.Join(sent[:min(len(sent), 3)], ", "))
	}
	if len(headers) == 0 {
		return nil, errors.New("could not find any valid 'Header-Name: Value' lines in pasted text")
	}
	return newHeadersReport(raw, proto, status, statusText, headers), nil
}

func statusCode(s string) (int, bool) {
	c, err := strconv.Atoi(strings.TrimSpace(s))
	return c, err == nil && c >= 100 && c < 600
}

func categoryOrder(cat string) int {
	switch cat {
	case "caching":
		return 1
	case "security":
		return 2
	case "cookies":
		return 3
	case "cors":
		return 4
	default:
		return 5
	}
}
