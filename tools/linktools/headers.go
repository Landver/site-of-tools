package linktools

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

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
	StatusCode     int              `json:"status_code"`
	StatusText     string           `json:"status_text"`
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

func countFindings(report *HeadersReport) {
	report.TotalFindings = len(report.Cache.Findings) + len(report.Security.Findings)
	tally := func(notes []HeaderNote) {
		for _, f := range notes {
			switch f.Severity {
			case SevFail:
				report.FailCount++
			case SevWarn:
				report.WarnCount++
			case SevOK:
				report.OKCount++
			case SevInfo:
				report.InfoCount++
			}
		}
	}
	tally(report.Cache.Findings)
	tally(report.Security.Findings)
}

func buildHeaderRows(headers http.Header) []HeaderRow {
	var rows []HeaderRow
	for k, vv := range headers {
		cat := HeaderCategory(k)
		for _, v := range vv {
			rows = append(rows, HeaderRow{
				Name:     k,
				Value:    v,
				Category: cat,
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Category != rows[j].Category {
			return categoryOrder(rows[i].Category) < categoryOrder(rows[j].Category)
		}
		return rows[i].Name < rows[j].Name
	})
	return rows
}

// ProbeHeaders dials out to a remote URL using the SSRF-guarded HTTP client.
func (t *Tracer) ProbeHeaders(ctx context.Context, raw string, persona string) (*HeadersReport, error) {
	if t == nil {
		return nil, ErrDisabled
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("no URL given")
	}
	if len(raw) > maxInput {
		return nil, fmt.Errorf("URL is %d bytes, over the %d KB limit", len(raw), maxInput>>10)
	}

	p := personaFor(persona)
	targetURL, _, err := parseTarget(raw)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", p.UA)
	req.Header.Set("Accept", traceAccept)

	start := time.Now()
	resp, err := t.client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return nil, fmt.Errorf("fetching headers: %w", err)
	}
	defer resp.Body.Close()

	// Drain up to 1KB to cleanly close connection
	_, _ = io.CopyN(io.Discard, resp.Body, 1024)

	rows := buildHeaderRows(resp.Header)

	cacheAudit := AnalyzeCache(resp.StatusCode, resp.Header)
	secAudit := AnalyzeSecurity(resp.Header)

	report := &HeadersReport{
		Input:       raw,
		IsLiveURL:   true,
		TargetURL:   targetURL.String(),
		StatusCode:  resp.StatusCode,
		StatusText:  http.StatusText(resp.StatusCode),
		Proto:       resp.Proto,
		LatencyMS:   elapsed,
		Persona:     p.Key,
		Headers:     rows,
		Cache:       cacheAudit,
		Security:    secAudit,
	}

	// Conditional ETag simulation if ETag present on 200 OK
	etag := strings.TrimSpace(resp.Header.Get("ETag"))
	if etag != "" && resp.StatusCode == http.StatusOK {
		sim := t.simulateETag(ctx, targetURL.String(), etag, p.UA)
		report.ETagSimulation = sim
	}

	countFindings(report)
	return report, nil
}

func (t *Tracer) simulateETag(ctx context.Context, urlStr, etag, ua string) *ETagSimulation {
	simCtx, cancel := context.WithTimeout(ctx, hopTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(simCtx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("If-None-Match", etag)

	resp, err := t.client.Do(req)
	if err != nil {
		return &ETagSimulation{
			SentETag:   etag,
			StatusCode: 0,
			StatusText: "Connection Failed",
			Detail:     fmt.Sprintf("Failed to complete conditional request: %v", err),
		}
	}
	defer resp.Body.Close()

	lr := io.LimitReader(resp.Body, 1024)
	body, _ := io.ReadAll(lr)

	sim := &ETagSimulation{
		SentETag:      etag,
		StatusCode:    resp.StatusCode,
		StatusText:    http.StatusText(resp.StatusCode),
		BytesReceived: len(body),
	}

	if resp.StatusCode == http.StatusNotModified {
		sim.Revalidated = true
		sim.Detail = "Server returned 304 Not Modified. Conditional caching is working correctly according to RFC 9110 §13.1.2."
	} else if resp.StatusCode == http.StatusOK {
		sim.Revalidated = false
		sim.Detail = fmt.Sprintf("Server answered HTTP 200 OK instead of 304 Not Modified. It ignored If-None-Match and sent %d bytes of body.", len(body))
	} else {
		sim.Revalidated = false
		sim.Detail = fmt.Sprintf("Server answered unexpected HTTP %d %s.", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	return sim
}

// ParseRawHeaders parses pasted raw HTTP response headers (e.g. from curl or browser DevTools).
func ParseRawHeaders(raw string) (*HeadersReport, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("no headers pasted")
	}

	scanner := bufio.NewScanner(strings.NewReader(raw))
	headers := make(http.Header)
	statusCode := http.StatusOK
	statusText := "OK"
	proto := "HTTP/1.1"

	firstLine := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if firstLine {
			firstLine = false
			// Check if line is an HTTP status line, e.g. "HTTP/1.1 200 OK" or "HTTP/2 404"
			if strings.HasPrefix(line, "HTTP/") {
				parts := strings.SplitN(line, " ", 3)
				if len(parts) >= 2 {
					proto = parts[0]
					var code int
					if _, err := fmt.Sscanf(parts[1], "%d", &code); err == nil && code >= 100 && code < 600 {
						statusCode = code
						if len(parts) >= 3 {
							statusText = parts[2]
						} else {
							statusText = http.StatusText(code)
						}
						continue
					}
				}
			}
		}

		// Header line: "Key: Value"
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		headers.Add(key, val)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading headers: %w", err)
	}

	if len(headers) == 0 {
		return nil, errors.New("could not find any valid 'Header-Name: Value' lines in pasted text")
	}

	rows := buildHeaderRows(headers)

	cacheAudit := AnalyzeCache(statusCode, headers)
	secAudit := AnalyzeSecurity(headers)

	report := &HeadersReport{
		Input:       raw,
		IsLiveURL:   false,
		StatusCode:  statusCode,
		StatusText:  statusText,
		Proto:       proto,
		Headers:     rows,
		Cache:       cacheAudit,
		Security:    secAudit,
	}

	countFindings(report)
	return report, nil
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
