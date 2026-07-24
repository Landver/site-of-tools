package iptools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// shodanUserAgent politely identifies our lookups to Shodan / Cloudflare.
const shodanUserAgent = "corpberry-iptools/1.0 (+https://ip.corpberry.com)"

// ShodanInfo is what Shodan's free InternetDB knows about one IP: a last-seen
// snapshot (refreshed ~weekly) of open ports plus light metadata. It is
// handler-populated on Result — best-effort, NOT set by Lookup — the same shape
// as Blocklist. Three states a consumer can tell apart:
//   - absent on Result (nil)   → not checked (disabled / private IP / errored)
//   - Found == false           → checked, Shodan has no record (HTTP 404)
//   - Found == true            → Shodan has data for this IP
//
// InternetDB never returns banners or versions, and Vulns are version-INFERRED
// CVEs (a fingerprinted version is known-affected — NOT confirmed exploitable),
// so present everything as "last seen by Shodan", not ground truth.
type ShodanInfo struct {
	Found     bool     `json:"found"`
	Ports     []int    `json:"ports,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
	CPEs      []string `json:"cpes,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Vulns     []string `json:"vulns,omitempty"`
}

// Shodan is a minimal client for Shodan's free, keyless InternetDB endpoint
// (https://internetdb.shodan.io/<ip>). No API key; free for NON-COMMERCIAL use;
// attribution required wherever the data is shown (the result card carries it).
// We call it server-side, live per request, and never store the returned
// payload — a deliberately compliant posture; see
// docs/reports/shodan-internetdb-feasibility.md.
//
// Nil-safe: a nil *Shodan (disabled — blank SHODAN_INTERNETDB_URL) makes Lookup
// a no-op returning (nil, nil), so callers need no guard — same shape as a nil
// *BlockList / *History.
type Shodan struct {
	client  *http.Client
	baseURL string
}

// NewShodan builds the InternetDB client. baseURL == "" disables it (returns
// nil → nil-safe no-op). timeout bounds each lookup so a slow upstream never
// stalls the page (InternetDB is fast and Cloudflare-cached ~5 days).
func NewShodan(baseURL string, timeout time.Duration) *Shodan {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil
	}
	return &Shodan{client: &http.Client{Timeout: timeout}, baseURL: baseURL}
}

// Lookup fetches InternetDB data for ip. Best-effort:
//   - 200 → (&ShodanInfo{Found:true, …}, nil)
//   - 404 → (&ShodanInfo{Found:false}, nil)   // checked, nothing on record
//   - nil receiver (disabled)                  → (nil, nil)
//   - other status / network / decode error    → (nil, err)
//
// The last case returns nil (not a zero ShodanInfo) so the caller OMITS the
// card rather than implying "no open ports" when we could not actually check.
func (s *Shodan) Lookup(ctx context.Context, ip string) (*ShodanInfo, error) {
	if s == nil {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/"+ip, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", shodanUserAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		// InternetDB's JSON fields line up 1:1 with ShodanInfo, so decode straight
		// into it (omitempty affects marshal only, not unmarshal); Found isn't in
		// the body, so set it. The extra "ip" key is ignored.
		var info ShodanInfo
		if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
			return nil, err
		}
		info.Found = true
		return &info, nil
	case http.StatusNotFound:
		return &ShodanInfo{Found: false}, nil
	default:
		return nil, fmt.Errorf("shodan internetdb: unexpected status %s", resp.Status)
	}
}
