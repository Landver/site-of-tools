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

// shodanUserAgent IDs our lookups to Shodan / Cloudflare.
const shodanUserAgent = "corpberry-iptools/1.0 (+https://ip.corpberry.com)"

// ShodanInfo = what Shodan's free InternetDB knows about one IP: last-seen
// snapshot (refreshed ~weekly) of open ports + light metadata. Handler-populated
// on Result — best-effort, NOT set by Lookup — same shape as Blocklist. Three
// states consumer can tell apart:
//   - absent on Result (nil)   → not checked (disabled / private IP / errored)
//   - Found == false           → checked, Shodan has no record (HTTP 404)
//   - Found == true            → Shodan has data for this IP
//
// InternetDB never returns banners/versions; Vulns are version-INFERRED CVEs
// (fingerprinted version known-affected — NOT confirmed exploitable), so present
// everything as "last seen by Shodan", not ground truth.
type ShodanInfo struct {
	Found     bool     `json:"found"`
	Ports     []int    `json:"ports,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
	CPEs      []string `json:"cpes,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Vulns     []string `json:"vulns,omitempty"`
}

// Shodan = minimal client for Shodan's free, keyless InternetDB endpoint
// (https://internetdb.shodan.io/<ip>). No API key; free for NON-COMMERCIAL use;
// attribution required wherever data shown (result card carries it). Called
// server-side, live per req, payload never stored — deliberately compliant
// posture; see docs/reports/shodan-internetdb-feasibility.md.
//
// Nil-safe: nil *Shodan (disabled — blank SHODAN_INTERNETDB_URL) makes Lookup
// no-op returning (nil, nil), so callers need no guard — same shape as nil
// *BlockList / *History.
type Shodan struct {
	client  *http.Client
	baseURL string
}

// NewShodan builds InternetDB client. baseURL == "" disables it (returns nil →
// nil-safe no-op). timeout bounds each lookup so slow upstream never stalls page
// (InternetDB fast & Cloudflare-cached ~5 days).
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
// Last case returns nil (not zero ShodanInfo) so caller OMITS card rather than
// implying "no open ports" when we couldn't actually check.
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
		// InternetDB JSON fields line up 1:1 w/ ShodanInfo, so decode straight into
		// it (omitempty affects marshal only, not unmarshal); Found not in body, so
		// set it. Extra "ip" key ignored.
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
