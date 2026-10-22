package iptools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// shodanUserAgent IDs our lookups to Shodan / Cloudflare.
const shodanUserAgent = "corpberry-iptools/1.0 (+https://ip.corpberry.com)"

// InternetDB bans an IP for an hour after a few hundred quick requests; ours all share one IP.
const (
	shodanPerSecond = 1
	shodanBurst     = 5
)

// ShodanInfo: Skipped = budget spent, Found=false = no record (404). Vulns are version-inferred CVEs,
// not confirmed exploitable, so present it all as "last seen by Shodan", not ground truth.
type ShodanInfo struct {
	Found     bool     `json:"found"`
	Skipped   bool     `json:"skipped,omitempty"`
	Ports     []int    `json:"ports,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
	CPEs      []string `json:"cpes,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Vulns     []string `json:"vulns,omitempty"`
}

// InternetDB is free for non-commercial use with attribution; payloads are fetched live, never stored.
type Shodan struct {
	client  *http.Client
	baseURL string
	limit   *rate.Limiter
}

// NewShodan returns nil, a no-op client, when baseURL is blank.
func NewShodan(baseURL string, timeout time.Duration) *Shodan {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil
	}
	return &Shodan{
		client:  &http.Client{Timeout: timeout},
		baseURL: baseURL,
		limit:   rate.NewLimiter(shodanPerSecond, shodanBurst),
	}
}

// Errors return nil, not an empty ShodanInfo, so an unchecked IP never reads as "no open ports".
func (s *Shodan) Lookup(ctx context.Context, ip string) (*ShodanInfo, error) {
	if s == nil {
		return nil, nil
	}
	if !s.limit.Allow() {
		return &ShodanInfo{Skipped: true}, nil
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
		// InternetDB fields map 1:1 onto ShodanInfo; Found isn't in the body.
		var info ShodanInfo
		if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
			return nil, err
		}
		info.Found, info.Skipped = true, false
		return &info, nil
	case http.StatusNotFound:
		return &ShodanInfo{Found: false}, nil
	default:
		return nil, fmt.Errorf("shodan internetdb: unexpected status %s", resp.Status)
	}
}
