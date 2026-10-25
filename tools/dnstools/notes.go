package dnstools

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/iptools"
)

// Note holds an audit finding for a DNS query or report.
type Note struct {
	Level string `json:"level"` // ok | warn | fail | info
	Text  string `json:"text"`
}

// sortNotes orders findings fail, warn, info, ok; stable within a level.
func sortNotes(notes []Note) {
	rank := func(n Note) int { return slices.Index([]string{"fail", "warn", "info", "ok"}, n.Level) }
	slices.SortStableFunc(notes, func(a, b Note) int { return rank(a) - rank(b) })
}

// BlockChecker represents blocklist inspection capabilities.
type BlockChecker interface {
	Check(ctx context.Context, ip string) (iptools.BlockLookup, error)
	LastSync(ctx context.Context, source string) (time.Time, error)
}

// BlockCheckerFrom returns nil for a nil list: a typed nil would report every address clean.
func BlockCheckerFrom(bl *iptools.BlockList) BlockChecker {
	if bl == nil {
		return nil
	}
	return bl
}

// policyClient dials through g: any domain can point outbound requests anywhere.
func policyClient(timeout time.Duration, g *platform.EgressGuard) *http.Client {
	tr := g.Transport(5 * time.Second)
	tr.TLSHandshakeTimeout = 5 * time.Second
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// WithEgressGuard sends outbound probes through g. Nil-safe.
func (s *Service) WithEgressGuard(g *platform.EgressGuard) *Service {
	if s != nil {
		if s.http != nil {
			s.http = policyClient(s.http.Timeout, g)
		}
		s.guard = g
	}
	return s
}
