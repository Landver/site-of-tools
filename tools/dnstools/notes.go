package dnstools

import (
	"slices"

	"github.com/Landver/site-of-tools/platform"
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

// WithEgressGuard sends outbound probes through g. Nil-safe.
func (s *Service) WithEgressGuard(g *platform.EgressGuard) *Service {
	if s != nil {
		s.guard = g
	}
	return s
}
