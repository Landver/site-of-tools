package iptools

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

const (
	probesDesc        = "Who probed corpberry.com for secret files in the last 30 days, by network, country and address pool. Flagged, never blocked."
	probesUnavailable = "The probe list is unavailable right now. Try again later."
	probesTop         = 10
	// One tally of the whole list per window, however many viewers: it costs a geo lookup per address.
	probesCacheTTL = 5 * time.Minute
)

// ProbeStats tallies the probe list; Countries is where each address is hosted, often a cloud region.
type ProbeStats struct {
	IPs       int     `json:"ips"`
	Networks  []Tally `json:"networks"`
	Countries []Tally `json:"countries"`
	Pools     []Tally `json:"pools"` // IPv4 /24 and IPv6 /48 holding at least two listed addresses
}

// Tally's Key is an ASN, a country code or a CIDR; empty when the databases don't know it.
type Tally struct {
	Key  string `json:"key"`
	Name string `json:"name,omitempty"`
	IPs  int    `json:"ips"`
}

// SummarizeProbes keeps the top probesTop of each tally; only an unloaded geo database is an error.
func SummarizeProbes(ctx context.Context, geo Looker, ips []string) (ProbeStats, error) {
	networks, countries, pools := map[string]Tally{}, map[string]Tally{}, map[string]Tally{}
	for _, ip := range ips {
		res, err := geo.Lookup(ctx, ip)
		if errors.Is(err, ErrUnavailable) {
			return ProbeStats{}, err
		}
		if err != nil {
			continue
		}
		addr, _ := netip.ParseAddr(ip)
		bits := 24
		if addr.Is6() {
			bits = 48
		}
		pool, _ := addr.Prefix(bits)
		count(networks, res.ASN, res.ASName)
		count(countries, res.CountryCode, res.Country)
		count(pools, pool.String(), res.ASName)
	}
	return ProbeStats{IPs: len(ips), Networks: top(networks, 1), Countries: top(countries, 1), Pools: top(pools, 2)}, nil
}

func count(m map[string]Tally, key, name string) {
	m[key] = Tally{Key: key, Name: name, IPs: m[key].IPs + 1}
}

func top(m map[string]Tally, minIPs int) []Tally {
	var out []Tally
	for _, t := range m {
		if t.IPs >= minIPs {
			out = append(out, t)
		}
	}
	slices.SortFunc(out, func(a, b Tally) int { return cmp.Or(b.IPs-a.IPs, cmp.Compare(a.Key, b.Key)) })
	return out[:min(len(out), probesTop)]
}

// RegisterProbes serves /probes. geo must be the plain Service: Shodan per listed IP would drain its budget.
func RegisterProbes(e *echo.Echo, geo Looker, listIPs func(context.Context) ([]string, error)) {
	var (
		mu     sync.Mutex
		cached ProbeStats
		at     time.Time
	)
	stats := func(ctx context.Context) (ProbeStats, error) {
		mu.Lock()
		defer mu.Unlock()
		if time.Since(at) < probesCacheTTL {
			return cached, nil
		}
		ips, err := listIPs(ctx)
		if err != nil {
			return ProbeStats{}, err
		}
		st, err := SummarizeProbes(ctx, geo, ips)
		if err == nil {
			cached, at = st, time.Now()
		}
		return st, err
	}
	e.GET("/probes", func(c *echo.Context) error {
		vm := map[string]any{"Title": "Probes", "Desc": probesDesc, "Active": "probes", "Subdomain": "ip", "Attribution": true}
		st, err := stats(c.Request().Context())
		if err != nil {
			vm["Error"] = probesUnavailable
			return platform.Reply(c, http.StatusServiceUnavailable, map[string]string{"error": probesUnavailable}, vm, "ip/probes", "ip/probes")
		}
		vm["Stats"] = st
		return platform.Reply(c, http.StatusOK, st, vm, "ip/probes", "ip/probes")
	})
}
