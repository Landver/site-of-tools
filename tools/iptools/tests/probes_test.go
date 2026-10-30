package tests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/tools/iptools"
)

// fakeGeo answers only the IPs it holds; any other lookup fails like a malformed address.
type fakeGeo map[string]*iptools.Result

func (f fakeGeo) Lookup(_ context.Context, ip string) (*iptools.Result, error) {
	if r, ok := f[ip]; ok {
		return r, nil
	}
	return nil, errors.New("not in the fake")
}

func probeGeo() (fakeGeo, []string) {
	google := func(cc, country string) *iptools.Result {
		return &iptools.Result{CountryCode: cc, Country: country, ASN: "396982", ASName: "Google LLC"}
	}
	hetzner := &iptools.Result{CountryCode: "DE", Country: "Germany", ASN: "24940", ASName: "Hetzner Online GmbH"}
	geo := fakeGeo{
		"34.1.2.3": google("US", "United States"), "34.1.2.4": google("US", "United States"),
		"34.9.9.9":    google("NL", "Netherlands"),
		"2a01:4f8::1": hetzner, "2a01:4f8::2": hetzner,
		"45.138.12.25": {}, // the databases know nothing about it
	}
	ips := []string{"34.1.2.3", "34.1.2.4", "34.9.9.9", "2a01:4f8::1", "2a01:4f8::2", "45.138.12.25", "1.1.1.1", "not-an-ip"}
	return geo, ips
}

func TestSummarizeProbes(t *testing.T) {
	geo, ips := probeGeo()
	got, err := iptools.SummarizeProbes(context.Background(), geo, ips)
	if err != nil {
		t.Fatalf("SummarizeProbes: %v", err)
	}
	want := iptools.ProbeStats{
		IPs: 8, // every listed address, even ones the databases can't place
		Networks: []iptools.Tally{
			{Key: "396982", Name: "Google LLC", IPs: 3}, {Key: "24940", Name: "Hetzner Online GmbH", IPs: 2}, {IPs: 1},
		},
		Countries: []iptools.Tally{
			{Key: "DE", Name: "Germany", IPs: 2}, {Key: "US", Name: "United States", IPs: 2},
			{IPs: 1}, {Key: "NL", Name: "Netherlands", IPs: 1},
		},
		// Single-address pools (34.9.9.0/24, 45.138.12.0/24) are left out.
		Pools: []iptools.Tally{
			{Key: "2a01:4f8::/48", Name: "Hetzner Online GmbH", IPs: 2}, {Key: "34.1.2.0/24", Name: "Google LLC", IPs: 2},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("SummarizeProbes (-want +got):\n%s", diff)
	}
}

func TestSummarizeProbesKeepsTheTop10(t *testing.T) {
	geo, ips := fakeGeo{}, []string{}
	for i := range 12 {
		ip := fmt.Sprintf("8.%d.0.1", i)
		geo[ip], ips = &iptools.Result{ASN: fmt.Sprint(100 + i)}, append(ips, ip)
	}
	got, _ := iptools.SummarizeProbes(context.Background(), geo, ips)
	if len(got.Networks) != 10 {
		t.Errorf("kept %d networks, want the top 10", len(got.Networks))
	}
}

func TestSummarizeProbesNeedsTheDatabases(t *testing.T) {
	geo := copyLooker{err: iptools.ErrUnavailable}
	if _, err := iptools.SummarizeProbes(context.Background(), geo, []string{"8.8.8.8"}); !errors.Is(err, iptools.ErrUnavailable) {
		t.Errorf("err = %v, want ErrUnavailable", err)
	}
}

func newProbesApp(geo iptools.Looker, list func(context.Context) ([]string, error)) *echo.Echo {
	e := newTestApp(geo)
	iptools.RegisterProbes(e, geo, list)
	return e
}

func TestProbesPage(t *testing.T) {
	geo, ips := probeGeo()
	reads := 0
	app := newProbesApp(geo, func(context.Context) ([]string, error) { reads++; return ips, nil })

	rec := do(app, "/probes", map[string]string{"Accept": "application/json"})
	var st iptools.ProbeStats
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || rec.Code != http.StatusOK || st.IPs != 8 {
		t.Fatalf("JSON = %d %+v (%v), want 200 with 8 IPs", rec.Code, st, err)
	}

	rec = do(app, "/probes", map[string]string{"Accept": "text/html"})
	for _, want := range []string{"8</span> addresses listed", "AS396982", `href="/cidr?cidr=34.1.2.0%2f24"`, "Germany", "never blocked"} {
		if !strings.Contains(strings.ToLower(rec.Body.String()), strings.ToLower(want)) {
			t.Errorf("page lacks %q", want)
		}
	}
	if reads != 1 {
		t.Errorf("the list was read %d times for two views, want 1: the tally is cached", reads)
	}
}

func TestProbesPageWithoutMongo(t *testing.T) {
	app := newProbesApp(nil, iptools.NewBlockList(nil).ProbeIPs)
	if rec := do(app, "/probes", map[string]string{"Accept": "application/json"}); rec.Code != http.StatusServiceUnavailable ||
		!strings.Contains(rec.Body.String(), "unavailable") {
		t.Errorf("JSON = %d %s, want 503 with an error", rec.Code, rec.Body.String())
	}
	if rec := do(app, "/probes", map[string]string{"Accept": "text/html"}); rec.Code != http.StatusServiceUnavailable ||
		!strings.Contains(rec.Body.String(), "unavailable right now") {
		t.Errorf("page = %d, want 503 saying the list is unavailable", rec.Code)
	}
}
