package tests

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/dnstools"
	"github.com/Landver/site-of-tools/tools/iptools"
	"github.com/Landver/site-of-tools/tools/linktools"
)

const limitedText = "Too many requests from your address. Try again in a few seconds."

// spendREST uses up the IP lookup budget of client over the REST door.
func spendREST(t *testing.T, s *stack, client string) {
	t.Helper()
	hdr := map[string]string{"Host": ipHost, "Accept": "application/json", "CF-Connecting-IP": client}
	for range 30 {
		if s.do(http.MethodGet, "/?ip=8.8.8.8", "", hdr).Code == http.StatusTooManyRequests {
			return
		}
	}
	t.Fatal("the REST lookup budget never ran out")
}

// TestOneBudgetWhicheverDoor: a client that spent its lookups over REST is
// refused over MCP, an IPv6 client by its /64 on both doors.
func TestOneBudgetWhicheverDoor(t *testing.T) {
	for _, tc := range []struct{ rest, mcp string }{
		{"198.51.100.20", "198.51.100.20"},
		{"2001:db8:5:6::1", "2001:db8:5:6::2"},
	} {
		s := newStack(t, stackOpts{})
		// Connected first, so the bucket has no time to refill between doors.
		cs := s.client(t, "/mcp/ip", map[string]string{"CF-Connecting-IP": tc.mcp}, nil)
		spendREST(t, s, tc.rest)
		res := call(t, cs, "ip_lookup", map[string]any{"ip": "1.1.1.1"})
		if !res.IsError || !strings.Contains(text(t, res), "Too many requests") {
			t.Errorf("MCP from %s after REST from %s spent the budget = %q, want refused", tc.mcp, tc.rest, text(t, res))
		}
		object(t, call(t, cs, "ip_cidr", map[string]any{"cidr": "10.0.0.0/8"}))
	}
}

func TestFullCapIsBusy(t *testing.T) {
	lim := iptools.NewLimits()
	if !lim.LookupCap.TryAcquire(otherClient, 8) {
		t.Fatal("a fresh lookup cap is not 8")
	}
	cs := newStack(t, stackOpts{ipLim: lim}).client(t, "/mcp/ip", nil, nil)
	if res := call(t, cs, "ip_lookup", map[string]any{"ip": "8.8.8.8"}); !res.IsError || text(t, res) != platform.BusyMessage {
		t.Errorf("full cap = %q, want %q", text(t, res), platform.BusyMessage)
	}
	lim.LookupCap.Release(otherClient, 8)
	object(t, call(t, cs, "ip_lookup", map[string]any{"ip": "8.8.8.8"}))
}

// stalledDNS is fakeDNS held up until release closes, like a resolver chasing
// a zone whose nameservers drop packets. Each lookup signals entered.
type stalledDNS struct {
	fakeDNS
	entered, release chan struct{}
}

func (s *stalledDNS) LookupSet(ctx context.Context, name, resolver string, types []string) (*dnstools.ResultSet, error) {
	s.entered <- struct{}{}
	select {
	case <-s.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return s.fakeDNS.LookupSet(ctx, name, resolver, types)
}

// TestOneClientCannotFillACap: a client whose calls are stuck on a slow
// upstream holds its share of the cap, 2 of dns_lookup's 8, and no more, so
// another client is still served.
func TestOneClientCannotFillACap(t *testing.T) {
	dns := &stalledDNS{entered: make(chan struct{}, 16), release: make(chan struct{})}
	s := newStack(t, stackOpts{dns: dns, dnsLim: dnstools.NewLimits()})
	lookup := func(ip string) string {
		hdr := mcpHeaders(map[string]string{"Mcp-Protocol-Version": "2025-11-25", "CF-Connecting-IP": ip})
		body := rpc(1, "tools/call", map[string]any{"name": "dns_lookup", "arguments": map[string]any{"name": "example.com"}})
		return s.do(http.MethodPost, "/mcp/dns", body, hdr).Body.String()
	}
	results := make(chan string, 9)
	for range 8 {
		go func() { results <- lookup("198.51.100.60") }()
	}
	timeout := time.After(5 * time.Second)
	for entered, busy := 0, 0; entered < 2 || busy < 6; {
		select {
		case <-dns.entered:
			entered++
			if entered > 2 {
				t.Fatal("a third call from one client got past the cap")
			}
		case r := <-results:
			if !strings.Contains(r, platform.BusyMessage) {
				t.Fatalf("a call answered while the upstream was stalled: %s", r)
			}
			busy++
		case <-timeout:
			t.Fatal("the burst from one client was neither held at 2 nor refused")
		}
	}
	go func() { results <- lookup("203.0.113.70") }()
	select {
	case <-dns.entered:
	case r := <-results:
		t.Fatalf("another client while the first held its share = %s, want served", r)
	case <-timeout:
		t.Fatal("another client's call never reached the upstream")
	}
	close(dns.release)
	for range 3 {
		if r := <-results; strings.Contains(r, platform.BusyMessage) || strings.Contains(r, `"isError":true`) {
			t.Errorf("a held call = %s, want its result", r)
		}
	}
}

// TestDomainInfoHasItsOwnCap: dns_domain_info waits on RDAP and crt.sh, so it
// holds a cap of its own and full lookup slots don't refuse it.
func TestDomainInfoHasItsOwnCap(t *testing.T) {
	lim := roomyDNS()
	lim.LookupCap.TryAcquire(otherClient, 8)
	cs := newStack(t, stackOpts{dnsLim: lim}).client(t, "/mcp/dns", nil, nil)
	if res := call(t, cs, "dns_lookup", map[string]any{"name": "example.com"}); text(t, res) != platform.BusyMessage {
		t.Errorf("dns_lookup with its cap full = %q, want busy", text(t, res))
	}
	object(t, call(t, cs, "dns_domain_info", map[string]any{"name": "example.com"}))
	lim.DomainCap.TryAcquire(otherClient, 4)
	if res := call(t, cs, "dns_domain_info", map[string]any{"name": "example.com"}); text(t, res) != platform.BusyMessage {
		t.Errorf("dns_domain_info with its own cap full = %q, want busy", text(t, res))
	}
}

// TestListFloodIsLimited: every message counts, not only tool calls.
func TestListFloodIsLimited(t *testing.T) {
	s := newStack(t, stackOpts{})
	hdr := mcpHeaders(map[string]string{"Mcp-Protocol-Version": "2025-11-25", "CF-Connecting-IP": "198.51.100.30"})
	for i := range 60 {
		rec := s.do(http.MethodPost, "/mcp", listBody, hdr)
		if strings.Contains(rec.Body.String(), "Too many requests") {
			if i < 20 {
				t.Errorf("tools/list refused after %d, inside its burst of 20", i)
			}
			return
		}
	}
	t.Error("60 tools/list in a row were never limited")
}

// blockingChecker holds a lookup until its context ends, and says how it ended.
type blockingChecker struct{ ended chan error }

func (b blockingChecker) Check(ctx context.Context, _ string) (iptools.BlockLookup, error) {
	<-ctx.Done()
	b.ended <- ctx.Err()
	return iptools.BlockLookup{}, ctx.Err()
}

// TestHangUpCancelsTheCall: the SDK cancels only 2026-07-28 requests when the
// client goes; a 2025-11-25 client hanging up must stop the work too, long
// before the 25 s deadline.
func TestHangUpCancelsTheCall(t *testing.T) {
	chk := blockingChecker{ended: make(chan error, 1)}
	s := newStack(t, stackOpts{chk: chk})
	req, _ := http.NewRequest(http.MethodPost, s.srv.URL+"/mcp/ip",
		strings.NewReader(rpc(1, "tools/call", map[string]any{"name": "ip_lookup", "arguments": map[string]any{"ip": "8.8.8.8"}})))
	for k, v := range mcpHeaders(map[string]string{"Mcp-Protocol-Version": "2025-11-25"}) {
		req.Header.Set(k, v)
	}
	req.Host = mcpHost
	client := &http.Client{Timeout: 300 * time.Millisecond}
	if _, err := client.Do(req); err == nil {
		t.Fatal("the call returned while its checker was still blocked")
	}
	select {
	case err := <-chk.ended:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("the call ended with %v, want cancelled by the hang-up", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the call kept running after its client hung up")
	}
}

// TestShortResolveSpendsBothRESTBudgets: link_short_resolve spends the
// client's /s/:code bucket and then the breaker every client shares, and a
// tripped breaker reads as busy, not as this client's fault.
func TestShortResolveSpendsBothRESTBudgets(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*linktools.Limits)
		want string
	}{
		{"per client", func(l *linktools.Limits) { l.Resolve = platform.NewLimiter(0.001, 1) }, limitedText},
		{"global", func(l *linktools.Limits) { l.ResolveGlobal = platform.NewGlobalLimiter(0.001, 1) }, platform.BusyMessage},
	} {
		lim := roomyLink()
		tc.set(lim)
		s := newStack(t, stackOpts{linkLim: lim})
		cs := s.client(t, "/mcp/link", map[string]string{"CF-Connecting-IP": "198.51.100.40"}, nil)
		s.do(http.MethodGet, "/s/no-such", "", map[string]string{"Host": linkHost, "CF-Connecting-IP": "198.51.100.40"})
		if res := call(t, cs, "link_short_resolve", map[string]any{"code": "no such!"}); !res.IsError || text(t, res) != tc.want {
			t.Errorf("%s budget spent over REST, then MCP = %q, want %q", tc.name, text(t, res), tc.want)
		}
	}
}
