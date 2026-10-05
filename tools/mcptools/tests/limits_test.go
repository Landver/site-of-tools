package tests

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/botcheck"
	"github.com/Landver/site-of-tools/tools/ciphertools"
	"github.com/Landver/site-of-tools/tools/dnstools"
	"github.com/Landver/site-of-tools/tools/iptools"
	"github.com/Landver/site-of-tools/tools/linktools"
)

// TestOneBudgetWhicheverDoor: a budget spent over REST is spent over MCP, an
// IPv6 client's by its /64; a tool on another budget still answers.
func TestOneBudgetWhicheverDoor(t *testing.T) {
	resolve := func(set func(*linktools.Limits)) stackOpts { l := roomyLink(); set(l); return stackOpts{linkLim: l} }
	type rest struct{ host, method, target, body string }
	for _, tc := range []struct {
		name          string
		opts          stackOpts
		rest          rest
		restIP, mcpIP string
		tool          string
		args          map[string]any
		want, free    string
	}{
		{"ip", stackOpts{}, rest{ipHost, http.MethodGet, "/?ip=8.8.8.8", ""}, "198.51.100.20", "198.51.100.20",
			"ip_lookup", map[string]any{"ip": "1.1.1.1"}, platform.LimitedMessage, "ip_cidr"},
		{"ip by /64", stackOpts{}, rest{ipHost, http.MethodGet, "/?ip=8.8.8.8", ""}, "2001:db8:5:6::1", "2001:db8:5:6::2",
			"ip_lookup", map[string]any{"ip": "1.1.1.1"}, platform.LimitedMessage, "ip_cidr"},
		{"botcheck", stackOpts{botLim: botcheck.NewLimits()}, rest{botHost, http.MethodGet, "/", ""}, "198.51.100.80", "198.51.100.80",
			"botcheck_score", map[string]any{"http": map[string]any{"user_agent": "curl/8.7.1"}}, platform.LimitedMessage, ""},
		{"cipher heavy", stackOpts{cipherLim: ciphertools.NewLimits()}, rest{cipherHost, http.MethodPost, "/jwt/sign", `{"key":"` + signKey + `","now":1700000000}`},
			"198.51.100.70", "198.51.100.70", "cipher_jwt_sign", map[string]any{"key": signKey}, platform.LimitedMessage, "cipher_hash"},
		{"short link per client", resolve(func(l *linktools.Limits) { l.Resolve = platform.NewLimiter(0.001, 1) }), rest{linkHost, http.MethodGet, "/s/no-such", ""},
			"198.51.100.40", "198.51.100.40", "link_short_resolve", map[string]any{"code": "no such!"}, platform.LimitedMessage, ""},
		// The breaker every client shares reads as busy, not as this client's fault.
		{"short link breaker", resolve(func(l *linktools.Limits) { l.ResolveGlobal = platform.NewGlobalLimiter(0.001, 1) }), rest{linkHost, http.MethodGet, "/s/no-such", ""},
			"198.51.100.41", "198.51.100.41", "link_short_resolve", map[string]any{"code": "no such!"}, platform.BusyMessage, ""},
	} {
		s := newStack(t, tc.opts)
		// Connected first, so the bucket has no time to refill between doors.
		cs := s.client(t, "/mcp", map[string]string{"CF-Connecting-IP": tc.mcpIP}, nil)
		hdr := map[string]string{"Host": tc.rest.host, "Accept": "application/json", "Content-Type": "application/json", "CF-Connecting-IP": tc.restIP}
		for i := 0; ; i++ {
			if code := s.do(tc.rest.method, tc.rest.target, tc.rest.body, hdr).Code; code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable {
				break
			}
			if i == 60 {
				t.Fatalf("%s: the REST budget never ran out", tc.name)
			}
		}
		if res := call(t, cs, tc.tool, tc.args); !res.IsError || text(t, res) != tc.want {
			t.Errorf("%s: MCP after REST spent the budget = %q, want %q", tc.name, text(t, res), tc.want)
		}
		if tc.free != "" {
			object(t, call(t, cs, tc.free, required[tc.free]))
		}
	}
}

func TestFullCapIsBusy(t *testing.T) {
	ipLim, botLim := iptools.NewLimits(), roomyBot()
	cs := newStack(t, stackOpts{ipLim: ipLim, botLim: botLim}).client(t, "/mcp", nil, nil)
	for tool, c := range map[string]*platform.Cap{"ip_lookup": ipLim.LookupCap, "botcheck_score": botLim.CheckCap} {
		if !c.TryAcquire(otherClient, 8) {
			t.Fatalf("%s: a fresh cap is not 8", tool)
		}
		if res := call(t, cs, tool, required[tool]); !res.IsError || text(t, res) != platform.BusyMessage {
			t.Errorf("%s with its cap full = %q, want busy", tool, text(t, res))
		}
		c.Release(otherClient, 8)
		object(t, call(t, cs, tool, required[tool]))
	}
}

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

// TestOneClientCannotFillACap: stuck calls hold their client's share, 2 of 8, no more.
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

// TestDomainInfoHasItsOwnCap: it waits on RDAP and crt.sh, not on lookup slots.
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

type blockingChecker struct{ ended chan error }

func (b blockingChecker) Check(ctx context.Context, _ string) (iptools.BlockLookup, error) {
	<-ctx.Done()
	b.ended <- ctx.Err()
	return iptools.BlockLookup{}, ctx.Err()
}

// TestHangUpCancelsTheCall: the SDK cancels only 2026-07-28 requests; a
// 2025-11-25 client hanging up must stop the work too.
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
