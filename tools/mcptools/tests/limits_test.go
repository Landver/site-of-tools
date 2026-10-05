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

// An IPv6 client spends its /64's budget.
func TestOneBudgetWhicheverDoor(t *testing.T) {
	perClient, breaker := linktools.NewLimits(), linktools.NewLimits()
	perClient.Resolve = platform.NewLimiter(0.001, 1)
	breaker.ResolveGlobal = platform.NewGlobalLimiter(0.001, 1)
	for _, tc := range []struct {
		opts               stackOpts
		host, target, body string
		tool               string
		args               map[string]any
		want, free         string
	}{
		{stackOpts{ipLim: iptools.NewLimits()}, ipHost, "/?ip=8.8.8.8", "", "ip_lookup", required["ip_lookup"], platform.LimitedMessage, "ip_cidr"},
		{stackOpts{botLim: botcheck.NewLimits()}, botHost, "/", "", "botcheck_score", required["botcheck_score"], platform.LimitedMessage, ""},
		{stackOpts{cipherLim: ciphertools.NewLimits()}, cipherHost, "/jwt/sign", `{"key":"` + signKey + `","now":1700000000}`,
			"cipher_jwt_sign", required["cipher_jwt_sign"], platform.LimitedMessage, "cipher_hash"},
		{stackOpts{linkLim: perClient}, linkHost, "/s/no-such", "", "link_short_resolve", map[string]any{"code": "no such!"}, platform.LimitedMessage, ""},
		// The breaker every client shares reads as busy, not as this client's fault.
		{stackOpts{linkLim: breaker}, linkHost, "/s/no-such", "", "link_short_resolve", map[string]any{"code": "no such!"}, platform.BusyMessage, ""},
	} {
		s := newStack(t, tc.opts)
		// Connected first, so the bucket has no time to refill between doors.
		cs := s.client(t, "/mcp", map[string]string{"CF-Connecting-IP": "2001:db8:5:6::2"})
		for i := 0; ; i++ {
			code := s.rest(tc.host, tc.target, tc.body, map[string]string{"CF-Connecting-IP": "2001:db8:5:6::1"}).Code
			if code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable {
				break
			}
			if i == 60 {
				t.Fatalf("%s: the REST budget never ran out", tc.tool)
			}
		}
		if res := call(t, cs, tc.tool, tc.args); text(t, res) != tc.want {
			t.Errorf("%s after REST spent the budget = %q, want %q", tc.tool, text(t, res), tc.want)
		}
		if tc.free != "" {
			object(t, call(t, cs, tc.free, required[tc.free]))
		}
	}
}

func TestFullCapIsBusy(t *testing.T) {
	s := newStack(t, stackOpts{})
	cs := s.client(t, "/mcp", nil)
	for _, tc := range []struct {
		cap        *platform.Cap
		size       int64
		busy, free string
	}{
		{s.ipLim.LookupCap, 8, "ip_lookup", ""},
		{s.botLim.CheckCap, 8, "botcheck_score", ""},
		// dns_domain_info waits on RDAP and crt.sh, not on lookup slots.
		{s.dnsLim.LookupCap, 8, "dns_lookup", "dns_domain_info"},
		{s.dnsLim.DomainCap, 4, "dns_domain_info", ""},
	} {
		if !tc.cap.TryAcquire(otherClient, tc.size) {
			t.Fatalf("%s: a fresh cap is not %d", tc.busy, tc.size)
		}
		if res := call(t, cs, tc.busy, required[tc.busy]); text(t, res) != platform.BusyMessage {
			t.Errorf("%s with its cap full = %q, want busy", tc.busy, text(t, res))
		}
		if tc.free != "" {
			object(t, call(t, cs, tc.free, required[tc.free]))
		}
		tc.cap.Release(otherClient, tc.size)
		object(t, call(t, cs, tc.busy, required[tc.busy]))
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

// Stuck calls hold their client's share of a cap, 2 of 8, and no more.
func TestOneClientCannotFillACap(t *testing.T) {
	dns := &stalledDNS{entered: make(chan struct{}, 16), release: make(chan struct{})}
	s := newStack(t, stackOpts{dns: dns})
	lookup := func(ip string) string {
		hdr := mcpHeaders(map[string]string{"Mcp-Protocol-Version": "2025-11-25", "CF-Connecting-IP": ip})
		body := rpc(1, "tools/call", map[string]any{"name": "dns_lookup", "arguments": required["dns_lookup"]})
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

// Every message counts, not only tool calls.
func TestListFloodIsLimited(t *testing.T) {
	s := newStack(t, stackOpts{})
	hdr := mcpHeaders(map[string]string{"Mcp-Protocol-Version": "2025-11-25", "CF-Connecting-IP": "198.51.100.30"})
	for i := range 60 {
		if strings.Contains(s.do(http.MethodPost, "/mcp", listBody, hdr).Body.String(), "Too many requests") {
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

// The SDK cancels only 2026-07-28 requests; a 2025-11-25 client hanging up must stop the work too.
func TestHangUpCancelsTheCall(t *testing.T) {
	chk := blockingChecker{ended: make(chan error, 1)}
	s := newStack(t, stackOpts{chk: chk})
	req, _ := http.NewRequest(http.MethodPost, s.srv.URL+"/mcp/ip",
		strings.NewReader(rpc(1, "tools/call", map[string]any{"name": "ip_lookup", "arguments": required["ip_lookup"]})))
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
