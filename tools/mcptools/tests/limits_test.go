package tests

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/iptools"
)

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
	if !lim.LookupCap.TryAcquire(8) {
		t.Fatal("a fresh lookup cap is not 8")
	}
	cs := newStack(t, stackOpts{ipLim: lim}).client(t, "/mcp/ip", nil, nil)
	if res := call(t, cs, "ip_lookup", map[string]any{"ip": "8.8.8.8"}); !res.IsError || text(t, res) != platform.BusyMessage {
		t.Errorf("full cap = %q, want %q", text(t, res), platform.BusyMessage)
	}
	lim.LookupCap.Release(8)
	object(t, call(t, cs, "ip_lookup", map[string]any{"ip": "8.8.8.8"}))
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
