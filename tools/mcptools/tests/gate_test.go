package tests

import (
	"bytes"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

var listBody = rpc(1, "tools/list", map[string]any{})

func TestGate(t *testing.T) {
	s := newStack(t, stackOpts{})
	browser := map[string]string{"Accept": "text/html,application/xhtml+xml,*/*"}
	cases := []struct {
		name, method, target, body string
		hdr                        map[string]string
		code                       int
		want                       string // in the body
	}{
		{"browser GET /mcp is the page", http.MethodGet, "/mcp", "", browser, http.StatusOK, "ip_lookup"},
		{"browser GET of a toolset is the page", http.MethodGet, "/mcp/ip", "", browser, http.StatusOK, "<html"},
		{"any other GET is the SDK's 405", http.MethodGet, "/mcp", "", map[string]string{"Accept": "text/event-stream"}, http.StatusMethodNotAllowed, ""},
		{"DELETE is 405", http.MethodDelete, "/mcp", "", nil, http.StatusMethodNotAllowed, ""},
		{"unknown toolset", http.MethodPost, "/mcp/nope", listBody, mcpHeaders(nil), http.StatusNotFound, "No MCP endpoint"},
		{"toolset without tools yet", http.MethodPost, "/mcp/dns", listBody, mcpHeaders(nil), http.StatusNotFound, "No MCP endpoint"},
		{"empty toolset", http.MethodPost, "/mcp/", listBody, mcpHeaders(nil), http.StatusNotFound, "Not Found"},
		{"owner endpoint off without a key", http.MethodPost, "/mcp/owner", listBody, mcpHeaders(nil), http.StatusNotFound, "No MCP endpoint"},
		{"body over 1 MiB", http.MethodPost, "/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"x":"` + strings.Repeat("a", 1<<20) + `"}}`, mcpHeaders(nil), http.StatusRequestEntityTooLarge, "1 MiB"},
		{"batch", http.MethodPost, "/mcp", " \n[" + listBody + "," + listBody + "]", mcpHeaders(nil), http.StatusBadRequest, "batching is not supported"},
		{"cross-site browser", http.MethodPost, "/mcp", listBody, mcpHeaders(map[string]string{"Sec-Fetch-Site": "cross-site"}), http.StatusForbidden, "Cross-site"},
		{"same-site browser", http.MethodPost, "/mcp", listBody, mcpHeaders(map[string]string{"Sec-Fetch-Site": "same-site"}), http.StatusForbidden, "Cross-site"},
		{"same-origin browser", http.MethodPost, "/mcp", listBody, mcpHeaders(map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": base}), http.StatusOK, "ip_cidr"},
		{"a list", http.MethodPost, "/mcp/ip", listBody, mcpHeaders(nil), http.StatusOK, "ip_cidr"},
		{"unknown Host", http.MethodPost, "/mcp", listBody, mcpHeaders(map[string]string{"Host": "rebound.example"}), http.StatusNotFound, ""},
	}
	// Echo's router answers these before the gate runs.
	byEcho := map[string]bool{"empty toolset": true, "unknown Host": true}
	for _, tc := range cases {
		rec := s.do(tc.method, tc.target, tc.body, tc.hdr)
		if rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: %d %.120q, want %d with %q", tc.name, rec.Code, rec.Body.String(), tc.code, tc.want)
		}
		if rec.Code >= 300 && rec.Code < 400 {
			t.Errorf("%s answered %d: nothing under /mcp redirects", tc.name, rec.Code)
		}
		if got := rec.Header().Get("Cache-Control"); !byEcho[tc.name] && got != "no-store" {
			t.Errorf("%s: Cache-Control %q, want no-store", tc.name, got)
		}
	}
}

func TestForeignOriginIsServedAndLogged(t *testing.T) {
	var log syncBuffer
	s := newStack(t, stackOpts{log: &log})
	rec := s.do(http.MethodPost, "/mcp", listBody, mcpHeaders(map[string]string{"Origin": "https://claude.ai", "User-Agent": "Claude-User"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("foreign Origin without Sec-Fetch-Site = %d, want served", rec.Code)
	}
	if got := log.String(); !strings.Contains(got, "foreign Origin") || !strings.Contains(got, "https://claude.ai") || !strings.Contains(got, "Claude-User") {
		t.Errorf("log = %s, want the Origin and user agent", got)
	}
	log.Reset()
	s.do(http.MethodPost, "/mcp", listBody, mcpHeaders(map[string]string{"Origin": base}))
	if strings.Contains(log.String(), "foreign Origin") {
		t.Errorf("our own Origin was logged as foreign")
	}
}

func TestOwnerKey(t *testing.T) {
	s := newStack(t, stackOpts{owner: offlineOwner(t)})
	try := func(ip string, hdr map[string]string) int {
		hdr = mcpHeaders(hdr)
		hdr["CF-Connecting-IP"] = ip
		return s.do(http.MethodPost, "/mcp/owner", listBody, hdr).Code
	}
	for name, hdr := range map[string]map[string]string{
		"no key":    nil,
		"wrong key": {"X-Api-Key": "guess"},
		"basic":     {"Authorization": "Basic " + ownerKey},
	} {
		ip := map[string]string{"no key": "198.51.100.1", "wrong key": "198.51.100.2", "basic": "198.51.100.3"}[name]
		for i := range 5 {
			if code := try(ip, hdr); code != http.StatusForbidden {
				t.Fatalf("%s, try %d = %d, want 403", name, i+1, code)
			}
		}
		refused := false
		for range 5 {
			if try(ip, hdr) == http.StatusTooManyRequests {
				refused = true
				break
			}
		}
		if !refused {
			t.Errorf("%s: never 429 after five wrong keys", name)
		}
		if code := try(ip, map[string]string{"X-Api-Key": ownerKey}); code != http.StatusTooManyRequests {
			t.Errorf("%s: the right key while locked out = %d, want 429 before it is compared", name, code)
		}
	}

	// A gateway's own token doesn't touch the public endpoints.
	if code := s.do(http.MethodPost, "/mcp", listBody, mcpHeaders(map[string]string{"Authorization": "Bearer someone-elses"})).Code; code != http.StatusOK {
		t.Errorf("public endpoint with an unrelated bearer token = %d, want 200", code)
	}

	for name, hdr := range map[string]map[string]string{
		"X-Api-Key": {"X-Api-Key": ownerKey},
		"Bearer":    {"Authorization": "bearer " + ownerKey},
	} {
		hdr["CF-Connecting-IP"] = "198.51.100.9"
		res := listTools(t, s.client(t, "/mcp/owner", hdr, nil))
		if res.CacheScope != "private" || len(res.Tools) != 0 {
			t.Errorf("owner list by %s = %q with %d tools, want private and none yet", name, res.CacheScope, len(res.Tools))
		}
	}
	if res := listTools(t, s.client(t, "/mcp", nil, nil)); res.CacheScope != "public" {
		t.Errorf("public list scope = %q", res.CacheScope)
	}
}

// TestProtocolEras: the newest client (stateless, server/discover) and a
// 2025-11-25 one (initialize first) both list and call.
func TestProtocolEras(t *testing.T) {
	s := newStack(t, stackOpts{})
	cs := s.client(t, "/mcp/ip", nil, nil)
	if v := cs.InitializeResult().ProtocolVersion; v != "2026-07-28" {
		t.Errorf("SDK client negotiated %q, want 2026-07-28", v)
	}
	object(t, call(t, cs, "ip_cidr", map[string]any{"cidr": "10.0.0.0/8"}))

	const old = "2025-11-25"
	init := s.do(http.MethodPost, "/mcp/ip", rpc(1, "initialize", map[string]any{
		"protocolVersion": old, "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "raw", "version": "1"},
	}), mcpHeaders(nil))
	if b := init.Body.String(); init.Code != http.StatusOK || !strings.Contains(b, `"protocolVersion":"`+old+`"`) ||
		!strings.Contains(b, `"tools":{}`) || strings.Contains(b, "logging") {
		t.Fatalf("initialize = %d %s, want %s with tools and no listChanged or logging", init.Code, b, old)
	}
	hdr := mcpHeaders(map[string]string{"Mcp-Protocol-Version": old})
	note := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	if rec := s.do(http.MethodPost, "/mcp/ip", note, hdr); rec.Code != http.StatusAccepted {
		t.Errorf("notifications/initialized = %d, want 202", rec.Code)
	}
	list := s.do(http.MethodPost, "/mcp/ip", listBody, hdr)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"name":"ip_lookup"`) {
		t.Errorf("tools/list = %d %s", list.Code, list.Body)
	}
	got := s.do(http.MethodPost, "/mcp/ip", rpc(3, "tools/call", map[string]any{"name": "ip_cidr", "arguments": map[string]any{"cidr": "10.0.0.0/8"}}), hdr)
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `16777214`) {
		t.Errorf("tools/call = %d %s", got.Code, got.Body)
	}
}

// TestSubscriptionsListenReturns: with listChanged false there is nothing to
// listen for, so the stream must close at once instead of holding a goroutine
// and a connection per client.
func TestSubscriptionsListenReturns(t *testing.T) {
	s := newStack(t, stackOpts{})
	body := rpc(1, "subscriptions/listen", map[string]any{
		"_meta": map[string]any{
			"io.modelcontextprotocol/protocolVersion":    "2026-07-28",
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		},
		"notifications": map[string]any{"toolsListChanged": true},
	})
	done := make(chan int, 1)
	go func() {
		done <- s.do(http.MethodPost, "/mcp", body, mcpHeaders(map[string]string{
			"Mcp-Protocol-Version": "2026-07-28", "Mcp-Method": "subscriptions/listen",
		})).Code
	}()
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Errorf("subscriptions/listen = %d, want 200", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("subscriptions/listen held its stream open")
	}
}

func TestPanickingToolIsAnErrorAndTheProcessLives(t *testing.T) {
	s := newStack(t, stackOpts{geo: &fakeGeo{panic: true}})
	cs := s.client(t, "/mcp/ip", nil, nil)
	res := call(t, cs, "ip_lookup", map[string]any{"ip": "8.8.8.8"})
	if !res.IsError || !strings.Contains(text(t, res), "Internal error") || strings.Contains(text(t, res), "exploded") {
		t.Errorf("panicking tool = %q, want an internal error without the panic's text", text(t, res))
	}
	object(t, call(t, cs, "ip_cidr", map[string]any{"cidr": "10.0.0.0/8"}))
}

// TestRecordsNeverHoldArguments: the per-call log line names the endpoint,
// tool and outcome, never what was asked.
func TestRecordsNeverHoldArguments(t *testing.T) {
	var log syncBuffer
	s := newStack(t, stackOpts{log: &log})
	cs := s.client(t, "/mcp/ip", nil, nil)
	call(t, cs, "ip_cidr", map[string]any{"cidr": "172.31.255.0/24"})
	call(t, cs, "ip_cidr", map[string]any{"cidr": "secret-looking-input"})
	got := log.String()
	for _, want := range []string{`"msg":"MCP"`, `"uri":"/mcp/ip#ip_cidr"`, `"outcome":"ok"`, `"outcome":"tool_error"`, `"client":"mcptools-tests/1"`} {
		if !strings.Contains(got, want) {
			t.Errorf("log lacks %s:\n%s", want, got)
		}
	}
	for _, leak := range []string{"172.31.255", "secret-looking"} {
		if strings.Contains(got, leak) {
			t.Errorf("log holds an argument (%s):\n%s", leak, got)
		}
	}
}

// syncBuffer is a bytes.Buffer safe for the logger and the test at once.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.Reset()
}
