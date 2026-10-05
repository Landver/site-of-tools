package tests

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

var browser = map[string]string{"Accept": "text/html,application/xhtml+xml,*/*"}

func TestGate(t *testing.T) {
	s := newStack(t, stackOpts{})
	cases := []struct {
		name, method, target, body string
		hdr                        map[string]string
		code                       int
		want                       string // in the body
	}{
		{"browser GET /mcp is the page", http.MethodGet, "/mcp", "", browser, http.StatusOK, "ip_lookup"},
		{"browser GET of a toolset is the page", http.MethodGet, "/mcp/ip", "", browser, http.StatusOK, "<html"},
		{"unknown toolset", http.MethodPost, "/mcp/nope", listBody, mcpHeaders(nil), http.StatusNotFound, "No MCP endpoint"},
		{"empty toolset", http.MethodPost, "/mcp/", listBody, mcpHeaders(nil), http.StatusNotFound, "Not Found"},
		{"owner endpoint off without a key", http.MethodPost, "/mcp/owner", listBody, mcpHeaders(nil), http.StatusNotFound, "No MCP endpoint"},
		{"body over 1 MiB", http.MethodPost, "/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"x":"` + strings.Repeat("a", 1<<20) + `"}}`, mcpHeaders(nil), http.StatusRequestEntityTooLarge, "1 MiB"},
		{"batch", http.MethodPost, "/mcp", " \n[" + listBody + "," + listBody + "]", mcpHeaders(nil), http.StatusBadRequest, "batching is not supported"},
		{"cross-site browser", http.MethodPost, "/mcp", listBody, mcpHeaders(map[string]string{"Sec-Fetch-Site": "cross-site"}), http.StatusForbidden, "Cross-site"},
		{"same-origin browser", http.MethodPost, "/mcp", listBody, mcpHeaders(map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": base}), http.StatusOK, "ip_cidr"},
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
	s.do(http.MethodPost, "/mcp", listBody, mcpHeaders(map[string]string{"Origin": base}))
	if n := strings.Count(log.String(), "foreign Origin"); n != 1 {
		t.Errorf("%d foreign Origins logged, want 1: ours is not foreign", n)
	}
}

func TestOwnerKey(t *testing.T) {
	s := newStack(t, stackOpts{owner: offlineOwner(t)})
	try := func(ip string, hdr map[string]string) int {
		hdr = mcpHeaders(hdr)
		hdr["CF-Connecting-IP"] = ip
		return s.do(http.MethodPost, "/mcp/owner", listBody, hdr).Code
	}
	const guesser = "198.51.100.2"
	wrong := map[string]string{"X-Api-Key": "guess"}
	for i := range 5 {
		if code := try(guesser, wrong); code != http.StatusForbidden {
			t.Fatalf("wrong key, try %d = %d, want 403", i+1, code)
		}
	}
	refused := false
	for range 5 {
		if try(guesser, wrong) == http.StatusTooManyRequests {
			refused = true
			break
		}
	}
	if !refused {
		t.Errorf("never 429 after five wrong keys")
	}
	if code := try(guesser, map[string]string{"X-Api-Key": ownerKey}); code != http.StatusTooManyRequests {
		t.Errorf("the right key while locked out = %d, want 429 before it is compared", code)
	}

	// What a web page can make a browser send can't lock the owner out.
	for i, hdr := range []map[string]string{
		nil,
		{"Authorization": "Basic " + ownerKey},
		{"X-Api-Key": "guess", "Sec-Fetch-Site": "cross-site"},
		{"X-Api-Key": "guess", "Sec-Fetch-Site": "same-site"},
	} {
		ip := fmt.Sprintf("198.51.100.%d", 10+i)
		for n := range 10 {
			if code := try(ip, hdr); code != http.StatusForbidden {
				t.Fatalf("%v, try %d = %d, want 403", hdr, n+1, code)
			}
		}
		if code := try(ip, map[string]string{"X-Api-Key": ownerKey}); code != http.StatusOK {
			t.Errorf("%v ten times, then the right key = %d, want 200", hdr, code)
		}
	}
	if code := try("198.51.100.9", map[string]string{"Authorization": "bearer " + ownerKey}); code != http.StatusOK {
		t.Errorf("the key as a bearer token = %d, want 200", code)
	}

	page, unknown := s.do(http.MethodGet, "/mcp/owner", "", browser), s.do(http.MethodGet, "/mcp/nope", "", browser)
	if page.Code != http.StatusNotFound || page.Body.String() != unknown.Body.String() {
		t.Errorf("browser GET /mcp/owner = %d %.80q, want the unknown path's 404 %.80q", page.Code, page.Body, unknown.Body)
	}
	if code := s.do(http.MethodPost, "/mcp", listBody, mcpHeaders(map[string]string{"Authorization": "Bearer someone-elses"})).Code; code != http.StatusOK {
		t.Errorf("public endpoint with an unrelated bearer token = %d, want 200", code)
	}
}

func TestCapabilitiesAreToolsOnly(t *testing.T) {
	caps := newStack(t, stackOpts{}).client(t, "/mcp/ip", nil).InitializeResult().Capabilities
	if caps.Tools == nil || caps.Tools.ListChanged || caps.Logging != nil {
		t.Errorf("capabilities = %+v, want tools and no listChanged or logging", caps)
	}
}

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
	cs := newStack(t, stackOpts{geo: &fakeGeo{panic: true}}).client(t, "/mcp/ip", nil)
	res := call(t, cs, "ip_lookup", required["ip_lookup"])
	failsWith(t, res, "Internal error")
	if strings.Contains(text(t, res), "exploded") {
		t.Errorf("the panic's text reached the client: %q", text(t, res))
	}
	object(t, call(t, cs, "ip_cidr", required["ip_cidr"]))
}

func TestNullArgumentsAreNoArguments(t *testing.T) {
	var log syncBuffer
	s := newStack(t, stackOpts{log: &log})
	hdr := mcpHeaders(map[string]string{"Mcp-Protocol-Version": "2025-11-25"})
	for tool, wantErr := range map[string]bool{"cipher_random": false, "dns_lookup": true} {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":null}}`
		got := s.do(http.MethodPost, "/mcp", body, hdr).Body.String()
		if strings.Contains(got, `"isError":true`) != wantErr || strings.Contains(got, "Internal error") || wantErr && !strings.Contains(got, "name") {
			t.Errorf("%s with null arguments = %.300s, want isError %v", tool, got, wantErr)
		}
	}
	if strings.Contains(log.String(), "mcp: panic") {
		t.Errorf("null arguments panicked:\n%.400s", log.String())
	}
}

func TestRecordsNeverHoldArguments(t *testing.T) {
	var log syncBuffer
	cs := newStack(t, stackOpts{log: &log}).client(t, "/mcp/ip", nil)
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
