package tests

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"syscall"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/platform"
)

// TestPubliclyRoutable is the highest-value test in the suite: it is the whole
// address half of the SSRF defence, and it needs no server, no network and no
// fixtures. Every entry is a range that is either reachable inside a datacentre
// or a way to smuggle an IPv4 destination past an IPv6 check.
func TestPubliclyRoutable(t *testing.T) {
	blocked := []struct{ addr, why string }{
		{"127.0.0.1", "loopback"},
		{"127.0.0.53", "loopback, systemd-resolved"},
		{"::1", "IPv6 loopback"},
		{"::ffff:127.0.0.1", "IPv4-mapped loopback — must be unmapped before judging"},
		{"10.0.0.1", "RFC 1918"},
		{"172.16.0.1", "RFC 1918"},
		{"192.168.1.1", "RFC 1918"},
		{"169.254.169.254", "cloud metadata endpoint"},
		{"169.254.1.1", "link-local"},
		{"100.64.0.1", "CGNAT (RFC 6598) — global unicast and not private, so the stdlib predicates miss it"},
		{"0.0.0.0", "unspecified"},
		{"0.1.2.3", "0.0.0.0/8"},
		{"192.0.0.1", "IETF protocol assignments"},
		{"192.0.2.1", "TEST-NET-1"},
		{"198.18.0.1", "RFC 2544 benchmarking"},
		{"198.51.100.1", "TEST-NET-2"},
		{"203.0.113.1", "TEST-NET-3"},
		{"240.0.0.1", "reserved"},
		{"255.255.255.255", "broadcast"},
		{"224.0.0.1", "multicast"},
		{"fc00::1", "unique local"},
		{"fe80::1", "IPv6 link-local"},
		{"ff02::1", "IPv6 multicast"},
		{"::", "IPv6 unspecified"},
		{"64:ff9b::7f00:1", "NAT64 embedding 127.0.0.1"},
		{"2002:7f00:1::", "6to4 embedding 127.0.0.1"},
		{"2001::1", "Teredo"},
		{"::127.0.0.1", "RFC 4291 IPv4-compatible — the original IPv4-embedding prefix, and IsLoopback only matches ::1"},
		{"fec0::1", "deprecated site-local"},
		{"192.88.99.1", "6to4 relay anycast"},
		{"100::1", "discard-only"},
		{"2001:db8::1", "documentation"},
	}
	for _, c := range blocked {
		addr, err := netip.ParseAddr(c.addr)
		if err != nil {
			t.Fatalf("test data %q does not parse: %v", c.addr, err)
		}
		if platform.PubliclyRoutable(addr) {
			t.Errorf("PubliclyRoutable(%s) = true, want false — %s", c.addr, c.why)
		}
	}

	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946", "2001:4860:4860::8888"}
	for _, a := range allowed {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			t.Fatalf("test data %q does not parse: %v", a, err)
		}
		if !platform.PubliclyRoutable(addr) {
			t.Errorf("PubliclyRoutable(%s) = false, want true — this is an ordinary public address", a)
		}
	}
}

// TestEgressGuardPorts: the port allowlist is a first-class control, not an
// anti-scanning nicety. Without it, a public-but-firewalled service (the Mongo
// host is reached by a public name on an IP allowlist) is dialled from the one
// source address its firewall trusts.
func TestEgressGuardPorts(t *testing.T) {
	g := platform.NewEgressGuard([]string{"80", "443"}, nil)
	for _, p := range []string{"80", "443"} {
		if err := g.AllowPort(p); err != nil {
			t.Errorf("AllowPort(%s) = %v, want nil", p, err)
		}
	}
	for _, p := range []string{"22", "25", "3306", "27017", "6379", "9200", "8080"} {
		if err := g.AllowPort(p); err == nil {
			t.Errorf("AllowPort(%s) = nil, want refused", p)
		}
	}
}

// TestEgressGuardHosts: names refused before resolution, plus IP literals
// judged immediately so the caller gets a reason rather than a dial error.
func TestEgressGuardHosts(t *testing.T) {
	// The mongodb:// form is the one that used to break: it carries credentials
	// and a port, so SplitHostPort rejects it and a TrimPrefix chain that only
	// knows http(s) leaves it whole — a deny entry that silently matches nothing.
	g := platform.NewEgressGuard([]string{"80", "443"}, []string{
		"link.corpberry.com",
		"https://mongo.example.com:27017",
		"mongodb://appuser:pw@db.example.net:27017/site-of-tools?authSource=admin",
	})

	refused := []string{
		"localhost", "LOCALHOST", "foo.localhost",
		"link.corpberry.com", "LINK.CORPBERRY.COM", "link.corpberry.com.",
		"mongo.example.com", "db.example.net",
		"127.0.0.1", "169.254.169.254", "10.0.0.1", "::1", "100.64.0.1",
	}
	for _, h := range refused {
		if err := g.AllowHost(h); err == nil {
			t.Errorf("AllowHost(%q) = nil, want refused", h)
		}
	}
	for _, h := range []string{"example.com", "8.8.8.8", "sub.example.co.uk"} {
		if err := g.AllowHost(h); err != nil {
			t.Errorf("AllowHost(%q) = %v, want nil", h, err)
		}
	}
}

// TestNilGuardFailsClosed. A nil guard must refuse everything, not permit it.
func TestNilGuardFailsClosed(t *testing.T) {
	var g *platform.EgressGuard
	if err := g.AllowHost("example.com"); err == nil {
		t.Error("nil guard permitted a host; it must fail closed")
	}
	if err := g.AllowPort("443"); err == nil {
		t.Error("nil guard permitted a port; it must fail closed")
	}
}

// TestRateLimitKey: a bare IP is not a usable key over IPv6, where an ordinary
// client holds a /64 — 2^64 addresses, so a per-address bucket is no limit at
// all and each distinct address also allocates memory for the expiry window.
func TestRateLimitKey(t *testing.T) {
	if got := platform.RateLimitKey("8.8.8.8"); got != "8.8.8.8" {
		t.Errorf("IPv4 key = %q, want the full address", got)
	}
	a := platform.RateLimitKey("2001:db8:1:2:aaaa::1")
	b := platform.RateLimitKey("2001:db8:1:2:bbbb::2")
	if a != b {
		t.Errorf("two addresses in one /64 gave different keys (%q vs %q); the whole prefix must share a bucket", a, b)
	}
	c := platform.RateLimitKey("2001:db8:1:3::1")
	if a == c {
		t.Errorf("addresses in different /64s share a key (%q); that would over-block", a)
	}
	if got := platform.RateLimitKey("not an ip"); got != "not an ip" {
		t.Errorf("unparseable input = %q, want it passed through unchanged", got)
	}
}

// TestEgressGuardControl covers the hook itself, not the predicates underneath
// it. PubliclyRoutable can be perfect and the guard still useless: Control is
// where the port allowlist, the self-connection check and the routable check
// are actually composed, and it is the last thing to run before the kernel
// connects. It is also the only one of these that the resolver calls with a
// literal address, which is what makes DNS rebinding a non-issue — so a
// hostname arriving here means something is wrong and must be refused, never
// resolved a second time.
func TestEgressGuardControl(t *testing.T) {
	g := platform.NewEgressGuard([]string{"80", "443"}, nil)

	cases := []struct {
		name    string
		address string
		want    error // nil = the dial must be permitted
		why     string
	}{
		{"public IPv4, allowed port", "93.184.216.34:443", nil,
			"an ordinary outbound HTTPS fetch is the whole point of the dialer"},
		{"public IPv6, allowed port", "[2606:2800:220:1:248:1893:25c8:1946]:80", nil,
			"IPv6 destinations must not be refused wholesale"},
		{"loopback", "127.0.0.1:443", platform.ErrBlockedAddress,
			"a redirect chain ending at 127.0.0.1 reaches this box's own services"},
		{"IPv6 loopback", "[::1]:443", platform.ErrBlockedAddress,
			"the v6 spelling of the same reach"},
		{"IPv4-mapped loopback", "[::ffff:127.0.0.1]:443", platform.ErrBlockedAddress,
			"unmapping has to happen here too, not only in PubliclyRoutable's own tests"},
		{"private RFC 1918", "10.0.0.1:443", platform.ErrBlockedAddress,
			"the LAN behind this host is exactly what SSRF is fishing for"},
		{"cloud metadata", "169.254.169.254:80", platform.ErrBlockedAddress,
			"the classic credential-theft destination"},
		{"CGNAT", "100.64.0.1:443", platform.ErrBlockedAddress,
			"global unicast and not private, so only the explicit prefix list catches it"},
		{"blocked port on a public address", "93.184.216.34:27017", platform.ErrBlockedPort,
			"a public-but-firewalled service (the Mongo host) is dialled from the one source address its firewall trusts"},
		{"blocked port on a loopback address", "127.0.0.1:22", platform.ErrBlockedPort,
			"port and address are separate controls; either alone must refuse"},
		{"unparseable address", "not-an-address", platform.ErrBlockedAddress,
			"anything Control cannot parse it cannot judge, so it must fail closed"},
		{"no port at all", "93.184.216.34", platform.ErrBlockedAddress,
			"same: unparseable is unjudgeable"},
		{"empty address", "", platform.ErrBlockedAddress,
			"same"},
		{"hostname instead of a literal", "example.com:443", platform.ErrBlockedAddress,
			"the resolver hands Control literals; a name here means the check was bypassed, and resolving it again would reopen the rebinding window"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := g.Control("tcp", c.address, nil)
			switch {
			case c.want == nil && err != nil:
				t.Errorf("Control(%q) = %v, want permitted — %s", c.address, err, c.why)
			case c.want != nil && err == nil:
				t.Errorf("Control(%q) permitted the dial, want refused — %s", c.address, c.why)
			case c.want != nil && !errors.Is(err, c.want):
				t.Errorf("Control(%q) = %v, want an error wrapping %v — callers switch on these, so the wrong sentinel is reported to the visitor as the wrong finding", c.address, err, c.want)
			}
		})
	}

	// A nil guard reaching Control must refuse rather than panic or permit: nil
	// is how "this feature is not configured" propagates through the wiring.
	t.Run("nil guard", func(t *testing.T) {
		var nilGuard *platform.EgressGuard
		if err := nilGuard.Control("tcp", "93.184.216.34:443", nil); err == nil {
			t.Error("nil guard permitted a dial in Control; it must fail closed")
		}
	})

	// syscall.RawConn is ignored by this implementation, and the signature has
	// to stay assignable to net.Dialer.Control or the whole gate silently
	// detaches. Assigning it here is the compile-time half of that check.
	var _ func(string, string, syscall.RawConn) error = g.Control
}

// TestGuardedDialerRefusesLoopback is the end-to-end assertion: a real dial, to
// a real listening server, through the dialer the features actually use.
//
// Everything above tests the guard's opinion. This tests that the opinion is
// WIRED — that Control is still attached to the Dialer, and to the DialContext
// an http.Transport is built from. Deleting `Control: g.Control` from Dialer
// leaves every predicate test green and the tool wide open, so this is the one
// that has to fail.
//
// The server's own port is put on the allowlist on purpose: it removes the port
// check as an explanation, leaving the address check as the only thing that can
// refuse the connection.
func TestGuardedDialerRefusesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("httptest server URL %q does not parse: %v", srv.URL, err)
	}
	g := platform.NewEgressGuard([]string{u.Port()}, nil)

	t.Run("Dialer", func(t *testing.T) {
		conn, err := g.Dialer(2*time.Second).Dial("tcp", u.Host)
		if err == nil {
			conn.Close()
			t.Fatalf("dialed %s successfully — the guard is not attached to Dialer, so every outbound fetch is unchecked", u.Host)
		}
		if !errors.Is(err, platform.ErrBlockedAddress) {
			t.Errorf("dial error = %v, want one wrapping ErrBlockedAddress — a refusal that does not carry the sentinel is reported as a network failure instead of a blocked destination", err)
		}
	})

	t.Run("DialContext", func(t *testing.T) {
		conn, err := g.DialContext(2*time.Second)(t.Context(), "tcp", u.Host)
		if err == nil {
			conn.Close()
			t.Fatalf("DialContext reached %s — this is the one an http.Transport is built from, so an unguarded copy here means every HTTP feature is unguarded", u.Host)
		}
		if !errors.Is(err, platform.ErrBlockedAddress) {
			t.Errorf("DialContext error = %v, want one wrapping ErrBlockedAddress", err)
		}
	})

	// The shape a feature actually uses: a transport whose DialContext is the
	// guard's. DisableKeepAlives mirrors the production requirement documented
	// on EgressGuard (a pooled connection would answer a second, unchecked
	// authority).
	t.Run("http.Client", func(t *testing.T) {
		client := &http.Client{Transport: &http.Transport{
			DialContext:       g.DialContext(2 * time.Second),
			DisableKeepAlives: true,
		}}
		resp, err := client.Get(srv.URL)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("fetched %s through the guarded transport — a visitor-supplied URL pointing at loopback would be fetched and its body rendered back", srv.URL)
		}
		if !errors.Is(err, platform.ErrBlockedAddress) {
			t.Errorf("client error = %v, want one wrapping ErrBlockedAddress", err)
		}
	})
}
