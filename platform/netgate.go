package platform

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Blocked address ranges beyond what netip's own predicates cover.
//
// IsGlobalUnicast/IsPrivate/IsLoopback/IsLinkLocalUnicast/IsMulticast/
// IsUnspecified between them miss several ranges that are either reachable
// inside a datacentre or a way to smuggle an IPv4 destination past an IPv6
// check. tools/botcheck's publicIP already carried cgnat; the rest are added
// here because this gate guards outbound connections to attacker-chosen hosts,
// which is a harder job than classifying a WebRTC candidate.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),   // RFC 6598 CGNAT
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // RFC 2544 benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64 — embeds IPv4
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("2002::/16"),       // 6to4 — embeds IPv4
	netip.MustParsePrefix("2001::/32"),       // Teredo — embeds IPv4
	netip.MustParsePrefix("fc00::/7"),        // unique local
	// ::/96 is RFC 4291's IPv4-compatible form and the ORIGINAL IPv4-embedding
	// prefix: ::127.0.0.1 is loopback wearing an IPv6 hat, and the stdlib
	// predicates miss it entirely (IsLoopback only matches ::1).
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("fec0::/10"),      // deprecated site-local
	netip.MustParsePrefix("192.88.99.0/24"), // 6to4 relay anycast
	netip.MustParsePrefix("100::/64"),       // discard-only
	netip.MustParsePrefix("2001:db8::/32"),  // documentation
}

// PubliclyRoutable reports whether addr is an address we are willing to open an
// outbound connection to. Unmaps first, so ::ffff:127.0.0.1 is judged as
// 127.0.0.1 rather than sailing through the IPv6 predicates.
//
// This is the whole of the SSRF defence's address half, so it is deliberately
// deny-by-default: anything not clearly a public unicast address is refused.
func PubliclyRoutable(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return false
	}
	if !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() ||
		addr.IsPrivate() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

var (
	// ErrBlockedAddress: the destination resolved to something we won't dial.
	ErrBlockedAddress = errors.New("destination address is not publicly routable")
	// ErrBlockedPort: the destination port is outside the allowlist.
	ErrBlockedPort = errors.New("destination port is not allowed")
)

// EgressGuard decides which outbound connections a feature may open. Zero value
// is unusable; build one with NewEgressGuard.
//
// The check runs in Dialer.Control, which fires after name resolution on the
// literal address the kernel is about to connect to. That placement is the
// point: there is no window between checking and connecting, so DNS rebinding
// has nothing to exploit, and it composes with Happy Eyeballs and multi-address
// fallback instead of fighting them.
//
// A Control hook only fires when a dial actually happens, so a transport using
// this guard must also set DisableKeepAlives — otherwise a pooled connection
// answers a second, unchecked authority. See
// tools/linktools/docs/06-security-and-abuse.md §2.
type EgressGuard struct {
	ports map[string]bool
	// denyHosts: lowercase hostnames refused before resolution (our own vhosts,
	// the database host). Belt and braces beyond the address check, since those
	// hosts resolve to public addresses and would otherwise pass.
	denyHosts map[string]bool
	// denyAddrs: this machine's own interface addresses, enumerated once at
	// startup. Stops a request looping back into the origin behind Cloudflare.
	denyAddrs map[netip.Addr]bool
	// allowLoopback: test-only seam. Never set in production; the constructor
	// leaves it false and nothing exported can change it.
	allowLoopback bool
}

// NewEgressGuard builds a guard allowing only the given ports, refusing the
// given hostnames, and refusing every address of every local interface.
//
// Enumerating local interfaces can fail on an unusual host; that is non-fatal
// and only forfeits the self-connection check, which the hostname deny list and
// the routable check already cover in the ordinary case.
func NewEgressGuard(ports []string, denyHosts []string) *EgressGuard {
	g := &EgressGuard{
		ports:     make(map[string]bool, len(ports)),
		denyHosts: make(map[string]bool, len(denyHosts)),
		denyAddrs: map[netip.Addr]bool{},
	}
	for _, p := range ports {
		g.ports[p] = true
	}
	for _, h := range denyHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		// Callers pass a bare host, a host:port, or a full URL of any scheme.
		// Parse rather than string-trim: a mongodb:// URI carries credentials
		// AND a port, so net.SplitHostPort rejects it ("too many colons") and a
		// TrimPrefix chain that only knows http(s) leaves it untouched — either
		// way the whole URI ends up as the map key and matches nothing, which
		// is a deny-list entry that silently is not there.
		if strings.Contains(h, "://") {
			u, err := url.Parse(h)
			if err != nil || u.Hostname() == "" {
				continue // unparseable: storing it whole would be a silent no-op
			}
			h = u.Hostname()
		} else if host, _, err := net.SplitHostPort(h); err == nil {
			h = host
		}
		g.denyHosts[strings.TrimSuffix(h, ".")] = true
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if na, ok := netip.AddrFromSlice(ip); ok {
				g.denyAddrs[na.Unmap()] = true
			}
		}
	}
	return g
}

// AllowHost reports whether a hostname may be dialled at all, before any
// resolution happens. Callers check this when they first see a URL, so a
// refusal can be reported as a finding rather than surfacing as a dial error.
func (g *EgressGuard) AllowHost(host string) error {
	if g == nil {
		return ErrBlockedAddress
	}
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return ErrBlockedAddress
	}
	if g.denyHosts[h] {
		return fmt.Errorf("%w: %s is not a permitted destination", ErrBlockedAddress, host)
	}
	// "localhost" and anything under it resolve to loopback on a normal host,
	// but a hostile resolver need not agree, so refuse by name too.
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, host)
	}
	// A bare IP literal in a URL never needs resolution; judge it now so the
	// caller gets a clear reason instead of a dial failure.
	if addr, err := netip.ParseAddr(h); err == nil {
		if !g.permitted(addr) {
			return fmt.Errorf("%w: %s", ErrBlockedAddress, addr)
		}
	}
	return nil
}

// AllowPort reports whether a port may be dialled.
func (g *EgressGuard) AllowPort(port string) error {
	if g == nil || !g.ports[port] {
		return fmt.Errorf("%w: %s", ErrBlockedPort, port)
	}
	return nil
}

func (g *EgressGuard) permitted(addr netip.Addr) bool {
	addr = addr.Unmap()
	if g.allowLoopback && addr.IsLoopback() {
		return true
	}
	if g.denyAddrs[addr] {
		return false
	}
	return PubliclyRoutable(addr)
}

// Control is the net.Dialer.Control hook. Assign it, don't call it.
//
//	d := &net.Dialer{Control: guard.Control}
func (g *EgressGuard) Control(_, address string, _ syscall.RawConn) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparseable address %q", ErrBlockedAddress, address)
	}
	if err := g.AllowPort(port); err != nil {
		return err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// Control is handed a literal address by the resolver. Anything else is
		// unexpected, so refuse rather than guess.
		return fmt.Errorf("%w: %q is not a literal address", ErrBlockedAddress, host)
	}
	if !g.permitted(addr) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, addr)
	}
	return nil
}

// Dialer returns a net.Dialer whose every connection passes Control.
func (g *EgressGuard) Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: g.Control}
}

// DialContext is the DialContext a guarded http.Transport should use.
func (g *EgressGuard) DialContext(timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	d := g.Dialer(timeout)
	return d.DialContext
}

// RateLimitKey normalises a client IP into a rate-limiting identifier.
//
// A bare IP is not a usable key over IPv6: an ordinary residential or mobile
// client is handed a /64, i.e. 2^64 addresses, so a per-address bucket is no
// limit at all — and every distinct address also allocates a bucket that is
// held for the store's expiry window, which makes it a memory-growth path too.
// IPv4 keys on the full address; IPv6 keys on the /64 prefix.
func RateLimitKey(ip string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	if p, err := addr.Prefix(64); err == nil {
		return p.String()
	}
	return addr.String()
}
