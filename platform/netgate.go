package platform

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Ranges netip's predicates miss: reachable inside a datacentre, or an IPv4 destination smuggled in IPv6.
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
	// ::/96 is RFC 4291's IPv4-compatible form: ::127.0.0.1 is loopback, yet IsLoopback only matches ::1.
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("fec0::/10"),      // deprecated site-local
	netip.MustParsePrefix("192.88.99.0/24"), // 6to4 relay anycast
	netip.MustParsePrefix("100::/64"),       // discard-only
	netip.MustParsePrefix("2001:db8::/32"),  // documentation
}

// PubliclyRoutable is the deny-by-default SSRF address check; unmapping judges ::ffff:127.0.0.1 as IPv4.
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
	ErrBlockedAddress = errors.New("destination address is not publicly routable")
	ErrBlockedPort    = errors.New("destination port is not allowed")
)

// EgressGuard checks in Dialer.Control, on the literal address after resolution, so DNS rebinding has no
// window. Control fires only on a real dial, so its transport must set DisableKeepAlives or a pooled
// connection answers a second, unchecked host (tools/linktools/docs/06-security-and-abuse.md §2).
type EgressGuard struct {
	ports map[string]bool
	// denyHosts: our own vhosts and the DB host resolve to public addresses, so they are refused by name.
	denyHosts map[string]bool
	// denyAddrs, denyPrefixes stop a request looping back into the origin behind Cloudflare.
	denyAddrs    map[netip.Addr]bool
	denyPrefixes []netip.Prefix
	// allowLoopback is a test-only seam; nothing exported can set it.
	allowLoopback bool
}

// NewEgressGuard also denies every local interface address; failing to list them only loses that check.
func NewEgressGuard(ports []string, deny []string) *EgressGuard {
	g := &EgressGuard{
		ports:     make(map[string]bool, len(ports)),
		denyHosts: make(map[string]bool, len(deny)),
		denyAddrs: map[netip.Addr]bool{},
	}
	for _, p := range ports {
		g.ports[p] = true
	}
	for _, h := range deny {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if p, err := netip.ParsePrefix(h); err == nil {
			g.denyPrefixes = append(g.denyPrefixes, p.Masked())
			continue
		}
		// Parse, don't trim: a mongodb:// URI with credentials and a port defeats SplitHostPort and an
		// http(s)-only trim, leaving the whole URI as a deny entry that silently matches nothing.
		if strings.Contains(h, "://") {
			u, err := url.Parse(h)
			if err != nil || u.Hostname() == "" {
				continue // unparseable: storing it whole would be a silent no-op
			}
			h = u.Hostname()
		} else if host, _, err := net.SplitHostPort(h); err == nil {
			h = host
		}
		h = strings.TrimSuffix(strings.Trim(h, "[]"), ".")
		if a, err := netip.ParseAddr(h); err == nil {
			g.denyAddrs[a.Unmap().WithZone("")] = true
			continue
		}
		g.denyHosts[h] = true
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

// AllowHost runs before resolution, so a refusal is reported as a finding rather than a dial error.
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
	// A hostile resolver needn't map localhost to loopback, so refuse it by name.
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, host)
	}
	// An IP literal needs no resolution; judge it now for a clear reason instead of a dial failure.
	if addr, err := netip.ParseAddr(h); err == nil {
		return g.AllowAddr(addr)
	}
	return nil
}

// AllowAddr is Control without the port check, for DNS probes to port 53.
func (g *EgressGuard) AllowAddr(addr netip.Addr) error {
	if g == nil || !g.permitted(addr) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, addr)
	}
	return nil
}

func (g *EgressGuard) AllowPort(port string) error {
	if g == nil || !g.ports[port] {
		return fmt.Errorf("%w: %s", ErrBlockedPort, port)
	}
	return nil
}

func (g *EgressGuard) permitted(addr netip.Addr) bool {
	// A zoned address never equals a map key or falls inside a prefix.
	addr = addr.Unmap().WithZone("")
	if g.allowLoopback && addr.IsLoopback() {
		return true
	}
	if g.denyAddrs[addr] {
		return false
	}
	for _, p := range g.denyPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return PubliclyRoutable(addr)
}

// Control is the net.Dialer.Control hook. Assign it, don't call it.
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
		// The resolver hands Control a literal address; anything else is unexpected, so refuse.
		return fmt.Errorf("%w: %q is not a literal address", ErrBlockedAddress, host)
	}
	return g.AllowAddr(addr)
}

// Dialer returns a net.Dialer whose every connection passes Control.
func (g *EgressGuard) Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: g.Control}
}

func (g *EgressGuard) DialContext(timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	d := g.Dialer(timeout)
	return d.DialContext
}

// Transport dials every request afresh and unproxied, so g judges each real destination.
func (g *EgressGuard) Transport(timeout time.Duration) *http.Transport {
	return &http.Transport{Proxy: nil, DialContext: g.DialContext(timeout), DisableKeepAlives: true}
}

// RateLimitKey keys IPv6 on its /64, since one client gets 2^64 addresses and each would hold a bucket;
// unparseable junk, such as a forged CF-Connecting-IP, shares one bucket.
func RateLimitKey(ip string) string {
	s := strings.TrimSpace(ip)
	if addr, err := netip.ParseAddr(s); err == nil {
		addr = addr.Unmap()
		if addr.Is4() {
			return addr.String()
		}
		p, _ := addr.Prefix(64)
		return p.String()
	}
	if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Is6() && p.Bits() == 64 {
		return p.Masked().String()
	}
	return "unknown"
}
