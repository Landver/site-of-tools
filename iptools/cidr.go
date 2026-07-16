package iptools

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net/netip"
	"strings"
)

// Subnet is the calculated view of a CIDR block, rendered as HTML or JSON. Counts
// are strings because an IPv6 block's address count overflows uint64.
type Subnet struct {
	CIDR      string `json:"cidr"`                // canonical network, e.g. 192.168.1.0/24
	Family    string `json:"family"`              // "IPv4" or "IPv6"
	Prefix    int    `json:"prefix_length"`       // e.g. 24
	Network   string `json:"network"`             // network address
	Broadcast string `json:"broadcast,omitempty"` // IPv4, prefixes /30 and shorter
	Netmask   string `json:"netmask,omitempty"`   // IPv4 only
	Wildcard  string `json:"wildcard,omitempty"`  // IPv4 only
	FirstHost string `json:"first_host"`
	LastHost  string `json:"last_host"`
	Usable    string `json:"usable_hosts"`    // usable host count
	Total     string `json:"total_addresses"` // total addresses in the block
}

// ParseSubnet parses a CIDR (or a bare IP, treated as /32 or /128) and computes
// its network properties. Pure and offline — no databases, no network.
func ParseSubnet(s string) (*Subnet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("enter a CIDR, e.g. 192.168.1.0/24 or 2001:db8::/32")
	}
	// Be lenient: a bare address is its own single-host network.
	if !strings.Contains(s, "/") {
		if a, err := netip.ParseAddr(s); err == nil {
			s = fmt.Sprintf("%s/%d", a, a.BitLen())
		}
	}
	pfx, err := netip.ParsePrefix(s)
	if err != nil {
		return nil, fmt.Errorf("%q is not valid CIDR notation (try 192.168.1.0/24 or 2001:db8::/32)", s)
	}
	pfx = pfx.Masked()
	network := pfx.Addr()
	bits := pfx.Bits()
	hostBits := network.BitLen() - bits // 32-bits (v4) or 128-bits (v6)
	last := lastAddr(pfx)

	total := new(big.Int).Lsh(big.NewInt(1), uint(hostBits)) // 2^hostBits
	sub := &Subnet{
		CIDR:    pfx.String(),
		Prefix:  bits,
		Network: network.String(),
		Total:   total.String(),
	}

	if network.Is4() {
		sub.Family = "IPv4"
		sub.Netmask, sub.Wildcard = v4Masks(bits)
		switch {
		case bits == 32: // single host
			sub.FirstHost, sub.LastHost, sub.Usable = network.String(), network.String(), "1"
		case bits == 31: // RFC 3021 point-to-point: both addresses usable, no broadcast
			sub.FirstHost, sub.LastHost, sub.Usable = network.String(), last.String(), "2"
		default:
			sub.Broadcast = last.String()
			sub.FirstHost = network.Next().String()
			sub.LastHost = last.Prev().String()
			sub.Usable = new(big.Int).Sub(total, big.NewInt(2)).String()
		}
	} else {
		sub.Family = "IPv6"
		// IPv6 has no broadcast/netmask/wildcard convention; treat all as usable.
		sub.FirstHost, sub.LastHost, sub.Usable = network.String(), last.String(), total.String()
	}
	return sub, nil
}

// v4HostMask returns the trailing host-bit mask for an IPv4 prefix length: the low
// (32-bits) bits set. Go zeroes a shift by the full width, so /32 correctly yields
// 0. Shared by lastAddr and v4Masks so the /32 edge case lives in one place.
func v4HostMask(bits int) uint32 { return uint32(0xffffffff) >> uint(bits) }

// lastAddr returns the highest address in the prefix (all host bits set to 1).
func lastAddr(pfx netip.Prefix) netip.Addr {
	if pfx.Addr().Is4() {
		v := pfx.Addr().As4()
		host := v4HostMask(pfx.Bits())
		binary.BigEndian.PutUint32(v[:], binary.BigEndian.Uint32(v[:])|host)
		return netip.AddrFrom4(v)
	}
	v := pfx.Addr().As16()
	host := 128 - pfx.Bits()
	for i := 15; i >= 0 && host > 0; i-- {
		n := host
		if n > 8 {
			n = 8
		}
		v[i] |= byte(0xff) >> (8 - n) // set the low n bits of this byte
		host -= n
	}
	return netip.AddrFrom16(v)
}

// v4Masks returns the dotted netmask and wildcard mask for an IPv4 prefix length.
func v4Masks(bits int) (netmask, wildcard string) {
	host := v4HostMask(bits)
	var nm, wc [4]byte
	binary.BigEndian.PutUint32(nm[:], ^host)
	binary.BigEndian.PutUint32(wc[:], host)
	return netip.AddrFrom4(nm).String(), netip.AddrFrom4(wc).String()
}
