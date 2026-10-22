package iptools

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net/netip"
	"strings"
)

// Counts are strings because an IPv6 block's address count overflows uint64.
type Subnet struct {
	CIDR      string `json:"cidr"`
	Family    string `json:"family"` // "IPv4" or "IPv6"
	Prefix    int    `json:"prefix_length"`
	Network   string `json:"network"`
	Broadcast string `json:"broadcast,omitempty"` // IPv4, prefixes /30 and shorter
	Netmask   string `json:"netmask,omitempty"`   // IPv4 only
	Wildcard  string `json:"wildcard,omitempty"`  // IPv4 only
	FirstHost string `json:"first_host"`
	LastHost  string `json:"last_host"`
	Usable    string `json:"usable_hosts"`
	Total     string `json:"total_addresses"`
}

// ParseSubnet treats a bare IP as a /32 or /128 network; pure, no DB or network.
func ParseSubnet(s string) (*Subnet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("enter a CIDR, e.g. 192.168.1.0/24 or 2001:db8::/32")
	}
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
	hostBits := network.BitLen() - bits
	last := lastAddr(pfx)

	total := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
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
		case bits == 32:
			sub.FirstHost, sub.LastHost, sub.Usable = network.String(), network.String(), "1"
		case bits == 31: // RFC 3021 point-to-point: both addrs usable, no broadcast
			sub.FirstHost, sub.LastHost, sub.Usable = network.String(), last.String(), "2"
		default:
			sub.Broadcast = last.String()
			sub.FirstHost = network.Next().String()
			sub.LastHost = last.Prev().String()
			sub.Usable = new(big.Int).Sub(total, big.NewInt(2)).String()
		}
	} else {
		sub.Family = "IPv6"
		// IPv6 has no broadcast convention, so every address counts as usable.
		sub.FirstHost, sub.LastHost, sub.Usable = network.String(), last.String(), total.String()
	}
	return sub, nil
}

// Go yields 0 for a full-width shift, so /32 correctly gets an empty host mask.
func v4HostMask(bits int) uint32 { return uint32(0xffffffff) >> uint(bits) }

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
		v[i] |= byte(0xff) >> (8 - n)
		host -= n
	}
	return netip.AddrFrom16(v)
}

func v4Masks(bits int) (netmask, wildcard string) {
	host := v4HostMask(bits)
	var nm, wc [4]byte
	binary.BigEndian.PutUint32(nm[:], ^host)
	binary.BigEndian.PutUint32(wc[:], host)
	return netip.AddrFrom4(nm).String(), netip.AddrFrom4(wc).String()
}

// ipv4RangeBounds returns inclusive IPv4 bounds for cidr; ok=false for IPv6 or unparseable input.
func ipv4RangeBounds(cidr string) (start, end uint32, ok bool) {
	pfx, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || !pfx.Addr().Is4() {
		return 0, 0, false
	}
	pfx = pfx.Masked()
	return ipv4Uint32(pfx.Addr()), ipv4Uint32(lastAddr(pfx)), true
}

// ipv4Uint32 gives a comparable, indexable form, unlike the address string.
func ipv4Uint32(a netip.Addr) uint32 {
	v := a.As4()
	return binary.BigEndian.Uint32(v[:])
}
