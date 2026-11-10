package iptools

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

// Bogon & DROP prefix trie for sub-microsecond classification of unallocated,
// martian, or hijacked netblocks without hitting external databases.

type RadixTrie struct {
	root *radixNode
}

type radixNode struct {
	children [2]*radixNode
	isMatch  bool
	tag      string
}

// NewRadixTrie constructs an empty bitwise CIDR trie.
func NewRadixTrie() *RadixTrie {
	return &RadixTrie{root: &radixNode{}}
}

// Insert adds a prefix to the bitwise trie.
func (t *RadixTrie) Insert(pfx netip.Prefix, tag string) {
	if t == nil || !pfx.IsValid() {
		return
	}
	pfx = pfx.Masked()
	addr := pfx.Addr()
	bits := pfx.Bits()
	raw := addr.AsSlice()

	curr := t.root
	for i := 0; i < bits; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		bit := (raw[byteIdx] >> bitIdx) & 1

		if curr.children[bit] == nil {
			curr.children[bit] = &radixNode{}
		}
		curr = curr.children[bit]
	}
	curr.isMatch = true
	curr.tag = tag
}

// Match looks up the longest matching prefix for addr.
func (t *RadixTrie) Match(addr netip.Addr) (bool, string) {
	if t == nil || t.root == nil || !addr.IsValid() {
		return false, ""
	}
	addr = addr.Unmap()
	raw := addr.AsSlice()
	totalBits := addr.BitLen()

	curr := t.root
	matched := false
	tag := ""

	if curr.isMatch {
		matched = true
		tag = curr.tag
	}

	for i := 0; i < totalBits; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		bit := (raw[byteIdx] >> bitIdx) & 1

		if curr.children[bit] == nil {
			break
		}
		curr = curr.children[bit]
		if curr.isMatch {
			matched = true
			tag = curr.tag
		}
	}
	return matched, tag
}

// BogonEntry represents an IANA unallocated/reserved or Spamhaus DROP prefix.
type BogonCheckResult struct {
	IsBogon bool   `json:"is_bogon"`
	Tag     string `json:"tag,omitempty"`
	Details string `json:"details,omitempty"`
}

var (
	globalPrefixTrie atomic.Pointer[RadixTrie]
	// Standard IANA IPv4 and IPv6 bogon prefixes
	standardBogonPrefixes = []struct {
		cidr string
		tag  string
	}{
		// IPv4 Bogons (RFC 5735, RFC 6598, etc.)
		{"0.0.0.0/8", "RFC 1122 This host on this network"},
		{"10.0.0.0/8", "RFC 1918 Private-Use"},
		{"100.64.0.0/10", "RFC 6598 Shared Address Space (CGNAT)"},
		{"127.0.0.0/8", "RFC 1122 Loopback"},
		{"169.254.0.0/16", "RFC 3927 Link Local"},
		{"172.16.0.0/12", "RFC 1918 Private-Use"},
		{"192.0.0.0/24", "RFC 6890 IETF Protocol Assignments"},
		{"192.0.2.0/24", "RFC 5737 Documentation (TEST-NET-1)"},
		{"192.168.0.0/16", "RFC 1918 Private-Use"},
		{"198.18.0.0/15", "RFC 2544 Benchmarking"},
		{"198.51.100.0/24", "RFC 5737 Documentation (TEST-NET-2)"},
		{"203.0.113.0/24", "RFC 5737 Documentation (TEST-NET-3)"},
		{"224.0.0.0/4", "RFC 5771 Multicast"},
		{"240.0.0.0/4", "RFC 1112 Reserved for Future Use"},
		{"255.255.255.255/32", "RFC 919 Limited Broadcast"},

		// IPv6 Bogons (RFC 5156, RFC 3849, etc.)
		{"::/128", "RFC 4291 Unspecified"},
		{"::1/128", "RFC 4291 Loopback"},
		{"::ffff:0:0/96", "RFC 4291 IPv4-mapped"},
		{"100::/64", "RFC 6666 Discard-Only"},
		{"2001:db8::/32", "RFC 3849 Documentation"},
		{"fc00::/7", "RFC 4193 Unique Local (ULA)"},
		{"fe80::/10", "RFC 4291 Link-Local Unicast"},
		{"fec0::/10", "RFC 3879 Site-Local (Deprecated)"},
		{"ff00::/8", "RFC 4291 Multicast"},
	}
)

func init() {
	trie := NewRadixTrie()
	for _, b := range standardBogonPrefixes {
		if pfx, err := netip.ParsePrefix(b.cidr); err == nil {
			trie.Insert(pfx, b.tag)
		}
	}
	globalPrefixTrie.Store(trie)
}

// CheckBogon tests if an IP is a bogon or Spamhaus DROP entry.
func CheckBogon(ip string) BogonCheckResult {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return BogonCheckResult{}
	}
	trie := globalPrefixTrie.Load()
	if trie == nil {
		return BogonCheckResult{}
	}
	matched, tag := trie.Match(addr)
	if !matched {
		return BogonCheckResult{}
	}
	return BogonCheckResult{
		IsBogon: true,
		Tag:     tag,
		Details: tag,
	}
}

const (
	dropURL         = "https://www.spamhaus.org/drop/drop_v4.json"
	dropHTTPTimeout = 60 * time.Second
)

var dropHTTPClient = &http.Client{Timeout: dropHTTPTimeout}

type dropRecord struct {
	Type      string `json:"type"`
	CIDR      string `json:"cidr"`
	SBLID     string `json:"sblid"`
	Timestamp int64  `json:"timestamp"`
	Copyright string `json:"copyright"`
	Terms     string `json:"terms"`
}

// UpdatePrefixTrie parses DROP/EDROP lines and rebuilds the global atomic trie.
func UpdatePrefixTrie(dropReader io.Reader) int {
	trie := NewRadixTrie()
	// Re-insert base bogons
	for _, b := range standardBogonPrefixes {
		if pfx, err := netip.ParsePrefix(b.cidr); err == nil {
			trie.Insert(pfx, b.tag)
		}
	}

	count := 0
	if dropReader != nil {
		sc := bufio.NewScanner(dropReader)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var rec dropRecord
			if json.Unmarshal([]byte(line), &rec) != nil || rec.Type == "metadata" || rec.CIDR == "" {
				continue
			}
			if pfx, err := netip.ParsePrefix(rec.CIDR); err == nil {
				trie.Insert(pfx, "Spamhaus DROP: "+rec.SBLID)
				count++
			}
		}
	}

	globalPrefixTrie.Store(trie)
	return count
}

// RunSpamhausTrieSync periodically syncs DROP and reloads the memory trie.
func RunSpamhausTrieSync(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	sync := func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, dropURL, nil)
		if err != nil {
			return
		}
		resp, err := dropHTTPClient.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			UpdatePrefixTrie(resp.Body)
		}
	}

	sync()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sync()
		}
	}
}
