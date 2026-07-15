package iptools

import (
	"context"
	"net"
	"strings"
	"time"
)

// ReverseDNS is a best-effort PTR lookup for an IP: it returns the first hostname
// (trailing dot trimmed), or "" on any error, empty result, or timeout. It is
// bounded so a slow or missing resolver can't stall a page render, and it is the
// default resolver the handler injects (override in tests via WithReverseDNS).
func ReverseDNS(ip string) string {
	if ip == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
