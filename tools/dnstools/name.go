package dnstools

import (
	"net"
	"net/url"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// NormalizeName turns a pasted URL, email or host:port into the bare ASCII name; it never refuses.
func NormalizeName(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	s = strings.TrimPrefix(s, "mailto:")
	if i := strings.IndexAny(s, "/?#"); i > 0 {
		s = s[:i]
	}
	// As a URL authority it loses userinfo, port and brackets; a bare IPv6 literal would lose its last group.
	if net.ParseIP(s) == nil {
		if u, err := url.Parse("//" + s); err == nil && u.Hostname() != "" {
			s = u.Hostname()
		}
	}
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if !isASCII(s) {
		if a, err := idnaNames.ToASCII(s); err == nil {
			s = a
		}
	}
	return s
}

// idnaNames is IDNA's lookup mapping without its STD3 rule, which refuses the _ in _dmarc.bücher.de.
var idnaNames = idna.New(idna.MapForLookup(), idna.StrictDomainName(false))

func isASCII(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return r >= utf8.RuneSelf })
}

// bareName lowercases a name and drops its trailing dot, so two spellings compare equal.
func bareName(s string) string {
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

// needDomain is validDomain that also refuses an IP.
func needDomain(name string) error {
	if net.ParseIP(name) != nil {
		return ErrNeedDomain
	}
	return validDomain(name)
}

// RegistrableDomain: the PSL's registrable name (github.com for www.github.com), else name.
func RegistrableDomain(name string) string {
	if d, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
		return d
	}
	return name
}

// UnicodeName: the readable spelling of a punycode name, or "" if there is none.
func UnicodeName(name string) string {
	u, err := idna.ToUnicode(name)
	if err != nil || u == name {
		return ""
	}
	return u
}
