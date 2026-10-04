package dnstools

import (
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// NormalizeName turns pasted input into the name meant: a URL's host, an
// email's domain, host:port without the port, lowercase, no trailing dot,
// Unicode as punycode. It never refuses; validDomain does that.
func NormalizeName(raw string) string {
	s := strings.TrimSpace(raw)

	// url.Parse also drops the port, userinfo and IPv6 brackets.
	if i := strings.Index(s, "://"); i >= 0 {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			s = u.Hostname()
		} else {
			// url.Parse refused it: cut the scheme by hand.
			s = s[i+3:]
		}
	}
	s = strings.TrimPrefix(s, "mailto:")
	// A scheme-less URL: the path isn't part of the name.
	if i := strings.IndexAny(s, "/?#"); i > 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 && i < len(s)-1 {
		s = s[i+1:]
	}
	s = stripPort(s)

	s = strings.ToLower(s)
	s = strings.TrimSuffix(s, ".")
	return toASCII(s)
}

// stripPort drops a port and IPv6 brackets; a bare IPv6 literal is left alone.
func stripPort(s string) string {
	if net.ParseIP(s) != nil {
		return s
	}
	if host, _, err := net.SplitHostPort(s); err == nil && host != "" {
		return host
	}
	return strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
}

// toASCII converts Unicode labels to punycode, label by label: IDNA's lookup
// profile refuses the underscore in names like _dmarc.bücher.de.
func toASCII(s string) string {
	if isASCII(s) {
		return s
	}
	// Ideographic full stops count as dots in IDNA.
	s = strings.NewReplacer("。", ".", "．", ".", "｡", ".").Replace(s)
	labels := strings.Split(s, ".")
	for i, l := range labels {
		if isASCII(l) {
			continue
		}
		if a, err := idna.Lookup.ToASCII(l); err == nil {
			labels[i] = a
		}
	}
	return strings.Join(labels, ".")
}

// needDomain is validDomain that also refuses an IP.
func needDomain(name string) error {
	if net.ParseIP(name) != nil {
		return ErrNeedDomain
	}
	return validDomain(name)
}

// RegistrableDomain: the name a registry holds a record for, per the Public
// Suffix List (github.com for www.github.com); unchanged if the list can't say.
func RegistrableDomain(name string) string {
	if d, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
		return d
	}
	return name
}

// UnicodeName: the readable spelling of a punycode name, or "" if there is none.
func UnicodeName(name string) string {
	if !strings.Contains(name, "xn--") {
		return ""
	}
	u, err := idna.ToUnicode(name)
	if err != nil || u == name {
		return ""
	}
	return u
}
