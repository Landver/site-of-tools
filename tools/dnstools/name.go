package dnstools

import (
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// NormalizeName turns what a visitor pastes into the name they meant. The
// input box is where a lookup tool meets copy-paste, and every shape handled
// here is one people paste: a whole URL, an email address, a host:port, a
// name in capitals or with its trailing root dot, and a Unicode name, which
// DNS only carries in its ASCII (punycode) spelling.
//
// It never refuses anything. Input that still isn't a name afterwards comes
// back trimmed, for validDomain to reject with a reason. An IP literal comes
// back as itself (bar IPv6 brackets): the lookup page turns it into a reverse
// lookup, and the other pages say they need a name.
func NormalizeName(raw string) string {
	s := strings.TrimSpace(raw)

	// A URL: the host is the only part DNS can use. url.Parse also drops the
	// port, the userinfo and the brackets round an IPv6 literal.
	if i := strings.Index(s, "://"); i >= 0 {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			s = u.Hostname()
		} else {
			// A URL url.Parse refuses ("https://example.com:abc/") still has
			// its scheme cut, or "https" is what gets looked up; the rest
			// goes through the same trimming as a scheme-less paste.
			s = s[i+3:]
		}
	}
	s = strings.TrimPrefix(s, "mailto:")
	// A scheme-less URL ("example.com/pricing"): everything from the path on
	// is not part of the name.
	if i := strings.IndexAny(s, "/?#"); i > 0 {
		s = s[:i]
	}
	// An email address: the domain is what has DNS records.
	if i := strings.LastIndexByte(s, '@'); i >= 0 && i < len(s)-1 {
		s = s[i+1:]
	}
	s = stripPort(s)

	s = strings.ToLower(s)
	// One trailing dot is the root, which every name here already ends in.
	s = strings.TrimSuffix(s, ".")
	return toASCII(s)
}

// stripPort drops ":443" from "example.com:443" and the brackets from
// "[2001:db8::1]:53", but leaves a bare IPv6 literal alone: its colons are
// the address, not a port.
func stripPort(s string) string {
	if net.ParseIP(s) != nil {
		return s
	}
	if host, _, err := net.SplitHostPort(s); err == nil && host != "" {
		return host
	}
	return strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
}

// toASCII converts each Unicode label to its punycode form, so "bücher.de"
// is asked as "xn--bcher-kva.de" rather than sent as raw UTF-8, which no
// resolver will find and every resolver answers with NXDOMAIN.
//
// Label by label, not the whole name at once: IDNA's lookup profile refuses
// the underscore, and "_dmarc.bücher.de" is a name worth asking about. A
// label that fails conversion is left as typed, for validDomain to refuse.
func toASCII(s string) string {
	if isASCII(s) {
		return s
	}
	// The ideographic full stops IDNA treats as dots, so a name typed with a
	// CJK input method splits where its writer meant it to.
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

// needDomain is validDomain for a check that only makes sense for a domain.
// An IP literal gets its own refusal instead of passing as four numeric
// labels.
func needDomain(name string) error {
	if net.ParseIP(name) != nil {
		return ErrNeedDomain
	}
	return validDomain(name)
}

// RegistrableDomain is the part of a name a registry holds a record for:
// github.com for www.github.com, example.co.uk for a.b.example.co.uk, per the
// Public Suffix List. A name that is itself a public suffix, or that the list
// can't place, comes back unchanged.
func RegistrableDomain(name string) string {
	if d, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
		return d
	}
	return name
}

// UnicodeName is the readable spelling of a punycode name, for showing beside
// the ASCII one DNS uses. Empty when the name has no punycode labels, or when
// one does not decode, so a caller can print it only when it adds something.
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
