package linktools

import (
	"fmt"
	"net/url"
	"strings"
)

// Rebuild turns an edited Inspection back into a URL. Rebuild(Parse(u)) must round-trip, so nothing
// normalises, and a part that can't be written back faithfully is an error, never a near miss.
// Input and empty pairs ("?a=1&&b=2") are deliberately not reproduced.
func (s *Service) Rebuild(in *Inspection) (string, error) {
	if in == nil {
		return "", fmt.Errorf("nothing to rebuild")
	}
	if in.HasPass {
		// The password is never stored; leaving it out would hand over a different URL that looks fine.
		return "", fmt.Errorf("this URL carries a password in its userinfo, which is never stored, so it cannot be rebuilt")
	}

	var b strings.Builder
	if in.Scheme != "" {
		b.WriteString(in.Scheme)
		b.WriteByte(':')
	}

	if in.Opaque != "" {
		// Parse keeps an opaque tail ("mailto:a@b") undecoded, and it has no escaping rule of its own.
		b.WriteString(in.Opaque)
	} else {
		auth, hasAuth := rebuildAuthority(in)
		if hasAuth {
			b.WriteString("//")
			b.WriteString(auth)
		}
		p := rebuildPath(in)
		if !hasAuth && strings.HasPrefix(p, "//") {
			// url.URL.String() would prefix "./", a rewrite this function may not do.
			return "", fmt.Errorf(`a path starting with "//" needs a host in front of it; on its own it would parse as an authority, not a path`)
		}
		b.WriteString(p)
	}

	if len(in.Params) > 0 || inputHadEmptyQuery(in.Input) {
		b.WriteByte('?')
		b.WriteString(rebuildPairs(in.Params))
	}

	if f := rebuildFragment(in); f != "" {
		b.WriteByte('#')
		b.WriteString(f)
	}

	out := b.String()
	// An edited host or scheme may not form a URL at all; never hand that back as one.
	if _, err := url.Parse(out); err != nil {
		return "", fmt.Errorf("the edited parts do not form a URL: %w", err)
	}
	return out, nil
}

// rebuildAuthority also reports whether an authority should be written at all.
func rebuildAuthority(in *Inspection) (string, bool) {
	var b strings.Builder
	if in.User != "" {
		// Userinfo escaping differs from path and query: ":" and "@" must go, "$" and "+" may stay.
		b.WriteString(url.User(in.User).String())
		b.WriteByte('@')
	}
	host := in.Host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		// u.Hostname() stripped the IPv6 brackets; without them "::1" reads as host and port.
		host = "[" + host + "]"
	}
	b.WriteString(host)
	if in.Port != "" {
		// Kept even when it is the default port: Rebuild never normalises.
		b.WriteByte(':')
		b.WriteString(in.Port)
	}
	if b.Len() == 0 {
		return "", inputHadEmptyAuthority(in.Input)
	}
	return b.String(), true
}

// rebuildPath uses path rules, never query rules ("/a+b/" would read as "/a b/"), and keeps an
// untouched segment's Raw byte-for-byte: re-escaping would turn "a%2Bb" into "a+b".
func rebuildPath(in *Inspection) string {
	if len(in.Segments) == 0 {
		return in.Path
	}
	parts := make([]string, 0, len(in.Segments))
	for _, seg := range in.Segments {
		dec, err := url.PathUnescape(seg.Raw)
		switch {
		case err == nil && dec == seg.Decoded:
			parts = append(parts, seg.Raw)
		case err != nil && seg.Decoded == seg.Raw:
			// A malformed escape kept as typed; PathEscape would turn "%zz" into "%25zz".
			parts = append(parts, seg.Raw)
		default:
			parts = append(parts, url.PathEscape(seg.Decoded))
		}
	}
	p := strings.Join(parts, "/")
	if strings.HasPrefix(in.Path, "/") {
		p = "/" + p
	}
	return p
}

// rebuildPairs keeps slice order and Valueless: "?debug" and "?debug=" differ to a server.
func rebuildPairs(ps []Param) string {
	var b strings.Builder
	for i, p := range ps {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(writeBack(p.Key, p.RawKey))
		if p.Valueless {
			continue
		}
		b.WriteByte('=')
		b.WriteString(writeBack(p.Value, p.RawValue))
	}
	return b.String()
}

// writeBack keeps raw while it still decodes to dec (an empty raw means the same bytes), and passes a
// malformed escape through as typed: "%zz" stays "%zz", never "%25zz". Anything else is encoded.
func writeBack(dec, raw string) string {
	if raw != "" {
		if got, err := url.QueryUnescape(raw); err == nil && got == dec {
			return raw
		}
	}
	round, err := url.QueryUnescape(dec)
	switch {
	case err != nil && querySafe(dec):
		return dec
	case err == nil && round == dec && querySafe(dec):
		return dec
	default:
		// An edit, or text like a bare "&" no query could hold unescaped; only encoding survives a re-parse.
		return encodeQuery(dec)
	}
}

// querySafe passes bytes above 0x7F (RawQuery keeps pasted UTF-8 byte-for-byte, so it returns as
// pasted) and "%" and "+", which writeBack needs for "%zz".
func querySafe(s string) bool {
	if strings.ContainsAny(s, "&# ") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}

// encodeQuery writes a space as "%20", not "+", which readers disagree on (space or plus).
func encodeQuery(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// rebuildFragment prefers FragParams: Fragment is already decoded and would lose their escaping.
func rebuildFragment(in *Inspection) string {
	if len(in.FragParams) > 0 {
		return rebuildPairs(in.FragParams)
	}
	if in.Fragment == "" {
		return ""
	}
	return (&url.URL{Fragment: in.Fragment}).EscapedFragment()
}

// inputHadEmptyQuery recovers url.URL's ForceQuery, which Inspection lacks: "x.com/?" vs "x.com/".
func inputHadEmptyQuery(input string) bool {
	rest, _, _ := strings.Cut(input, "#")
	_, q, ok := strings.Cut(rest, "?")
	return ok && q == ""
}

// inputHadEmptyAuthority recovers url.URL's OmitHost, which Inspection lacks: "file:///x" vs "file:/x".
func inputHadEmptyAuthority(input string) bool {
	_, rest, ok := strings.Cut(input, ":")
	return ok && strings.HasPrefix(rest, "//")
}
