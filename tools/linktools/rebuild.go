package linktools

import (
	"fmt"
	"net/url"
	"strings"
)

// Rebuild writes an Inspection back out as a URL: the write half of the struct
// Parse fills in, and all of A15 (docs/01-feature-inventory.md). The Inspect
// table's cells become inputs, and this turns the edited table back into a URL.
//
// The contract is round-trip, not tidiness. Rebuild(Parse(u)) must parse back to
// an equal Inspection, and everything below follows from that one requirement:
// nothing here normalises. A default port stays, an uppercase escape stays, a
// malformed escape stays malformed. Dropping a redundant ":443" is
// canonicalise's job (url.go) and it is lossy.
//
// calcbe is the cautionary example
// (docs/reports/calcbe-query-string-parser.md, "One inconsistency worth
// recording"): its table flags "%zz" honestly, and its copy button hands you
// "%25zz" — a different URL from the one pasted in, with "debug" silently turned
// into "debug=". A tool that warns in one pane and mutates in the other is worse
// than one that does neither. So where a component cannot be written back
// faithfully, this returns an error instead of emitting something subtly
// different.
//
// Two things Rebuild deliberately does not reproduce. Input, because it is the
// "before" text by definition and an edited Inspection must not be measured
// against it — note that url.Parse lowercases the scheme, so a URL pasted as
// "HTTPS://x" rebuilds as "https://x" and every other field still matches. And
// an empty pair: "?a=1&&b=2" comes back as "?a=1&b=2", because Parse already
// discards the empty pair and reconstructing it from the gaps in Param.Index
// would turn a deleted table row into a stray "&".
func (s *Service) Rebuild(in *Inspection) (string, error) {
	if in == nil {
		return "", fmt.Errorf("nothing to rebuild")
	}
	if in.HasPass {
		// types.go keeps HasPass and never the password itself, on purpose. So
		// there is nothing to write back, and writing the URL without it would
		// hand over a different URL that still looks like it works.
		return "", fmt.Errorf("this URL carries a password in its userinfo, which is never stored, so it cannot be rebuilt")
	}

	var b strings.Builder
	if in.Scheme != "" {
		b.WriteString(in.Scheme)
		b.WriteByte(':')
	}

	if in.Opaque != "" {
		// Non-hierarchical: "mailto:a@b", "javascript:alert(1)". Parse stores
		// this tail exactly as written and never decodes it, so verbatim is both
		// faithful and the only option — there is no per-position escaping rule
		// for an opaque part.
		b.WriteString(in.Opaque)
	} else {
		auth, hasAuth := rebuildAuthority(in)
		if hasAuth {
			b.WriteString("//")
			b.WriteString(auth)
		}
		p := rebuildPath(in)
		if !hasAuth && strings.HasPrefix(p, "//") {
			// url.URL.String() papers over this by prefixing "./". That is a
			// rewrite, and a rewrite is the one thing this function may not do.
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
	// Last guard. Every branch above is meant to produce something Parse
	// accepts; an edited Inspection can still carry a host or scheme that is not
	// a URL at all, and handing that back as if it were one is exactly the
	// failure mode this whole file exists to avoid.
	if _, err := url.Parse(out); err != nil {
		return "", fmt.Errorf("the edited parts do not form a URL: %w", err)
	}
	return out, nil
}

// rebuildAuthority writes userinfo, host and port, and reports whether an
// authority should be written at all.
func rebuildAuthority(in *Inspection) (string, bool) {
	var b strings.Builder
	if in.User != "" {
		// url.User applies the userinfo escaping rules, which differ again from
		// path and query: ":" and "@" must go, "$" and "+" may stay.
		b.WriteString(url.User(in.User).String())
		b.WriteByte('@')
	}
	host := in.Host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		// Parse fills Host from u.Hostname(), which strips the brackets off an
		// IPv6 literal. Without them back on, "::1" reads as a host with a port.
		host = "[" + host + "]"
	}
	b.WriteString(host)
	if in.Port != "" {
		// Written even when DefaultPort is set: see the note on Rebuild.
		b.WriteByte(':')
		b.WriteString(in.Port)
	}
	if b.Len() == 0 {
		return "", inputHadEmptyAuthority(in.Input)
	}
	return b.String(), true
}

// rebuildPath writes the path from its segments, falling back to Path when
// describePath recorded none ("" or "/").
//
// The escaping here is PATH escaping, and the difference from query escaping is
// not cosmetic: url.QueryEscape writes a space as "+" and QueryUnescape reads
// "+" back as a space, so running a path segment through the query rules renders
// "/a+b/" as "/a b/" (docs/reports/go-url-stdlib-behaviour.md §3). url.PathEscape
// applies RFC 3986's segment rules, which also escape "/" — correct, because a
// slash inside one segment is part of that segment's name and not a separator.
//
// A segment goes back out byte-for-byte whenever its Raw still decodes to its
// Decoded text, which is the untouched case. Re-encoding Decoded instead would
// be a silent rewrite: "a%2Bb" and "a+b" both decode to "a+b" under path rules,
// so a round trip through PathEscape would quietly move the URL from the first
// spelling to the second.
func rebuildPath(in *Inspection) string {
	if len(in.Segments) == 0 {
		return in.Path
	}
	parts := make([]string, 0, len(in.Segments))
	for _, seg := range in.Segments {
		dec, err := url.PathUnescape(seg.Raw)
		switch {
		case err == nil && dec == seg.Decoded:
			parts = append(parts, seg.Raw) // untouched
		case err != nil && seg.Decoded == seg.Raw:
			// Raw carries a malformed escape and describePath copied it into
			// Decoded unchanged rather than guessing. Writing it back as-is is
			// the whole point: PathEscape would turn "%zz" into "%25zz".
			parts = append(parts, seg.Raw)
		default:
			parts = append(parts, url.PathEscape(seg.Decoded)) // edited
		}
	}
	p := strings.Join(parts, "/")
	if strings.HasPrefix(in.Path, "/") {
		p = "/" + p
	}
	return p
}

// rebuildPairs writes an ordered parameter list back into a query string.
//
// Order is the slice's own order; Param.Index is not consulted, for the reason
// given on Rebuild. Repeated keys are written once each, because they are two
// parameters and always were. Valueless is the "?debug" versus "?debug="
// distinction, which is a real difference to a server and which calcbe's copy
// button flattens into the second form.
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

// writeBack returns the text to emit for one decoded key or value, given the raw
// form Parse kept beside it — which parsePairs sets only when decoding changed
// something, so an empty raw means "these were the same bytes".
//
// Three cases, in order:
//
//  1. raw still decodes to dec. Nobody edited this cell, so the original bytes
//     go back out untouched. This is what keeps "%2520" from collapsing to
//     "%20", a base64 "+" from becoming "%2B", and an uppercase "%2F" from
//     becoming "%2f".
//  2. raw is empty and dec does not decode at all. Then dec IS the raw text:
//     decodeOrRaw put it there because the escape is malformed, since
//     QueryUnescape returns the empty string rather than the original on error
//     (docs/reports/go-url-stdlib-behaviour.md §2). Param.Warn says as much in
//     prose; this checks the same fact structurally, because one Warn field is
//     shared by the key and the value and cannot say which of them is broken.
//     Emitting dec unchanged is the anti-calcbe rule: "%zz" stays "%zz", never
//     "%25zz". A cell edited to hold a literal "100%" is indistinguishable from
//     that and comes back out as "100%" too — which is what was typed, and which
//     Parse will flag again on the next inspection rather than silently repair.
//  3. otherwise the cell was edited, or was always plain, so it is encoded from
//     scratch — unless it is already its own decoding and structurally safe, in
//     which case re-encoding would be the silent rewrite of case 1 again.
//
// There is no fourth case and no error: a decoded string can always be
// percent-encoded, and the encoding always decodes back to it. Rebuild's
// refusals are structural (a password that was never stored, a path that would
// read as an authority), never per-value.
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
		// Either an edit that has to be escaped, or text that could not have
		// come out of a query string unescaped in the first place — a bare "&"
		// or a space would have ended the value. Encoding is the only reading
		// that survives a re-parse.
		return encodeQuery(dec)
	}
}

// querySafe reports whether s can sit in a query string as-is without changing
// the shape of the URL around it: no "&" to end the value early, no "#" to start
// a fragment, no space or control byte to break a copy-paste.
//
// Bytes above 0x7F are allowed through deliberately. url.Parse keeps RawQuery
// byte-for-byte, so a URL pasted with literal UTF-8 in its query parses that way
// and has to come back that way; percent-encoding it here would be a rewrite of
// a URL nobody edited. Note that "%" and "+" are *not* rejected here — case 2 of
// writeBack needs this to pass for "%zz", and the callers that care about a
// value decoding to itself check that separately.
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

// encodeQuery percent-encodes a decoded component for a query string, with one
// deliberate departure from url.QueryEscape: a space is written "%20", never
// "+".
//
// "+" is the correct x-www-form-urlencoded spelling and it is also the one
// ambiguity this tool makes the most noise about (A1, and
// docs/reports/go-url-stdlib-behaviour.md §3): QueryUnescape reads it as a
// space, PathUnescape as a plus, and two hosted parsers in the survey answer
// differently. "%20" means a space to both readings, so it is the only spelling
// that cannot be misread by whatever receives the rebuilt URL.
func encodeQuery(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// rebuildFragment writes the fragment back.
//
// FragParams wins when it is set. Parse builds it from the RAW fragment while
// Inspection.Fragment holds the already-decoded text (url.go re-reads the raw
// tail precisely because u.Fragment is decoded), so rebuilding from the string
// would drop the escaping those parameters depend on. The pairs are written with
// query escaping rather than fragment escaping because parsePairs decodes them
// with QueryUnescape: the inverse has to match the parse, not the position.
//
// A plain fragment takes RFC 3986's fragment rules instead, which escape far
// less — "a/b?c" is legal after a "#" untouched — and that is the third set of
// rules in this file.
func rebuildFragment(in *Inspection) string {
	if len(in.FragParams) > 0 {
		return rebuildPairs(in.FragParams)
	}
	if in.Fragment == "" {
		return ""
	}
	return (&url.URL{Fragment: in.Fragment}).EscapedFragment()
}

// inputHadEmptyQuery reports whether the original text ended in a bare "?".
//
// This is the one place Rebuild reads Input, and only because url.URL records
// the fact as ForceQuery and Inspection has no field for it: "x.com/?" and
// "x.com/" produce identical Params, so without this the round trip drops the
// "?" and the rebuilt URL's Canonical stops matching the original's. It is
// consulted only when there are no parameters at all, so an edit that deletes
// every row still yields a clean URL rather than a dangling "?"... which is
// exactly what the original had, and is therefore still right.
func inputHadEmptyQuery(input string) bool {
	rest, _, _ := strings.Cut(input, "#")
	_, q, ok := strings.Cut(rest, "?")
	return ok && q == ""
}

// inputHadEmptyAuthority reports whether the original wrote "//" after the
// scheme with nothing before the path: "file:///tmp/x" rather than "file:/tmp/x".
//
// Same reason as inputHadEmptyQuery. url.URL calls this OmitHost, Inspection has
// no field for it, and the two spellings are indistinguishable from an empty
// Host alone — so without this the round trip silently moves between them.
func inputHadEmptyAuthority(input string) bool {
	_, rest, ok := strings.Cut(input, ":")
	return ok && strings.HasPrefix(rest, "//")
}
