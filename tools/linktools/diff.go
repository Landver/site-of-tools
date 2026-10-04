package linktools

import (
	"sort"
	"strconv"
	"strings"
)

// A13 — compare two URLs. No new parsing logic: this is a second view over two
// Inspections that Parse already produced, which is why it is forty lines
// rather than four hundred.
//
// The case it exists for is "why does staging behave differently from
// production", where the answer is almost always one parameter that is present
// on one side, or reordered, or subtly different.

// ChangeKind names what happened to one parameter between two URLs.
type ChangeKind string

const (
	ChangeAdded    ChangeKind = "added"
	ChangeRemoved  ChangeKind = "removed"
	ChangeModified ChangeKind = "modified"
	ChangeMoved    ChangeKind = "moved"
	ChangeSame     ChangeKind = "same"
)

// ParamChange is one row of the comparison.
type ParamChange struct {
	Key    string     `json:"key"`
	Kind   ChangeKind `json:"kind"`
	A      string     `json:"a,omitempty"`
	B      string     `json:"b,omitempty"`
	IndexA int        `json:"index_a,omitempty"`
	IndexB int        `json:"index_b,omitempty"`
}

// FieldChange is one differing component outside the query. Cosmetic marks a
// difference of spelling, not meaning (host case, a default port, a dot
// segment, escape case): listed, but not counted against Identical.
type FieldChange struct {
	Field    string `json:"field"`
	A        string `json:"a,omitempty"`
	B        string `json:"b,omitempty"`
	Cosmetic bool   `json:"cosmetic,omitempty"`
}

// Diff is the whole comparison.
type Diff struct {
	A         string        `json:"a"`
	B         string        `json:"b"`
	Fields    []FieldChange `json:"fields,omitempty"`
	Params    []ParamChange `json:"params,omitempty"`
	Identical bool          `json:"identical"`
	Notes     []Note        `json:"notes,omitempty"`
}

// DiffInspections compares two parsed URLs.
//
// Repeated keys are compared positionally within the key, not collapsed, for
// the same reason Parse keeps them apart: ?id=1&id=2 versus ?id=2&id=1 is a real
// difference and a map-based diff cannot see it.
func DiffInspections(a, b *Inspection) *Diff {
	d := &Diff{A: a.Input, B: b.Input}

	// Values as written (av, bv) and normalised (an, bn).
	for _, f := range []struct{ name, av, bv, an, bn string }{
		{"scheme", a.Scheme, b.Scheme, strings.ToLower(a.Scheme), strings.ToLower(b.Scheme)},
		// opaque carries the ENTIRE payload of a non-hierarchical URL
		// (mailto:, tel:, javascript:, data:, magnet:). Omitting it made this
		// function report "javascript:alert(1)" and "javascript:fetch(...)" as
		// equivalent — an affirmative false claim from the one tool whose job is
		// saying what differs.
		{"opaque", a.Opaque, b.Opaque, a.Opaque, b.Opaque},
		{"host", a.Host, b.Host, normalHost(a), normalHost(b)},
		{"port", a.Port, b.Port, normalPort(a), normalPort(b)},
		{"path", a.Path, b.Path, normalPath(a), normalPath(b)},
		{"fragment", a.Fragment, b.Fragment, normalizeEscapes(a.Fragment), normalizeEscapes(b.Fragment)},
		{"user", a.User, b.User, a.User, b.User},
		{"unwrapped target", a.Unwrapped, b.Unwrapped, a.Unwrapped, b.Unwrapped},
	} {
		if f.av != f.bv {
			d.Fields = append(d.Fields, FieldChange{Field: f.name, A: f.av, B: f.bv, Cosmetic: f.an == f.bn})
		}
	}
	// Passwords are deliberately never captured (Inspection.HasPass is a bool,
	// docs/06-security-and-abuse.md §8), so presence can be compared but value
	// cannot. Report the presence difference, and below refuse to claim
	// equivalence whenever either side has one.
	if a.HasPass != b.HasPass {
		d.Fields = append(d.Fields, FieldChange{
			Field: "password",
			A:     passLabel(a.HasPass),
			B:     passLabel(b.HasPass),
		})
	}

	// Group by key, preserving order of occurrence within each key.
	ga, gb := groupByKey(a.Params), groupByKey(b.Params)
	for _, key := range orderedKeys(a.Params, b.Params) {
		va, vb := ga[key], gb[key]
		n := max(len(va), len(vb))
		for i := 0; i < n; i++ {
			switch {
			case i >= len(va):
				d.Params = append(d.Params, ParamChange{Key: key, Kind: ChangeAdded, B: vb[i].Value, IndexB: vb[i].Index})
			case i >= len(vb):
				d.Params = append(d.Params, ParamChange{Key: key, Kind: ChangeRemoved, A: va[i].Value, IndexA: va[i].Index})
			case va[i].Value != vb[i].Value:
				d.Params = append(d.Params, ParamChange{Key: key, Kind: ChangeModified,
					A: va[i].Value, B: vb[i].Value, IndexA: va[i].Index, IndexB: vb[i].Index})
			default:
				d.Params = append(d.Params, ParamChange{Key: key, Kind: ChangeSame,
					A: va[i].Value, B: vb[i].Value, IndexA: va[i].Index, IndexB: vb[i].Index})
			}
		}
	}

	// Order is load-bearing for signed URLs, so a move is named.
	markMoves(d.Params)

	// Two URLs both carrying a password can never be declared equivalent: the
	// values were never captured, so the claim is unverifiable either way. Say
	// that, rather than asserting equality we cannot stand behind.
	undecidable := a.HasPass && b.HasPass
	d.Identical = !hasRealField(d.Fields) && !hasRealChange(d.Params) && !undecidable
	if undecidable {
		d.Notes = append(d.Notes, Note{SevWarn, "Passwords not compared",
			"Both URLs carry a password. This tool never captures a password, so it cannot tell you whether the two match — everything else about them is compared below."})
	}
	if d.Identical && a.Input != b.Input {
		d.Notes = append(d.Notes, Note{SevInfo, "Different text, same URL",
			"Every difference is formatting: letter case, a default port written out, a dot segment, an escape. A server reads both URLs the same way."})
	}
	if onlyMoves(d.Params) && !hasRealField(d.Fields) && !d.Identical {
		d.Notes = append(d.Notes, Note{SevWarn, "Only the order changed",
			"Same parameters, same values, new positions. Most servers won't notice. A signed URL will: if its signature covers the query as written, reordering it returns a 403 that doesn't say why."})
	}
	return d
}

// markMoves marks the unchanged pairs that moved relative to the others: those
// outside the longest run whose B positions rise in A order (on a tie, the run
// keeping more exact positions). Absolute positions can't decide it: one
// deletion shifts everything after it.
func markMoves(cs []ParamChange) {
	var same []int // indexes into cs of unchanged pairs present on both sides
	for i, c := range cs {
		if c.Kind == ChangeSame {
			same = append(same, i)
		}
	}
	sort.Slice(same, func(x, y int) bool { return cs[same[x]].IndexA < cs[same[y]].IndexA })

	n := len(same)
	length, exact, prev := make([]int, n), make([]int, n), make([]int, n)
	best := -1
	for i := 0; i < n; i++ {
		here := 0
		if c := cs[same[i]]; c.IndexA == c.IndexB {
			here = 1
		}
		length[i], exact[i], prev[i] = 1, here, -1
		for j := 0; j < i; j++ {
			if cs[same[j]].IndexB >= cs[same[i]].IndexB {
				continue
			}
			if l, e := length[j]+1, exact[j]+here; l > length[i] || (l == length[i] && e > exact[i]) {
				length[i], exact[i], prev[i] = l, e, j
			}
		}
		if best < 0 || length[i] > length[best] || (length[i] == length[best] && exact[i] > exact[best]) {
			best = i
		}
	}
	kept := make(map[int]bool, n)
	for i := best; i >= 0; i = prev[i] {
		kept[same[i]] = true
	}
	for _, i := range same {
		if !kept[i] {
			cs[i].Kind = ChangeMoved
		}
	}
}

// normalHost is the host as a resolver sees it: ASCII, lowercase.
func normalHost(in *Inspection) string {
	if in.HostASCII != "" {
		return strings.ToLower(in.HostASCII)
	}
	return strings.ToLower(in.Host)
}

func normalPort(in *Inspection) string {
	if in.DefaultPort {
		return ""
	}
	return in.Port
}

// normalPath resolves dot segments and escapes; an empty http(s) path is "/"
// (RFC 3986 §6.2.3).
func normalPath(in *Inspection) string {
	p := normalizeEscapes(removeDotSegments(in.Path))
	if p == "" && in.Host != "" && (strings.EqualFold(in.Scheme, "http") || strings.EqualFold(in.Scheme, "https")) {
		return "/"
	}
	return p
}

// normalizeEscapes applies RFC 3986 §6.2.2: uppercase hex, unreserved
// characters unescaped. %2F stays escaped: it is not a slash.
func normalizeEscapes(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHexDigit(s[i+1]) && isHexDigit(s[i+2]) {
			c := hexVal(s[i+1])<<4 | hexVal(s[i+2])
			if isUnreserved(c) {
				b.WriteByte(c)
			} else {
				b.WriteString(strings.ToUpper(s[i : i+3]))
			}
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

// isUnreserved: RFC 3986 §2.3, the characters that never need escaping.
func isUnreserved(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

func groupByKey(ps []Param) map[string][]Param {
	m := map[string][]Param{}
	for _, p := range ps {
		m[p.Key] = append(m[p.Key], p)
	}
	return m
}

// orderedKeys returns every key in either URL, in first-seen order across A
// then B, so the rendered diff reads in the order the URLs are written.
func orderedKeys(a, b []Param) []string {
	seen := map[string]bool{}
	var out []string
	for _, ps := range [][]Param{a, b} {
		for _, p := range ps {
			if !seen[p.Key] {
				seen[p.Key] = true
				out = append(out, p.Key)
			}
		}
	}
	return out
}

func hasRealField(fs []FieldChange) bool {
	for _, f := range fs {
		if !f.Cosmetic {
			return true
		}
	}
	return false
}

func hasRealChange(cs []ParamChange) bool {
	for _, c := range cs {
		if c.Kind != ChangeSame {
			return true
		}
	}
	return false
}

func onlyMoves(cs []ParamChange) bool {
	moved := false
	for _, c := range cs {
		switch c.Kind {
		case ChangeMoved:
			moved = true
		case ChangeSame:
		default:
			return false
		}
	}
	return moved
}

// Summary renders a one-line description, for the page heading.
func (d *Diff) Summary() string {
	var added, removed, modified, moved int
	for _, c := range d.Params {
		switch c.Kind {
		case ChangeAdded:
			added++
		case ChangeRemoved:
			removed++
		case ChangeModified:
			modified++
		case ChangeMoved:
			moved++
		}
	}
	if d.Identical {
		if d.A == d.B {
			return "These two URLs are identical."
		}
		return "Same request, written differently."
	}
	var params []string
	for _, p := range []struct {
		n     int
		label string
	}{{added, "added"}, {removed, "removed"}, {modified, "changed"}, {moved, "moved"}} {
		if p.n > 0 {
			params = append(params, strconv.Itoa(p.n)+" "+p.label)
		}
	}
	real := 0
	for _, f := range d.Fields {
		if !f.Cosmetic {
			real++
		}
	}
	var out []string
	if len(params) > 0 {
		out = append(out, "Parameters: "+strings.Join(params, ", ")+".")
	}
	if real > 0 {
		out = append(out, "URL parts: "+strconv.Itoa(real)+" different.")
	}
	if len(out) == 0 {
		// Reachable when the only reason these are not identical is something
		// that cannot be counted — today, two URLs that both carry a password.
		// Returning an empty heading would be a worse answer than saying plainly
		// that we cannot tell.
		return "Nothing comparable differs, but these cannot be called equivalent: see the note below."
	}
	return strings.Join(out, " ")
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}

// passLabel renders password presence without ever rendering the password.
func passLabel(has bool) string {
	if has {
		return "(a password is present)"
	}
	return "(none)"
}
