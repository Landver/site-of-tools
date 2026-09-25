package linktools

import "strings"

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

// FieldChange is one differing component outside the query.
type FieldChange struct {
	Field string `json:"field"`
	A     string `json:"a,omitempty"`
	B     string `json:"b,omitempty"`
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

	for _, f := range []struct{ name, av, bv string }{
		{"scheme", a.Scheme, b.Scheme},
		// opaque carries the ENTIRE payload of a non-hierarchical URL
		// (mailto:, tel:, javascript:, data:, magnet:). Omitting it made this
		// function report "javascript:alert(1)" and "javascript:fetch(...)" as
		// equivalent — an affirmative false claim from the one tool whose job is
		// saying what differs.
		{"opaque", a.Opaque, b.Opaque},
		{"host", a.Host, b.Host},
		{"port", a.Port, b.Port},
		{"path", a.Path, b.Path},
		{"fragment", a.Fragment, b.Fragment},
		{"user", a.User, b.User},
		{"unwrapped target", a.Unwrapped, b.Unwrapped},
	} {
		if f.av != f.bv {
			d.Fields = append(d.Fields, FieldChange{Field: f.name, A: f.av, B: f.bv})
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
			case va[i].Index != vb[i].Index:
				// Same value, different position. Worth naming rather than
				// hiding: order is load-bearing for signed URLs, and "only the
				// order changed" is a genuinely different answer from "nothing
				// changed".
				d.Params = append(d.Params, ParamChange{Key: key, Kind: ChangeMoved,
					A: va[i].Value, B: vb[i].Value, IndexA: va[i].Index, IndexB: vb[i].Index})
			default:
				d.Params = append(d.Params, ParamChange{Key: key, Kind: ChangeSame,
					A: va[i].Value, B: vb[i].Value, IndexA: va[i].Index, IndexB: vb[i].Index})
			}
		}
	}

	// Two URLs both carrying a password can never be declared equivalent: the
	// values were never captured, so the claim is unverifiable either way. Say
	// that, rather than asserting equality we cannot stand behind.
	undecidable := a.HasPass && b.HasPass
	d.Identical = len(d.Fields) == 0 && !hasRealChange(d.Params) && !undecidable
	if undecidable {
		d.Notes = append(d.Notes, Note{SevWarn, "Passwords not compared",
			"Both URLs carry a password. This tool never captures a password, so it cannot tell you whether the two match — everything else about them is compared below."})
	}
	if d.Identical && a.Input != b.Input {
		d.Notes = append(d.Notes, Note{SevInfo, "Different text, same URL",
			"These two strings differ but describe the same request: the differences are all in encoding or formatting, not in content."})
	}
	if onlyMoves(d.Params) && len(d.Fields) == 0 && !d.Identical {
		d.Notes = append(d.Notes, Note{SevWarn, "Only the order changed",
			"Same parameters, same values, different positions. Harmless to most servers and fatal to any URL whose signature covers the literal query string."})
	}
	return d
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
		return "These two URLs are equivalent."
	}
	var parts []string
	for _, p := range []struct {
		n     int
		label string
	}{{added, "added"}, {removed, "removed"}, {modified, "changed"}, {moved, "moved"}} {
		if p.n > 0 {
			parts = append(parts, plural(p.n, "parameter")+" "+p.label)
		}
	}
	if len(d.Fields) > 0 {
		parts = append(parts, plural(len(d.Fields), "component")+" different")
	}
	if len(parts) == 0 {
		// Reachable when the only reason these are not identical is something
		// that cannot be counted — today, two URLs that both carry a password.
		// Returning the bare "." that joining an empty list produces would be a
		// worse answer than saying plainly that we cannot tell.
		return "Nothing comparable differs, but these cannot be called equivalent — see the note below."
	}
	return strings.Join(parts, ", ") + "."
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return itoa(n) + " " + word + "s"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// passLabel renders password presence without ever rendering the password.
func passLabel(has bool) string {
	if has {
		return "(a password is present)"
	}
	return "(none)"
}
