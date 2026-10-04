package linktools

import (
	"fmt"
	"strings"
)

// A11 — the campaign builder. The inverse of Clean, on the same rule table: the
// five tags it adds are exactly the five Clean knows how to take away.

// UTMKeys are the five standard campaign parameters, in the order Google
// documents them. The form's labels and hints live in handler.go; the order and
// the names live here, where the building happens.
var UTMKeys = []string{"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content"}

// UTM tag provenance: how each tag on the built URL got there.
const (
	TagSet      = "set"      // typed here, the URL had none
	TagReplaced = "replaced" // typed here, over a different value on the URL
	TagKept     = "kept"     // already on the URL, and left alone
)

// UTMTag is one campaign tag on the built URL and where it came from.
type UTMTag struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Source string `json:"source"`
	Was    string `json:"was,omitempty"` // the URL's own value, when replaced
}

// UTMResult is the tagged URL with the account of every tag on it.
type UTMResult struct {
	URL   string   `json:"url"`
	Tags  []UTMTag `json:"tags,omitempty"`
	Notes []Note   `json:"notes,omitempty"`
}

// BuildUTM tags raw with the typed values.
//
// A typed value replaces the URL's own, and two copies of one tag never come
// out: two utm_source parameters is a real bug that analytics tools resolve
// inconsistently. An EMPTY field leaves the URL's value alone. It used to delete
// it, so pasting a tagged link to change one tag silently wiped the other four,
// and the only warning was in a collapsed paragraph. Removing a tag is now
// something you do to the URL, or all at once on the Clean page.
func (s *Service) BuildUTM(raw string, typed map[string]string) (*UTMResult, error) {
	raw = strings.TrimSpace(raw)
	in, err := s.Parse(raw)
	if err != nil {
		return nil, err
	}
	res := &UTMResult{}

	// "example.com/landing" is what people paste. Tagged as it stands it is a
	// relative link, which works only on the page it is pasted into. Assume
	// https and say so, the rule Trace already follows. A path that starts
	// with "/" is relative on purpose (a site's own links, an API caller
	// templating them) and is tagged as it stands, as Clean cleans one.
	switch {
	case in.Scheme == "" && in.Host == "" && strings.HasPrefix(raw, "/"):
		res.Notes = append(res.Notes, Note{SevWarn, "Not a whole link",
			"This is a path, so the tagged URL is one too, and it works only on pages of the same site. To tag a link you can share, paste all of it, starting with https://."})
	case in.Scheme == "" && in.Host == "":
		alt, err := s.Parse("https://" + raw)
		if err != nil || alt.Host == "" {
			// Not a link with the scheme missing, just not a link: tagging
			// "hello world" built "hello%20world?utm_source=…" and called it done.
			return nil, fmt.Errorf("not a whole link: paste all of it, starting with https://")
		}
		in = alt
		res.Notes = append(res.Notes, Note{SevInfo, "No scheme",
			"The URL had none, so the tagged URL starts with https://. Without one it would be a relative link that only works on the page it is pasted into."})
	}

	for _, key := range UTMKeys {
		v := strings.TrimSpace(typed[key])
		old, copies := firstValue(in.Params, key)
		switch {
		case v != "":
			in.Params = upsertParam(in.Params, key, v)
			tag := UTMTag{Key: key, Value: v, Source: TagSet}
			if copies > 0 {
				tag.Source = TagKept
				if old != v {
					tag.Source, tag.Was = TagReplaced, old
				}
			}
			res.Tags = append(res.Tags, tag)
		case copies > 0:
			res.Tags = append(res.Tags, UTMTag{Key: key, Value: old, Source: TagKept})
			if copies > 1 {
				res.Notes = append(res.Notes, Note{SevWarn, key + " appears " + fmt.Sprint(copies) + " times",
					"The URL already carries more than one " + key + ", and analytics tools disagree about which one counts. Type a value here to leave exactly one."})
			}
		}
	}

	built, err := s.Rebuild(in)
	if err != nil {
		return nil, err
	}
	res.URL = built
	res.Notes = append(res.Notes, tagHygiene(res.Tags)...)
	return res, nil
}

// tagHygiene is the advice a campaign report would otherwise give you a month
// late. Soft findings, never refusals: every one of these builds a working URL.
func tagHygiene(tags []UTMTag) []Note {
	var notes []Note
	has := map[string]bool{}
	var caps, spaces, plus []string
	var capsValue string
	for _, t := range tags {
		has[t.Key] = true
		if strings.ToLower(t.Value) != t.Value {
			caps = append(caps, t.Key)
			if capsValue == "" {
				capsValue = t.Value
			}
		}
		if strings.ContainsAny(t.Value, " \t") {
			spaces = append(spaces, t.Key)
		}
		if strings.Contains(t.Value, "+") {
			plus = append(plus, t.Key)
		}
	}
	if len(tags) > 0 && !has["utm_source"] {
		notes = append(notes, Note{SevWarn, "No utm_source",
			"Most analytics tools need utm_source to attribute the visit at all; without it the other tags may be ignored."})
	}
	if len(caps) > 0 {
		// The reader's own value and the field's own noun: "two different
		// mediums" was said of every field, utm_source included.
		noun := "values"
		if n, ok := utmNouns[caps[0]]; ok && len(caps) == 1 {
			noun = n
		}
		notes = append(notes, Note{SevWarn, "Capital letters in " + strings.Join(caps, ", "),
			"Most analytics tools are case-sensitive, so “" + capsValue + "” and “" + strings.ToLower(capsValue) + "” are reported as two different " + noun + ". Lowercase keeps them together."})
	}
	if len(plus) > 0 {
		notes = append(notes, Note{SevWarn, "A + in " + strings.Join(plus, ", "),
			"A + typed here is a literal plus, encoded as %2B, and reports show it as one. For a space, type a space; for a separator, a dash."})
	}
	if len(spaces) > 0 {
		notes = append(notes, Note{SevInfo, "Spaces in " + strings.Join(spaces, ", "),
			"Each space is written %20 in the URL and comes back as a space in reports. It works; dashes read better in both places."})
	}
	return notes
}

// utmNouns names what each tag's values are, for the capitals note.
var utmNouns = map[string]string{
	"utm_source": "sources", "utm_medium": "mediums", "utm_campaign": "campaigns",
	"utm_term": "terms", "utm_content": "content values",
}

// firstValue returns key's first value in ps and how many times key appears.
func firstValue(ps []Param, key string) (string, int) {
	val, n := "", 0
	for _, p := range ps {
		if p.Key == key {
			if n == 0 {
				val = p.Value
			}
			n++
		}
	}
	return val, n
}

// upsertParam sets key to value, replacing the first occurrence and dropping
// the rest; an empty value removes the key entirely.
func upsertParam(ps []Param, key, value string) []Param {
	out := make([]Param, 0, len(ps)+1)
	done := false
	for _, p := range ps {
		if p.Key != key {
			out = append(out, p)
			continue
		}
		if done || value == "" {
			continue
		}
		p.Value, p.RawValue, p.Layers, p.List, p.Delimiter = value, "", nil, nil, ""
		p.Valueless, p.Warn, p.AltValue, p.Nested = false, "", "", ""
		out = append(out, p)
		done = true
	}
	if !done && value != "" {
		out = append(out, Param{Index: len(out) + 1, Key: key, Value: value})
	}
	for i := range out {
		out[i].Index = i + 1
	}
	return out
}
