package mcptools

import (
	"encoding/json"

	"github.com/google/jsonschema-go/jsonschema"
)

// inputSchema infers T's input schema, then applies mods. The jsonschema struct
// tag carries descriptions only, so enums, bounds and defaults are set here,
// from the domain's own lists. A type it can't infer is a programming error.
func inputSchema[T any](mods ...func(*jsonschema.Schema)) *jsonschema.Schema {
	s, err := jsonschema.For[T](nil)
	if err != nil {
		panic(err)
	}
	// A pointer field only tells an absent argument from a zero one; inferred,
	// it would also invite an explicit null, which means nothing here.
	for _, p := range s.Properties {
		if len(p.Types) == 2 && p.Types[0] == "null" {
			p.Type, p.Types = p.Types[1], nil
		}
	}
	for _, m := range mods {
		m(s)
	}
	return s
}

// minLength requires the string property prop to hold at least n characters.
func minLength(prop string, n int) func(*jsonschema.Schema) {
	return func(s *jsonschema.Schema) { s.Properties[prop].MinLength = jsonschema.Ptr(n) }
}

// oneOf limits the string property prop to values.
func oneOf(prop string, values []string) func(*jsonschema.Schema) {
	return func(s *jsonschema.Schema) {
		p := s.Properties[prop]
		p.Enum = make([]any, len(values))
		for i, v := range values {
			p.Enum[i] = v
		}
	}
}

// defaultTo is what the SDK fills in for an absent prop before the handler
// runs, so it must be what the domain does with an absent value too.
func defaultTo(prop string, v any) func(*jsonschema.Schema) {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return func(s *jsonschema.Schema) { s.Properties[prop].Default = raw }
}

// between bounds the integer property prop to [lo, hi].
func between(prop string, lo, hi int) func(*jsonschema.Schema) {
	return func(s *jsonschema.Schema) {
		p := s.Properties[prop]
		p.Minimum, p.Maximum = jsonschema.Ptr(float64(lo)), jsonschema.Ptr(float64(hi))
	}
}
