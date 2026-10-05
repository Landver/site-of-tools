package mcptools

import (
	"encoding/json"

	"github.com/google/jsonschema-go/jsonschema"
)

// inputSchema infers T's input schema, then applies mods: the jsonschema tag
// carries descriptions only, so enums, bounds and defaults come from the domain.
func inputSchema[T any](mods ...func(*jsonschema.Schema)) *jsonschema.Schema {
	s, err := jsonschema.For[T](nil)
	if err != nil {
		panic(err)
	}
	// A pointer field tells absent from zero; it must not invite an explicit null.
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

func minLength(prop string, n int) func(*jsonschema.Schema) {
	return func(s *jsonschema.Schema) { s.Properties[prop].MinLength = jsonschema.Ptr(n) }
}

func oneOf(prop string, values []string) func(*jsonschema.Schema) {
	return func(s *jsonschema.Schema) {
		p := s.Properties[prop]
		p.Enum = make([]any, len(values))
		for i, v := range values {
			p.Enum[i] = v
		}
	}
}

// defaultTo is what the SDK fills in for an absent prop, so it must match the domain's.
func defaultTo(prop string, v any) func(*jsonschema.Schema) {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return func(s *jsonschema.Schema) { s.Properties[prop].Default = raw }
}

func between(prop string, lo, hi int) func(*jsonschema.Schema) {
	return func(s *jsonschema.Schema) {
		p := s.Properties[prop]
		p.Minimum, p.Maximum = jsonschema.Ptr(float64(lo)), jsonschema.Ptr(float64(hi))
	}
}
