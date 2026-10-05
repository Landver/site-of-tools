package mcptools

import "github.com/google/jsonschema-go/jsonschema"

// inputSchema infers T's input schema, then applies mods. The jsonschema struct
// tag carries descriptions only, so enums, bounds and defaults are set here,
// from the domain's own lists. A type it can't infer is a programming error.
func inputSchema[T any](mods ...func(*jsonschema.Schema)) *jsonschema.Schema {
	s, err := jsonschema.For[T](nil)
	if err != nil {
		panic(err)
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
