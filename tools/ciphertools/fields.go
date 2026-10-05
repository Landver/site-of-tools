package ciphertools

import (
	"fmt"
	"strconv"
	"strings"
)

type Kind string

const (
	KindString Kind = "string"
	KindInt    Kind = "int"
	KindBool   Kind = "bool"
	KindJSON   Kind = "json" // a string holding JSON text
	KindEnum   Kind = "enum"
	KindList   Kind = "list" // a comma-separated subset of Enum
	KindFile   Kind = "file" // multipart forms only, never JSON
)

// Field is one input an op reads, the contract tool schemas are generated from.
type Field struct {
	Name        string
	Kind        Kind
	Description string
	// Enum: an enum's choices, a list's members, or an int field's only values.
	Enum []string
	// Default is form text; "" when there is none or it depends on another field.
	Default string
	// Min, Max bound an int field; where a bound depends on another field, the widest.
	Min, Max *int
	Required bool
}

func (f Field) withMax(n int) Field { f.Max = &n; return f }

func (f Field) withDefault(n int) Field { f.Default = strconv.Itoa(n); return f }

// intField checks the range before any work: for Heavy ops it is what bounds a request.
func intField(in Input, f Field) (int, error) {
	v := strings.TrimSpace(in.Get(f.Name))
	if v == "" {
		n, _ := strconv.Atoi(f.Default)
		return n, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: want a whole number, got %q", f.Name, v)
	}
	switch {
	case f.Min != nil && n < *f.Min:
		return 0, fmt.Errorf("%s: %d is below the minimum of %s", f.Name, n, thousands(*f.Min))
	case f.Max != nil && n > *f.Max:
		return 0, fmt.Errorf("%s: %d is above the limit of %s", f.Name, n, thousands(*f.Max))
	}
	return n, nil
}

// thousands writes n with comma separators: 600000 as "600,000".
func thousands(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	if neg {
		return "-" + s
	}
	return s
}
