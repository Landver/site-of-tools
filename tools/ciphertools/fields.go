package ciphertools

import (
	"fmt"
	"strconv"
	"strings"
)

// Kind is how a field's value is written in a form or a JSON body.
type Kind string

const (
	KindString Kind = "string"
	KindInt    Kind = "int"  // a whole number, in decimal
	KindBool   Kind = "bool" // a checkbox: "false", "off", "0", "no" and absent are unset
	KindJSON   Kind = "json" // a string holding JSON text
	KindEnum   Kind = "enum" // one of Enum
	KindList   Kind = "list" // a comma-separated subset of Enum
	KindFile   Kind = "file" // an uploaded file: multipart forms only, never JSON
)

// Field is one input an op reads, as Op.Fields declares it: the contract the
// API's tool schemas are generated from, and for an int field the default
// and bounds intField enforces.
type Field struct {
	Name        string
	Kind        Kind
	Description string
	// Enum lists the accepted values: an enum's choices, a list's members,
	// or the only values an int field's range allows.
	Enum []string
	// Default is what the op uses when the field is absent or blank, written
	// as form text; "" when there is none or it depends on another field.
	Default string
	// Min and Max bound an int field. Where a bound depends on another field
	// they are the widest, and Description gives the narrower ones.
	Min, Max *int
	// Required: the op refuses a request without it.
	Required bool
}

func (f Field) withMax(n int) Field { f.Max = &n; return f }

func (f Field) withDefault(n int) Field { f.Default = strconv.Itoa(n); return f }

// intField reads a whole-number field: f's default when it is absent or blank,
// and an error naming the field and its range otherwise. The range is the cap,
// so it is checked here, before any work starts: for the Heavy ops the upper
// bound is what keeps one request from tying up the server.
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
