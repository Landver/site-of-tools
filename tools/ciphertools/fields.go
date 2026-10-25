package ciphertools

import (
	"cmp"
	"fmt"
	"slices"
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

// Field is one input an op reads; the MCP tool schemas are generated from it.
type Field struct {
	Name        string
	Kind        Kind
	Description string
	Enum        []string // an enum's choices, a list's members, or an int field's only values
	Default     string   // form text; "" when there is none or it depends on another field
	Min, Max    *int     // where a bound depends on another field, the widest
	Required    bool
}

func (f Field) withMax(n int) Field { f.Max = &n; return f }

func (f Field) withDefault(n int) Field { f.Default = strconv.Itoa(n); return f }

func ptr[T any](v T) *T { return &v }

// choice reads a menu value case-insensitively; blank means def.
func choice(v, def string) string { return cmp.Or(strings.ToLower(strings.TrimSpace(v)), def) }

// checked reads a checkbox: "on" from a form, "true" from a JSON body.
func checked(v string) bool {
	return !slices.Contains([]string{"", "0", "false", "off", "no"}, choice(v, ""))
}

// enumField reads f trimmed and case-insensitively, blank meaning its default, as the Enum spells it.
func enumField(v string, f Field) (string, error) {
	v = cmp.Or(strings.TrimSpace(v), f.Default)
	if i := slices.IndexFunc(f.Enum, func(e string) bool { return strings.EqualFold(e, v) }); i >= 0 {
		return f.Enum[i], nil
	}
	return "", fmt.Errorf("%s: want %s or %s, got %q", f.Name, strings.Join(f.Enum[:len(f.Enum)-1], ", "), f.Enum[len(f.Enum)-1], v)
}

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
	for i := len(s) - 3; i > 0 && s[i-1] != '-'; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
