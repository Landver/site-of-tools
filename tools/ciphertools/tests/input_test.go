package tests

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

func TestInputFromJSON(t *testing.T) {
	var obj map[string]any
	body := `{"text":" spaces kept\n","now":1700000000,"m":1e6,"frac":1.5,"neg":-2,"on":true,"off":false,"gone":null}`
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		t.Fatal(err)
	}
	in, err := ciphertools.InputFromJSON(obj)
	if err != nil {
		t.Fatal(err)
	}
	want := url.Values{"text": {" spaces kept\n"}, "now": {"1700000000"}, "m": {"1000000"}, "frac": {"1.5"},
		"neg": {"-2"}, "on": {"true"}, "off": {"false"}}
	if diff := cmp.Diff(want, in.Fields); diff != "" {
		t.Errorf("fields (-want +got):\n%s", diff)
	}
	if in.Files == nil || len(in.Files) != 0 {
		t.Errorf("Files = %v, want empty and non-nil", in.Files)
	}

	for _, v := range []any{map[string]any{"a": "b"}, []any{"lower", "digits"}} {
		_, err := ciphertools.InputFromJSON(map[string]any{"sets": v})
		if err == nil || err.Error() != `field "sets": want a string, number or boolean` {
			t.Errorf("%v: error %v", v, err)
		}
	}
	if in, err := ciphertools.InputFromJSON(nil); err != nil || in.Fields == nil {
		t.Errorf("nil object: %+v, %v", in, err)
	}
}

// Numbers decoded with UseNumber read as float64 ones do, except that integers keep every digit.
func TestInputFromJSONNumbers(t *testing.T) {
	body := `{"now":1700000000,"m":1e6,"M":2E+3,"frac":1.5,"whole":2.0,"neg":-2,"zero":-0,` +
		`"big":9007199254740993,"huge":123456789012345678901234567890}`
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		t.Fatal(err)
	}
	in, err := ciphertools.InputFromJSON(obj)
	if err != nil {
		t.Fatal(err)
	}
	want := url.Values{"now": {"1700000000"}, "m": {"1000000"}, "M": {"2000"}, "frac": {"1.5"}, "whole": {"2"},
		"neg": {"-2"}, "zero": {"-0"}, "big": {"9007199254740993"}, "huge": {"123456789012345678901234567890"}}
	if diff := cmp.Diff(want, in.Fields); diff != "" {
		t.Errorf("fields (-want +got):\n%s", diff)
	}

	// The MCP SDK hands over float64s.
	in, err = ciphertools.InputFromJSON(map[string]any{"m": float64(1e6), "frac": 1.5})
	if diff := cmp.Diff(url.Values{"m": {"1000000"}, "frac": {"1.5"}}, in.Fields); err != nil || diff != "" {
		t.Errorf("float64: %v (-want +got):\n%s", err, diff)
	}
}
