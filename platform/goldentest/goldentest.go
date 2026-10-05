// Package goldentest pins test output in testdata; UPDATE_GOLDEN=1 rewrites it.
package goldentest

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// Response is one reply as a golden file pins it.
type Response struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

func Recorded(recs map[string]*httptest.ResponseRecorder) map[string]Response {
	out := make(map[string]Response, len(recs))
	for name, rec := range recs {
		out[name] = Response{Status: rec.Code, Body: rec.Body.Bytes()}
	}
	return out
}

// JSON compares got with testdata/<name>.golden.json, decoded so key order never matters.
func JSON(t testing.TB, name string, got any) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(got); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	path := filepath.Join("testdata", name+".golden.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (UPDATE_GOLDEN=1 creates it)", err)
	}
	if diff := cmp.Diff(decode(t, want), decode(t, buf.Bytes())); diff != "" {
		t.Errorf("%s differs (-golden +got):\n%s", path, diff)
	}
}

func decode(t testing.TB, b []byte) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	return v
}
