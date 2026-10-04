package tests

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type goldenResponse struct {
	Status int `json:"status"`
	Body   any `json:"body"`
}

// checkGolden compares each named response with testdata/<name>.golden.json,
// decoded on both sides so key order never matters. UPDATE_GOLDEN=1 rewrites
// the file instead: review that diff like code.
func checkGolden(t *testing.T, name string, got map[string]*httptest.ResponseRecorder) {
	t.Helper()
	decoded := make(map[string]goldenResponse, len(got))
	for k, rec := range got {
		var body any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: body is not JSON: %v\n%s", k, err, rec.Body)
		}
		decoded[k] = goldenResponse{Status: rec.Code, Body: body}
	}
	path := filepath.Join("testdata", name+".golden.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(decoded); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (UPDATE_GOLDEN=1 creates it): %v", err)
	}
	var want map[string]goldenResponse
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if diff := cmp.Diff(want, decoded); diff != "" {
		t.Errorf("%s mismatch (-want +got):\n%s", path, diff)
	}
}
