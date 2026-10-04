package tests

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// A JSON body exercises every value rule: strings as typed, a large number
// in full ('f', not 1.7e+09), booleans as "true"/"false", null as absent.
func TestJSONPostGolden(t *testing.T) {
	e := newCipherApp(t)
	post := func(body string) *httptest.ResponseRecorder {
		return do(t, e, http.MethodPost, "/jwt/sign", body, "application/json", asAPI)
	}
	checkGolden(t, "json-post", map[string]*httptest.ResponseRecorder{
		"jwt-sign": post(`{"alg":"HS256","key":"0123456789abcdef0123456789abcdef","payload":"{\"sub\":\"42\"}",` +
			`"now":1700000000,"iat":true,"exp":"1h","kid":null,"header":"{\"cty\":\"JWT\"}"}`),
		"jwt-sign-iat-false": post(`{"key":"0123456789abcdef0123456789abcdef","now":1.7e9,"iat":false}`),
		"nested-value":       post(`{"key":"k","payload":{"sub":"42"}}`),
	})
}

func TestFormPostGolden(t *testing.T) {
	e := newCipherApp(t)
	msg, key := `{"action":"opened"}`, []byte("webhook secret")
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	body := url.Values{"text": {msg}, "key": {string(key)}, "expected": {"sha256=" + hex.EncodeToString(mac.Sum(nil))}}
	checkGolden(t, "form-post", map[string]*httptest.ResponseRecorder{
		"hmac": do(t, e, http.MethodPost, "/hmac", body.Encode(), form, asAPI),
	})
}
