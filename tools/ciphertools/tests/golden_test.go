package tests

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Landver/site-of-tools/platform/goldentest"
)

// A JSON body exercises every value rule: strings as typed, a large number
// in full ('f', not 1.7e+09), booleans as "true"/"false", null as absent.
func TestJSONPostGolden(t *testing.T) {
	e := newCipherApp(t)
	post := func(body string) *httptest.ResponseRecorder {
		return do(t, e, http.MethodPost, "/jwt/sign", body, "application/json", asAPI)
	}
	goldentest.JSON(t, "json-post", goldentest.Recorded(map[string]*httptest.ResponseRecorder{
		"jwt-sign": post(`{"alg":"HS256","key":"0123456789abcdef0123456789abcdef","payload":"{\"sub\":\"42\"}",` +
			`"now":1700000000,"iat":true,"exp":"1h","kid":null,"header":"{\"cty\":\"JWT\"}"}`),
		"jwt-sign-iat-false": post(`{"key":"0123456789abcdef0123456789abcdef","now":1.7e9,"iat":false}`),
		"nested-value":       post(`{"key":"k","payload":{"sub":"42"}}`),
	}))
}

func TestFormPostGolden(t *testing.T) {
	e := newCipherApp(t)
	msg, key := `{"action":"opened"}`, []byte("webhook secret")
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	body := url.Values{"text": {msg}, "key": {string(key)}, "expected": {"sha256=" + hex.EncodeToString(mac.Sum(nil))}}
	goldentest.JSON(t, "form-post", goldentest.Recorded(map[string]*httptest.ResponseRecorder{
		"hmac": do(t, e, http.MethodPost, "/hmac", body.Encode(), form, asAPI),
	}))
}
