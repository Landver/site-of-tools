package tests

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Landver/site-of-tools/platform/goldentest"
)

func TestJSONPostGolden(t *testing.T) {
	e := newCipherApp(t)
	sign := func(body string) *httptest.ResponseRecorder {
		return do(t, e, http.MethodPost, "/jwt/sign", body, "application/json", asAPI)
	}
	goldentest.JSON(t, "json-post", goldentest.Recorded(map[string]*httptest.ResponseRecorder{
		"jwt-sign": sign(`{"alg":"HS256","key":"0123456789abcdef0123456789abcdef","payload":"{\"sub\":\"42\"}",` +
			`"now":1700000000,"iat":true,"exp":"1h","kid":null,"header":"{\"cty\":\"JWT\"}"}`),
		"nested-value": sign(`{"key":"k","payload":{"sub":"42"}}`),
	}))
}

func TestFormPostGolden(t *testing.T) {
	body := url.Values{"text": {`{"action":"opened"}`}, "key": {"webhook secret"},
		"expected": {"sha256=aa71099416fd7916f0e739ced18c2abf058cb8f839819932eae2460b05b339dd"}}
	goldentest.JSON(t, "form-post", goldentest.Recorded(map[string]*httptest.ResponseRecorder{
		"hmac": do(t, newCipherApp(t), http.MethodPost, "/hmac", body.Encode(), form, asAPI),
	}))
}
