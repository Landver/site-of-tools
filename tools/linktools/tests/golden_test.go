package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform/goldentest"
	"github.com/Landver/site-of-tools/tools/linktools"
)

type linkCase struct {
	name, method, target string
	// body is sent as ctype; headers ride on top of a plain curl's Accept.
	body, ctype string
	headers     map[string]string
	short       *linktools.Shortener
}

func runLinkGolden(t *testing.T, file string, cases []linkCase) {
	t.Helper()
	got := map[string]*httptest.ResponseRecorder{}
	for _, tc := range cases {
		got[tc.name] = linkCall(t, newLinkApp(t, nil, tc.short), tc)
	}
	goldentest.JSON(t, file, goldentest.Recorded(got))
}

func linkCall(t *testing.T, e *echo.Echo, tc linkCase) *httptest.ResponseRecorder {
	t.Helper()
	method := tc.method
	if method == "" {
		method = http.MethodGet
	}
	req := httptest.NewRequest(method, tc.target, strings.NewReader(tc.body))
	req.Header.Set("Accept", "*/*")
	if tc.ctype != "" {
		req.Header.Set("Content-Type", tc.ctype)
	}
	for k, v := range tc.headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func q(kv ...string) string {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Add(kv[i], kv[i+1])
	}
	return v.Encode()
}

const formType = "application/x-www-form-urlencoded"

func TestGoldenInspectJSON(t *testing.T) {
	t.Parallel()
	runLinkGolden(t, "link_inspect", []linkCase{
		{name: "tracking_link", target: "/?" + q("u", "https://shop.example.com/p/42?utm_source=news&fbclid=IwAR0&color=red,green&id=7&id=8&next=https%253A%252F%252Fexample.org%252F#frag=1")},
		{name: "phishing_shape", target: "/?" + q("u", "https://login.bank.example@exämple.net/verify?session=a+b")},
		{name: "no_scheme", target: "/?" + q("u", "example.com/a?b=1")},
		{name: "bad_url", target: "/?" + q("u", "http://[::1")},
		{name: "wrong_tool", target: "/?" + q("u", "curl 'https://example.com/' -H 'x: y'")},
		{name: "no_url", target: "/"},
	})
}

func TestGoldenCleanJSON(t *testing.T) {
	t.Parallel()
	safelinks := "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.example.com%2Farticle%3Fid%3D42%26utm_source%3Dnewsletter%26gclid%3DCj0KCQ&data=05%7C02&reserved=0"
	runLinkGolden(t, "link_clean", []linkCase{
		{name: "trackers", target: "/clean?" + q("u", "https://www.example.com/article?id=42&utm_source=twitter&utm_medium=social&fbclid=IwAR0Zx3&mc_eid=8f2a#top")},
		{name: "unwrapped", target: "/clean?" + q("u", safelinks)},
		{name: "unwrap_off", target: "/clean?" + q("u", safelinks, "unwrap", "false")},
		{name: "affiliate_kept", target: "/clean?" + q("u", "https://www.amazon.com/dp/B08N5WRWNW?tag=reviewer-20&ref_=nav_logo&th=1")},
		{name: "affiliate_stripped", target: "/clean?" + q("u", "https://www.amazon.com/dp/B08N5WRWNW?tag=reviewer-20&ref_=nav_logo&th=1", "affiliate", "true")},
		{name: "sorted", target: "/clean?" + q("u", "https://example.com/?z=1&a=2&utm_campaign=x", "sort", "true")},
		{name: "presigned", target: "/clean?" + q("u", "https://bucket.s3.amazonaws.com/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc&utm_source=x")},
		{name: "no_url", target: "/clean"},
	})
}

// The rules page's JSON is the whole table, as Rules holds it.
func TestRulesJSON(t *testing.T) {
	t.Parallel()
	rec := linkCall(t, newLinkApp(t, nil, nil), linkCase{target: "/clean/rules"})
	want, err := json.Marshal(linktools.Rules())
	if err != nil {
		t.Fatal(err)
	}
	var w, g any
	if err := json.Unmarshal(want, &w); err != nil || json.Unmarshal(rec.Body.Bytes(), &g) != nil || rec.Code != http.StatusOK {
		t.Fatalf("GET /clean/rules = %d %.100s", rec.Code, rec.Body)
	}
	if diff := cmp.Diff(w, g); diff != "" {
		t.Errorf("GET /clean/rules vs Rules() (-want +got):\n%s", diff)
	}
}

func TestGoldenDiffJSON(t *testing.T) {
	t.Parallel()
	runLinkGolden(t, "link_diff", []linkCase{
		{name: "staging_vs_prod", target: "/diff?" + q("a", "https://example.com/search?q=shoes&page=2&sort=price", "b", "https://staging.example.com/search?page=2&q=shoes&sort=rating&debug=1")},
		{name: "cosmetic", target: "/diff?" + q("a", "HTTPS://Example.com:443/a/./b?x=%7e", "b", "https://example.com/a/b?x=~")},
		{name: "identical", target: "/diff?" + q("a", " https://example.com/?a=1 ", "b", "https://example.com/?a=1")},
		{name: "bad_a", target: "/diff?" + q("a", "http://[::1", "b", "https://example.com/")},
		{name: "bad_b", target: "/diff?" + q("a", "https://example.com/", "b", "http://%zz")},
		{name: "wrong_tool", target: "/diff?" + q("a", "https://example.com/", "b", "curl https://example.com/ -H 'a: b'")},
		{name: "missing_b", target: "/diff?" + q("a", "https://example.com/")},
	})
}

func TestGoldenCurlJSON(t *testing.T) {
	t.Parallel()
	chrome := "curl 'https://api.example.com/v1/items?page=2&limit=50' -H 'accept: application/json' -H 'authorization: Bearer eyJhbGciOiJIUzI1NiJ9' -H 'user-agent: Mozilla/5.0' --compressed"
	post := "curl -X POST https://api.example.com/v1/login -d 'user=a&pass=b' -u admin:secret -b 'sid=1'"
	runLinkGolden(t, "link_curl", []linkCase{
		{name: "get_parse", target: "/curl?" + q("curl", chrome)},
		{name: "post_parse", method: http.MethodPost, target: "/curl", ctype: formType, body: q("curl", post)},
		{name: "get_flag_moves_body", target: "/curl?" + q("curl", "curl -G https://example.com/search --data-urlencode 'q=a b'")},
		{name: "bare_url", target: "/curl?" + q("curl", "https://example.com/x?y=1")},
		{name: "parse_url_invalid", target: "/curl?" + q("curl", "curl 'http://[::1'")},
		{name: "no_url_in_command", target: "/curl?" + q("curl", "curl -H 'a: b'")},
		{name: "unterminated", target: "/curl?" + q("curl", "curl 'https://example.com")},
		{name: "build", target: "/curl?" + q("u", "https://example.com/?a='b'", "ua", "googlebot", "follow", "true", "headers", "true")},
		{name: "build_bad_persona", target: "/curl?" + q("u", "https://example.com/", "ua", "nobody")},
		{name: "no_input", target: "/curl"},
	})
}

func TestGoldenExtractJSON(t *testing.T) {
	t.Parallel()
	text := `<p>Read <a href="https://example.com/post?utm_source=newsletter">our post</a> or https://example.com/sale. Again: https://example.com/sale</p>`
	runLinkGolden(t, "link_extract", []linkCase{
		{name: "get", target: "/extract?" + q("text", text)},
		{name: "post", method: http.MethodPost, target: "/extract", ctype: formType, body: q("text", "see [docs](https://example.com/docs) and javascript:alert(1)")},
		{name: "empty", target: "/extract"},
	})
}

func TestGoldenUTMJSON(t *testing.T) {
	t.Parallel()
	runLinkGolden(t, "link_utm", []linkCase{
		{name: "retag", target: "/utm?" + q("u", "https://example.com/?utm_source=old&utm_medium=email&ref=home", "utm_source", "twitter", "utm_campaign", "Fall Sale+")},
		{name: "empty_fields_keep", target: "/utm?" + q("u", "https://example.com/?utm_source=old&utm_source=dup", "utm_source", "", "utm_medium", "  ", "utm_campaign", "", "utm_term", "", "utm_content", "")},
		{name: "no_scheme", target: "/utm?" + q("u", "example.com/landing", "utm_source", "news")},
		{name: "path_only", target: "/utm?" + q("u", "/landing", "utm_source", "news")},
		{name: "bad_url", target: "/utm?" + q("u", "http://[::1", "utm_source", "news")},
		{name: "no_url", target: "/utm"},
	})
}

func TestGoldenEncodeJSON(t *testing.T) {
	t.Parallel()
	runLinkGolden(t, "link_encode", []linkCase{
		{name: "value", target: "/encode?" + q("v", "hello world & a+b=c")},
		{name: "empty", target: "/encode"},
	})
}

// POST /short, offline only: every case here is answered before a successful
// insert, which needs Mongo.
func TestGoldenShortCreateJSON(t *testing.T) {
	t.Parallel()
	keyed := map[string]string{"X-Api-Key": testAPIKey}
	jsonType := "application/json"
	off := offlineShortener(t)
	cases := []linkCase{
		{name: "switched_off", body: `{"url":"https://example.com/"}`, ctype: jsonType, headers: keyed},
		{name: "keyless", body: `{"url":"https://example.com/"}`, ctype: jsonType, headers: keyed, short: keylessShortener(t, offlineStore())},
		{name: "no_key", body: `{"url":"https://example.com/"}`, ctype: jsonType, short: off},
		{name: "wrong_key", body: `{"url":"https://example.com/"}`, ctype: jsonType, headers: map[string]string{"X-Api-Key": "nope"}, short: off},
		{name: "unreadable_body", body: `{"url":`, ctype: jsonType, headers: keyed, short: off},
		{name: "bad_ttl", body: `{"url":"https://example.com/","ttl":"a month"}`, ctype: jsonType, headers: keyed, short: off},
		{name: "short_ttl", body: `{"url":"https://example.com/","ttl":"30s"}`, ctype: jsonType, headers: keyed, short: off},
		{name: "bad_target", body: `{"url":"javascript:alert(1)"}`, ctype: jsonType, headers: keyed, short: off},
		{name: "private_target", body: `{"url":"http://192.168.1.1/setup.cgi","ttl":"720h"}`, ctype: jsonType, headers: keyed, short: off},
		{name: "bad_slug", body: `{"url":"https://example.com/","slug":"Bad Slug"}`, ctype: jsonType, headers: keyed, short: off},
		{name: "reserved_slug", body: "url=https%3A%2F%2Fexample.com%2F&slug=admin", ctype: formType, headers: keyed, short: off},
		{name: "long_note", body: `{"url":"https://example.com/","note":"` + strings.Repeat("n", 300) + `"}`, ctype: jsonType, headers: keyed, short: off},
		{name: "clean_without_cleaner", body: `{"url":"https://example.com/?utm_source=x","clean":true}`, ctype: jsonType, headers: keyed, short: off},
		{name: "storage_down", body: `{"url":"https://example.com/","slug":"q4-report","ttl":"720h","note":"hi"}`, ctype: jsonType, headers: keyed, short: off},
	}
	for i := range cases {
		cases[i].method, cases[i].target = http.MethodPost, "/short"
	}
	runLinkGolden(t, "link_short_create", cases)
}
