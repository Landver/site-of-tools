package tests

import (
	"cmp"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Landver/site-of-tools/platform/goldentest"
	"github.com/Landver/site-of-tools/tools/linktools"
)

type linkCase struct {
	name, method, target, body string
	headers                    map[string]string
	short                      *linktools.Shortener
}

func runLinkGolden(t *testing.T, file string, cases []linkCase) {
	t.Helper()
	got := map[string]*httptest.ResponseRecorder{}
	for _, tc := range cases {
		e := newLinkApp(t, nil, tc.short)
		got[tc.name] = request(t, e, cmp.Or(tc.method, http.MethodGet), tc.target, tc.headers, tc.body)
	}
	goldentest.JSON(t, file, goldentest.Recorded(got))
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
		{name: "bad_url", target: "/?" + q("u", "http://[::1")},
		{name: "wrong_tool", target: "/?" + q("u", "curl 'https://example.com/' -H 'x: y'")},
		{name: "no_url", target: "/"},
	})
}

func TestGoldenCleanJSON(t *testing.T) {
	t.Parallel()
	runLinkGolden(t, "link_clean", []linkCase{
		{name: "unwrapped", target: "/clean?" + q("u", "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.example.com%2Farticle%3Fid%3D42%26utm_source%3Dnewsletter%26gclid%3DCj0KCQ&data=05%7C02&reserved=0")},
	})
}

func TestGoldenDiffJSON(t *testing.T) {
	t.Parallel()
	runLinkGolden(t, "link_diff", []linkCase{
		{name: "staging_vs_prod", target: "/diff?" + q("a", "https://example.com/search?q=shoes&page=2&sort=price", "b", "https://staging.example.com/search?page=2&q=shoes&sort=rating&debug=1")},
		{name: "bad_b", target: "/diff?" + q("a", "https://example.com/", "b", "http://%zz")},
		{name: "missing_b", target: "/diff?" + q("a", "https://example.com/")},
	})
}

func TestGoldenCurlJSON(t *testing.T) {
	t.Parallel()
	post := "curl -X POST https://api.example.com/v1/login -d 'user=a&pass=b' -u admin:secret -b 'sid=1'"
	runLinkGolden(t, "link_curl", []linkCase{
		{name: "post_parse", method: http.MethodPost, target: "/curl", body: q("curl", post), headers: map[string]string{"Content-Type": formType}},
		{name: "bare_url", target: "/curl?" + q("curl", "https://example.com/x?y=1")},
		{name: "unterminated", target: "/curl?" + q("curl", "curl 'https://example.com")},
		{name: "build", target: "/curl?" + q("u", "https://example.com/?a='b'", "ua", "googlebot", "follow", "true", "headers", "true")},
	})
}

func TestGoldenExtractJSON(t *testing.T) {
	t.Parallel()
	text := `<p>Read <a href="https://example.com/post?utm_source=newsletter">our post</a> or https://example.com/sale. Again: https://example.com/sale</p>`
	runLinkGolden(t, "link_extract", []linkCase{
		{name: "get", target: "/extract?" + q("text", text)},
		{name: "empty", target: "/extract"},
	})
}

func TestGoldenUTMJSON(t *testing.T) {
	t.Parallel()
	runLinkGolden(t, "link_utm", []linkCase{
		{name: "retag", target: "/utm?" + q("u", "https://example.com/?utm_source=old&utm_medium=email&ref=home", "utm_source", "twitter", "utm_campaign", "Fall Sale+")},
		{name: "empty_fields_keep", target: "/utm?" + q("u", "https://example.com/?utm_source=old&utm_source=dup", "utm_source", "", "utm_medium", "  ", "utm_campaign", "", "utm_term", "", "utm_content", "")},
	})
}

func TestGoldenEncodeJSON(t *testing.T) {
	t.Parallel()
	runLinkGolden(t, "link_encode", []linkCase{
		{name: "value", target: "/encode?" + q("v", "hello world & a+b=c")},
		{name: "empty", target: "/encode"},
	})
}

// Offline: a successful insert needs Mongo.
func TestGoldenShortCreateJSON(t *testing.T) {
	t.Parallel()
	keyed := map[string]string{"X-Api-Key": testAPIKey, "Content-Type": "application/json"}
	off := offlineShortener(t)
	cases := []linkCase{
		{name: "switched_off"},
		{name: "no_key", short: off},
		{name: "unreadable_body", body: `{"url":`, headers: keyed, short: off},
		{name: "bad_ttl", body: `{"url":"https://example.com/","ttl":"a month"}`, headers: keyed, short: off},
		{name: "reserved_slug", body: "url=https%3A%2F%2Fexample.com%2F&slug=admin", headers: map[string]string{"X-Api-Key": testAPIKey, "Content-Type": formType}, short: off},
		{name: "storage_down", body: `{"url":"https://example.com/","slug":"q4-report","ttl":"720h","note":"hi"}`, headers: keyed, short: off},
	}
	for i := range cases {
		cases[i].method, cases[i].target = http.MethodPost, "/short"
	}
	runLinkGolden(t, "link_short_create", cases)
}
