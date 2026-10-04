package linktools

import "net/url"

// Example is one "try it" link in a page's empty state. Built in Go so
// url.Values does the escaping: a hand-escaped href is one typo away from the
// bug the page exists to explain.
type Example struct {
	Label string
	Href  string
}

func ex(label, path string, kv ...string) Example {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Add(kv[i], kv[i+1])
	}
	return Example{Label: label, Href: path + "?" + v.Encode()}
}

// examples per page key (the sub-nav's .Active). All on reserved example
// domains (RFC 2606) except Trace's, which needs real hosts that redirect.
var examples = map[string][]Example{
	"inspect": {
		ex("A tracking-heavy link", "/",
			"u", "https://shop.example.com/product/42?utm_source=newsletter&utm_medium=email&fbclid=IwAR0Zx3&color=red,green,blue&id=7&id=8&next=https%253A%252F%252Fexample.org%252Fcheckout%253Fstep%253D2"),
		ex("A phishing-shaped link", "/",
			"u", "https://login.yourbank.example@exämple.net/verify?session=a+b"),
		ex("A token in the fragment", "/",
			"u", "https://app.example.com/callback#access_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9.c2ln&token_type=bearer&state=xyz"),
	},
	"clean": {
		ex("A Safe Links URL", "/clean",
			"u", "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.example.com%2Farticle%3Fid%3D42%26utm_source%3Dnewsletter%26gclid%3DCj0KCQ&data=05%7C02&reserved=0"),
		ex("A link full of trackers", "/clean",
			"u", "https://www.example.com/article?id=42&utm_source=twitter&utm_medium=social&fbclid=IwAR0Zx3&mc_eid=8f2a"),
		ex("An Amazon link with an affiliate tag", "/clean",
			"u", "https://www.amazon.com/dp/B08N5WRWNW?tag=reviewer-20&ref_=nav_logo&th=1", "affiliate", "true"),
	},
	"trace": {
		ex("http to https", "/trace", "u", "http://github.com/"),
		ex("Asked as Googlebot", "/trace", "u", "http://google.com/", "ua", "googlebot"),
	},
	"diff": {
		ex("Staging vs production", "/diff",
			"a", "https://example.com/search?q=shoes&page=2&sort=price",
			"b", "https://staging.example.com/search?page=2&q=shoes&sort=rating&debug=1"),
		ex("Same request, written differently", "/diff",
			"a", "HTTPS://Example.com:443/a/./b?x=%7e",
			"b", "https://example.com/a/b?x=~"),
	},
	"curl": {
		ex("A Copy as cURL command", "/curl",
			"curl", "curl 'https://api.example.com/v1/items?page=2&limit=50' -H 'accept: application/json' -H 'authorization: Bearer eyJhbGciOiJIUzI1NiJ9' -H 'user-agent: Mozilla/5.0' --compressed"),
		ex("A URL as Googlebot would ask", "/curl",
			"u", "https://example.com/", "ua", "googlebot", "follow", "true"),
	},
	"utm": {
		ex("A newsletter link", "/utm",
			"u", "https://example.com/pricing", "utm_source", "newsletter", "utm_medium", "email", "utm_campaign", "october-launch"),
		ex("Re-tag a tagged link", "/utm",
			"u", "https://example.com/?utm_source=old&ref=home", "utm_source", "twitter", "utm_medium", "social"),
	},
	"encode": {
		ex("Spaces and symbols", "/encode", "v", "hello world & a+b=c"),
		ex("Encoded twice", "/encode", "v", "https%253A%252F%252Fexample.com%252F%253Fq%253Da%252Bb"),
		ex("Base64", "/encode", "v", "aGVsbG8gd29ybGQ="),
	},
	"extract": {
		ex("An HTML email", "/extract",
			"text", `<p>Read <a href="https://example.com/post?utm_source=newsletter">our new post</a>, or <a href="https://example.com/sale">click here</a>. Unsubscribe: https://example.com/unsub?id=42</p>`),
		ex("Markdown", "/extract",
			"text", "See [the docs](https://example.com/docs), [the docs again](https://example.com/docs) and https://example.com/changelog."),
	},
}
