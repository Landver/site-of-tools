package tests

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/ciphertools"
)

func encodeOf(t *testing.T, from, text string) *ciphertools.Encoded {
	t.Helper()
	res, err := runOp(t, "encode", url.Values{"text": {text}, "from": {from}}, nil)
	if err != nil {
		t.Fatalf("encode %s %q: %v", from, text, err)
	}
	return res.(*ciphertools.Encoded)
}

// RFC 4648 §10 test vectors.
func TestEncodeRFC4648Vectors(t *testing.T) {
	for _, c := range []struct{ in, b64, b32 string }{
		{"f", "Zg==", "MY======"},
		{"fo", "Zm8=", "MZXQ===="},
		{"foo", "Zm9v", "MZXW6==="},
		{"foob", "Zm9vYg==", "MZXW6YQ="},
		{"fooba", "Zm9vYmE=", "MZXW6YTB"},
		{"foobar", "Zm9vYmFy", "MZXW6YTBOI======"},
	} {
		e := encodeOf(t, "utf8", c.in)
		if e.Base64 != c.b64 || e.Base32 != c.b32 || e.Bytes != len(c.in) || e.Text != c.in {
			t.Errorf("%q: %+v", c.in, e)
		}
	}
	e := encodeOf(t, "utf8", "\xfb\xff")
	if e.Base64 != "+/8=" || e.Base64URL != "-_8" || e.Hex != "fbff" || e.HexColons != "fb:ff" {
		t.Errorf("fbff: %+v", e)
	}
}

// Every output reads back to the same bytes, from every encoding.
func TestEncodeRoundTrips(t *testing.T) {
	for _, in := range []string{"f", "foobar", "Hello, world!\n", "naïve ☃", "\x00\xff\xfe\x80 binary", strings.Repeat("\xa5", 31)} {
		e := ciphertools.EncodeBytes([]byte(in), "test")
		forms := map[string]string{
			"hex": e.Hex, "base64": e.Base64, "base64url": e.Base64URL, "base32": e.Base32,
		}
		for from, v := range forms {
			if got := encodeOf(t, from, v); got.Hex != e.Hex {
				t.Errorf("%q via %s %q: hex %s, want %s", in, from, v, got.Hex, e.Hex)
			}
		}
		if got := encodeOf(t, "hex", e.HexColons); got.Hex != e.Hex {
			t.Errorf("%q via colon hex: %s", in, got.Hex)
		}
		// base64 output is accepted as base64url input and vice versa: the
		// alphabet decides, and the variant is reported.
		if got := encodeOf(t, "base64url", e.Base64); got.Hex != e.Hex {
			t.Errorf("%q: padded std base64 through base64url: %s", in, got.Hex)
		}
		if e.Text != "" {
			if got := encodeOf(t, "utf8", e.Text); got.Hex != e.Hex {
				t.Errorf("%q via text: %s", in, got.Hex)
			}
		}
	}
}

func TestEncodeNamesBase64Variant(t *testing.T) {
	for in, want := range map[string]string{
		"Zm9vYg==": ciphertools.VariantStd,
		"Zm9vYg":   ciphertools.VariantStdRaw,
		"-_8=":     ciphertools.VariantURL,
		"-_8":      ciphertools.VariantURLRaw,
	} {
		if got := encodeOf(t, "base64", in).ReadAs; got != want {
			t.Errorf("%q read as %q, want %q", in, got, want)
		}
	}
}

// Binary that isn't UTF-8 is never forced into text, and the page says where
// it stopped being UTF-8.
func TestEncodeNonUTF8(t *testing.T) {
	e := encodeOf(t, "hex", "61ff62")
	if e.UTF8 || e.Text != "" || !strings.Contains(e.TextNote, "offset 1") || !strings.Contains(e.TextNote, "0xff") {
		t.Fatalf("%+v", e)
	}
	e = encodeOf(t, "hex", "610062")
	if !e.UTF8 || e.Text != "" || !strings.Contains(e.TextNote, "control characters") {
		t.Fatalf("NUL: %+v", e)
	}
}

func TestEncodeInvalidInputNamesOffset(t *testing.T) {
	for _, c := range []struct{ from, text, want string }{
		{"hex", "abzz", "offset 2"},
		{"hex", "ab\ncd zz", "offset 6"}, // offsets count in the original, whitespace included
		{"hex", "abc", "odd number"},
		{"base64", "YW*j", "offset 2"},
		{"base64", "ab+c-d", "mixes"},
		{"base32", "MZX1", "offset 3"},
	} {
		_, err := runOp(t, "encode", url.Values{"text": {c.text}, "from": {c.from}}, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %q: err = %v, want %q", c.from, c.text, err, c.want)
		}
	}
	if _, err := runOp(t, "encode", url.Values{"text": {""}}, nil); err == nil {
		t.Error("empty input: no error")
	}
}

func TestEncodeNotesTrailingNewline(t *testing.T) {
	e := encodeOf(t, "utf8", "abc\n")
	if e.Bytes != 4 || !noted(e.Warnings, "Ends in a newline") {
		t.Errorf("%+v", e)
	}
}

func TestBasicAuthVectors(t *testing.T) {
	for _, c := range []struct{ user, password, token string }{
		{"Aladdin", "open sesame", "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="}, // RFC 7617 §2
		{"test", "123£", "dGVzdDoxMjPCow=="},                       // RFC 7617 §2.1, UTF-8
		{"a", "b:c", "YTpiOmM="},                                   // a colon in the password is fine
	} {
		b, err := ciphertools.BuildBasic(c.user, c.password)
		if err != nil {
			t.Fatalf("%s: %v", c.user, err)
		}
		if b.Token != c.token || b.Header != "Authorization: Basic "+c.token {
			t.Errorf("build %s:%s = %q", c.user, c.password, b.Header)
		}
		for _, pasted := range []string{b.Header, "Basic " + c.token, "basic " + c.token, c.token, "  authorization: BASIC " + c.token + "\n", `"` + c.token + `"`} {
			d, err := ciphertools.DecodeBasic(pasted)
			if err != nil {
				t.Fatalf("decode %q: %v", pasted, err)
			}
			if d.User.Value != c.user || d.Password.Value != c.password {
				t.Errorf("decode %q = %q / %q", pasted, d.User.Value, d.Password.Value)
			}
		}
	}
}

func TestBasicAuthRefusals(t *testing.T) {
	_, err := ciphertools.BuildBasic("ab:c", "pw")
	if err == nil || !strings.Contains(err.Error(), "':' at offset 2") {
		t.Errorf("colon in user: %v", err)
	}
	for pasted, want := range map[string]string{
		"Basic QWxh!ZGRp":        "offset 10", // counted in what was pasted, prefix included
		"Bearer eyJhbGciOi":      "Bearer",
		"Basic bm9jb2xvbg==":     "no ':'",
		"Authorization: Basic  ": "no credentials",
	} {
		_, err := ciphertools.DecodeBasic(pasted)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", pasted, err, want)
		}
	}
	d, err := ciphertools.DecodeBasic("QWxhZGRpbjpvcGVuIHNlc2FtZQ")
	if err != nil || !noted(d.Warnings, "unpadded") || d.Token != "QWxhZGRpbjpvcGVuIHNlc2FtZQ==" {
		t.Errorf("unpadded: %+v %v", d, err)
	}
}

// The op picks build or decode from mode, or from which fields are filled.
func TestBasicOpModes(t *testing.T) {
	res, err := runOp(t, "basic", url.Values{"user": {"Aladdin"}, "password": {"open sesame"}}, nil)
	if err != nil || res.(*ciphertools.BasicAuth).Mode != "build" {
		t.Fatalf("build: %+v %v", res, err)
	}
	res, err = runOp(t, "basic", url.Values{"header": {"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="}}, nil)
	if err != nil || res.(*ciphertools.BasicAuth).User.Value != "Aladdin" {
		t.Fatalf("decode: %+v %v", res, err)
	}
	if _, err := runOp(t, "basic", url.Values{"mode": {"guess"}}, nil); err == nil {
		t.Error("unknown mode accepted")
	}
	if _, err := runOp(t, "basic", url.Values{"user": {"a:b"}, "mode": {"build"}}, nil); err == nil {
		t.Error("colon in user accepted through the op")
	}
}

func TestRenderEncodeEscapes(t *testing.T) {
	html := render(t, "encode", url.Values{"text": {"<script>alert(1)</script>"}})
	if strings.Contains(html, "<script>alert") {
		t.Fatal("input reached the fragment unescaped")
	}
	if !strings.Contains(html, "3c7363726970743e") {
		t.Error("hex missing")
	}
	html = render(t, "basic", url.Values{"mode": {"decode"}, "header": {"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="}})
	for _, want := range []string{"Aladdin", "open sesame", "Rebuilt header", "not encryption"} {
		if !strings.Contains(html, want) {
			t.Errorf("basic fragment lacks %q", want)
		}
	}
}

// Two forms share the basic op; with JavaScript off, only the one that was
// submitted gets its result box filled.
func TestBasicNoJSFillsOnlyItsBox(t *testing.T) {
	e := newCipherApp(t)
	body := url.Values{"mode": {"decode"}, "header": {"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="}}.Encode()
	rec := do(t, e, http.MethodPost, "/encode/basic", body, form, asBrowser)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	html := rec.Body.String()
	if n := strings.Count(html, "Rebuilt header"); n != 1 {
		t.Fatalf("decode result rendered %d times", n)
	}
	build := html[strings.Index(html, `id="basic-build-result"`):strings.Index(html, `id="basic-decode-result"`)]
	if strings.Contains(build, "Aladdin") {
		t.Error("decode result leaked into the build box")
	}
	// The decode textarea is refilled; the build form isn't.
	if !strings.Contains(html, "QWxhZGRpbjpvcGVuIHNlc2FtZQ==</textarea>") {
		t.Error("decode input not refilled")
	}
}

// Percent-encoding lives on Link Tools; the page links there from the catalog.
func TestEncodePageLinksToLinkTools(t *testing.T) {
	funcs := template.FuncMap{"navTools": func() []platform.Tool {
		return []platform.Tool{{Name: "Link Tools", URL: "https://link.example"}}
	}}
	e := cipherApp(funcs, nil, nil)
	rec := do(t, e, http.MethodGet, "/encode", "", "", asBrowser)
	if !strings.Contains(rec.Body.String(), `href="https://link.example/encode"`) {
		t.Fatal("no link to Link Tools' encode page")
	}
}
