package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

var hashOf = runner[ciphertools.HashResult]("hash")

func digestByID(t *testing.T, ds []ciphertools.Digest, id string) ciphertools.Digest {
	t.Helper()
	for _, d := range ds {
		if d.ID == id {
			return d
		}
	}
	t.Fatalf("no digest %q", id)
	return ciphertools.Digest{}
}

// "abc" vectors: FIPS 180-4 / 202, RFC 7693 (BLAKE2), and the well-known values for the rest.
var abcVectors = map[string]string{
	"md5":         "900150983cd24fb0d6963f7d28e17f72",
	"sha1":        "a9993e364706816aba3e25717850c26c9cd0d89d",
	"sha224":      "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
	"sha256":      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	"sha384":      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
	"sha512":      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
	"sha512_256":  "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
	"sha3_256":    "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
	"sha3_512":    "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
	"blake2b_256": "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
	"blake2b_512": "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
	"blake2s_256": "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
	"keccak256":   "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
	"crc32":       "352441c2",
	"crc32c":      "364b3fb7",
	"adler32":     "024d0127",
}

func TestHashKnownVectors(t *testing.T) {
	r := hashOf(t, url.Values{"text": {"abc"}})
	if r.Bytes != 3 {
		t.Fatalf("bytes = %d", r.Bytes)
	}
	if len(r.Digests) != len(abcVectors) {
		t.Errorf("%d digests, want %d", len(r.Digests), len(abcVectors))
	}
	for id, want := range abcVectors {
		d := digestByID(t, r.Digests, id)
		if d.Hex != want {
			t.Errorf("%s(abc) = %s, want %s", d.Name, d.Hex, want)
		}
		b, _ := hex.DecodeString(want)
		if d.Base64 != base64.StdEncoding.EncodeToString(b) {
			t.Errorf("%s base64 = %s", d.Name, d.Base64)
		}
	}
}

func TestHashEmptyInput(t *testing.T) {
	r := hashOf(t, url.Values{"text": {""}})
	for id, want := range map[string]string{
		"sha256":    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"keccak256": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		"sha3_256":  "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
	} {
		if d := digestByID(t, r.Digests, id); d.Hex != want {
			t.Errorf("%s(\"\") = %s, want %s", d.Name, d.Hex, want)
		}
	}
	if !noted(r.Warnings, "zero bytes") {
		t.Error("empty input not called out")
	}
}

// Keccak-256 is not SHA3-256: labelled distinctly, and different output.
func TestHashKeccakIsLabelledApartFromSHA3(t *testing.T) {
	r := hashOf(t, url.Values{"text": {"abc"}})
	k, s := digestByID(t, r.Digests, "keccak256"), digestByID(t, r.Digests, "sha3_256")
	if k.Hex == s.Hex {
		t.Fatal("Keccak-256 and SHA3-256 agree; one of them is wired to the other")
	}
	if !strings.Contains(k.Name, "Ethereum") || !strings.Contains(k.Note, "SHA3-256") {
		t.Errorf("Keccak row = %q / %q", k.Name, k.Note)
	}
}

func TestHashWeakAlgorithmsMarked(t *testing.T) {
	r := hashOf(t, url.Values{"text": {"abc"}})
	for _, d := range r.Digests {
		weak := d.ID == "md5" || d.ID == "sha1"
		if d.Weak != weak {
			t.Errorf("%s: Weak = %v", d.Name, d.Weak)
		}
		if weak && d.Note != "not collision-resistant" {
			t.Errorf("%s: note %q", d.Name, d.Note)
		}
	}
}

// Text vs bytes: "abc", 616263 and YWJj are the same three bytes.
func TestHashTextHexBase64HashIdentically(t *testing.T) {
	want := hashOf(t, url.Values{"text": {"abc"}}).Digests
	for _, f := range []url.Values{
		{"text": {"616263"}, "enc": {"hex"}},
		{"text": {"61 62 63"}, "enc": {"hex"}},
		{"text": {"0x616263"}, "enc": {"hex"}},
		{"text": {"YWJj"}, "enc": {"base64"}},
	} {
		got := hashOf(t, f)
		if got.Bytes != 3 {
			t.Errorf("%v: %d bytes", f, got.Bytes)
		}
		for i := range want {
			if got.Digests[i].Hex != want[i].Hex {
				t.Errorf("%v: %s differs", f, want[i].Name)
			}
		}
	}
	file := opOf[ciphertools.HashResult](t, "hash", url.Values{}, map[string][]byte{"file": []byte("abc")})
	if file.Source != "file" || digestByID(t, file.Digests, "sha256").Hex != abcVectors["sha256"] {
		t.Errorf("file: %+v", file)
	}
}

func TestHashFileWinsOverText(t *testing.T) {
	r := opOf[ciphertools.HashResult](t, "hash", url.Values{"text": {"something else"}}, map[string][]byte{"file": []byte("abc")})
	if digestByID(t, r.Digests, "md5").Hex != abcVectors["md5"] {
		t.Fatal("the text was hashed instead of the file")
	}
	if !noted(r.Warnings, "text box was ignored") {
		t.Error("no note that the text was ignored")
	}
}

func TestHashTrailingNewline(t *testing.T) {
	// Not trimmed: the newline is data, and the result says so.
	r := hashOf(t, url.Values{"text": {"abc\n"}})
	if r.Bytes != 4 || r.TrimmedNewline || digestByID(t, r.Digests, "sha256").Hex == abcVectors["sha256"] {
		t.Fatalf("untrimmed: %d bytes, trimmed=%v", r.Bytes, r.TrimmedNewline)
	}
	if !noted(r.Warnings, `Ends in a newline (\n)`) {
		t.Errorf("no newline note: %+v", r.Warnings)
	}

	for _, in := range []string{"abc\n", "abc\r\n"} {
		r := hashOf(t, url.Values{"text": {in}, "trim_newline": {"on"}})
		if r.Bytes != 3 || !r.TrimmedNewline || digestByID(t, r.Digests, "sha256").Hex != abcVectors["sha256"] {
			t.Errorf("%q trimmed: %d bytes, trimmed=%v", in, r.Bytes, r.TrimmedNewline)
		}
		if !noted(r.Warnings, "Stripped one trailing") {
			t.Errorf("%q: trim not reported", in)
		}
	}
	// Exactly one: a blank last line survives.
	r = hashOf(t, url.Values{"text": {"abc\n\n"}, "trim_newline": {"true"}})
	if r.Bytes != 4 {
		t.Errorf("abc\\n\\n trimmed to %d bytes, want 4", r.Bytes)
	}
	r = hashOf(t, url.Values{"text": {"abc"}, "trim_newline": {"on"}})
	if r.TrimmedNewline || !noted(r.Warnings, "no trailing newline") {
		t.Errorf("nothing to trim: %+v", r)
	}
	// The API's JSON false is not "on".
	r = hashOf(t, url.Values{"text": {"abc\n"}, "trim_newline": {"false"}})
	if r.Bytes != 4 {
		t.Error(`trim_newline "false" trimmed`)
	}
}

// Hashed as typed: no trimming, no Unicode normalisation (U+00E9 and e + U+0301 differ).
func TestHashDoesNotNormalise(t *testing.T) {
	nfc, nfd := hashOf(t, url.Values{"text": {"caf\u00e9"}}), hashOf(t, url.Values{"text": {"cafe\u0301"}})
	if nfc.Bytes != 5 || nfd.Bytes != 6 || digestByID(t, nfc.Digests, "sha256").Hex == digestByID(t, nfd.Digests, "sha256").Hex {
		t.Errorf("NFC %d bytes, NFD %d bytes, same digest: the text was normalised", nfc.Bytes, nfd.Bytes)
	}
	if r := hashOf(t, url.Values{"text": {" abc\t"}}); r.Bytes != 5 || digestByID(t, r.Digests, "sha256").Hex == abcVectors["sha256"] {
		t.Errorf("surrounding whitespace trimmed: %d bytes", r.Bytes)
	}
}

func TestHashCRLFAndBOMNotes(t *testing.T) {
	r := hashOf(t, url.Values{"text": {"a\r\nb"}})
	if !noted(r.Warnings, "CRLF") {
		t.Errorf("CRLF not noted: %+v", r.Warnings)
	}
	r = hashOf(t, url.Values{"text": {"\xef\xbb\xbfabc"}})
	if r.Bytes != 6 || !noted(r.Warnings, "byte order mark") {
		t.Errorf("BOM not noted: %d bytes %+v", r.Bytes, r.Warnings)
	}
	r = hashOf(t, url.Values{"text": {"abc"}})
	if len(r.Warnings) != 0 {
		t.Errorf("clean input got notes: %+v", r.Warnings)
	}
}

func TestHashCompareFindsTheAlgorithm(t *testing.T) {
	sha := abcVectors["sha256"]
	raw, _ := hex.DecodeString(sha)
	b64 := base64.StdEncoding.EncodeToString(raw)
	for name, expected := range map[string]string{
		"hex":             sha,
		"uppercase":       strings.ToUpper(sha),
		"colons":          fp(raw),
		"spaces and wrap": sha[:32] + "\n " + sha[32:] + "  ",
		"base64":          b64,
		"base64url":       base64.RawURLEncoding.EncodeToString(raw),
		"sha256sum line":  sha + "  -",
		"BSD line":        "SHA256 (abc.txt) = " + sha,
		"labelled":        "sha256:" + sha,
		"SRI":             "sha256-" + b64,
	} {
		t.Run(name, func(t *testing.T) {
			c := hashOf(t, url.Values{"text": {"abc"}, "expected": {expected}}).Compare
			if c == nil || !c.Match || !slices.Equal(c.Matches, []string{"SHA-256"}) {
				t.Fatalf("compare = %+v", c)
			}
		})
	}
	r := hashOf(t, url.Values{"text": {"abc"}, "expected": {abcVectors["md5"]}})
	if !slices.Equal(r.Compare.Matches, []string{"MD5"}) || !digestByID(t, r.Digests, "md5").Match {
		t.Errorf("md5 compare = %+v", r.Compare)
	}
}

func TestHashCompareNoMatchNamesSameLength(t *testing.T) {
	// SHA-256 of "abc\n": the checksum of a file whose text is "abc".
	r := hashOf(t, url.Values{"text": {"abc"}, "expected": {"edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb"}})
	c := r.Compare
	if c == nil || c.Match || c.Bytes != 32 {
		t.Fatalf("compare = %+v", c)
	}
	for _, want := range []string{"SHA-256", "SHA3-256", "BLAKE2b-256", "BLAKE2s-256", "SHA-512/256", "Keccak-256 (Ethereum)"} {
		if !slices.Contains(c.SameSize, want) {
			t.Errorf("SameSize %v lacks %s", c.SameSize, want)
		}
	}
	if slices.Contains(c.SameSize, "SHA-512") {
		t.Error("SHA-512 listed as 32 bytes")
	}
	// The checksum it came from does match once the newline is part of the input.
	r = hashOf(t, url.Values{"text": {"abc\n"}, "expected": {c.Given}})
	if !r.Compare.Match {
		t.Error("abc\\n doesn't match its own SHA-256")
	}
}

// A garbage expected value says where it broke, and the hashes still come back.
func TestHashCompareGarbage(t *testing.T) {
	r := hashOf(t, url.Values{"text": {"abc"}, "expected": {"ba7816bf8f01cfea!14140de"}})
	if r.Compare == nil || r.Compare.Match || !strings.Contains(r.Compare.Detail, "offset 16") {
		t.Fatalf("compare = %+v", r.Compare)
	}
	if len(r.Digests) == 0 {
		t.Fatal("hashes dropped because the expected value was bad")
	}
}

// Nothing left after the prefix, no algorithm of that length, and a value that is not even hex-like.
func TestHashCompareNoReading(t *testing.T) {
	for expected, want := range map[string]string{
		"t=1,v1=": "Nothing left to compare once the prefix was removed.",
		"000000":  "No algorithm here outputs 3 bytes, the length of the expected value read as hex.",
		"%%%":     "The expected value is neither hex nor base64: not base64 (standard, unpadded): '%' at offset 0.",
	} {
		c := hashOf(t, url.Values{"text": {"abc"}, "expected": {expected}}).Compare
		if c == nil || c.Match || c.Detail != want {
			t.Errorf("%q: compare = %+v, want detail %q", expected, c, want)
		}
	}
}

func TestHashInvalidInputNamesOffset(t *testing.T) {
	for enc, text := range map[string]string{"hex": "61zz", "base64": "YW!j"} {
		wantErr(t, "hash", url.Values{"text": {text}, "enc": {enc}}, "offset 2")
	}
}

func TestHashRefusesOversizedInput(t *testing.T) {
	big := make([]byte, ciphertools.MaxHashInput+1)
	_, err := runOp(t, "hash", url.Values{}, map[string][]byte{"file": big})
	if err == nil || !strings.Contains(err.Error(), "sha256sum") {
		t.Fatalf("err = %v", err)
	}
}

// In the browser a bigger file arrives cut to MaxFile+1 bytes, so the refusal can't state its size.
func TestHashOversizeMessageDoesNotStateTruncatedSize(t *testing.T) {
	_, err := runOp(t, "hash", url.Values{}, map[string][]byte{"file": make([]byte, ciphertools.MaxFile+1)})
	if err == nil || !strings.Contains(err.Error(), "file is larger than 64.0 MiB") {
		t.Fatalf("err = %v", err)
	}
}

func TestRenderHash(t *testing.T) {
	html := render(t, "hash", url.Values{"text": {"abc"}, "expected": {abcVectors["sha1"]}})
	holds(t, "fragment", html, abcVectors["sha256"], "Keccak-256 (Ethereum)", "not collision-resistant", "Match", "3</span> bytes hashed", `data-copy="`+abcVectors["md5"]+`"`)
}

// The API takes a file as multipart; a browser with JavaScript off gets the page with the result.
func TestHashFileUploadAPI(t *testing.T) {
	e := newCipherApp(t)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "abc.txt")
	fw.Write([]byte("abc"))
	mw.WriteField("expected", "SHA256 (abc.txt) = "+abcVectors["sha256"])
	mw.Close()

	rec := do(t, e, http.MethodPost, "/hash", body.String(), mw.FormDataContentType(), asAPI)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d: %s", rec.Code, rec.Body)
	}
	var got ciphertools.HashResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Source != "file" || got.Bytes != 3 || got.Compare == nil || !got.Compare.Match {
		t.Fatalf("got %+v", got)
	}

	// No file picked: the browser still sends an empty part, which isn't a file.
	body.Reset()
	mw = multipart.NewWriter(&body)
	mw.CreateFormFile("file", "")
	mw.WriteField("text", "abc")
	mw.Close()
	noJSPage(t, e, "/hash", body.String(), mw.FormDataContentType(), abcVectors["sha256"])
}
