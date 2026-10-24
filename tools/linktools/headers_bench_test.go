package linktools

import (
	"net/http"
	"testing"
)

const benchRawHeadersPayload = `HTTP/2 200 OK
content-type: text/html; charset=utf-8
cache-control: public, max-age=3600, s-maxage=7200, must-revalidate
cdn-cache-control: max-age=86400, stale-while-revalidate=600
etag: "33a64df551425fcc55e4d42a148795d9f25f89d4"
age: 120
vary: Accept-Encoding, Origin
cross-origin-opener-policy: same-origin
cross-origin-embedder-policy: require-corp
content-security-policy: default-src 'self'; script-src 'self' 'strict-dynamic'; object-src 'none'; base-uri 'none'
permissions-policy: camera=(), microphone=()
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
set-cookie: __Host-id=sess_987654321; Secure; Path=/; HttpOnly; SameSite=Lax
set-cookie: pref=dark; Secure; Path=/; SameSite=Strict; Max-Age=31536000`

func BenchmarkAnalyzeCache(b *testing.B) {
	h := make(http.Header)
	h.Set("Cache-Control", "public, max-age=3600, s-maxage=7200, must-revalidate")
	h.Set("CDN-Cache-Control", "max-age=86400, stale-while-revalidate=600")
	h.Set("ETag", `"33a64df551425fcc55e4d42a148795d9f25f89d4"`)
	h.Set("Age", "120")
	h.Set("Vary", "Accept-Encoding, Origin")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = AnalyzeCache(http.StatusOK, h)
	}
}

func BenchmarkAnalyzeSecurity(b *testing.B) {
	h := make(http.Header)
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Embedder-Policy", "require-corp")
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'strict-dynamic'; object-src 'none'")
	h.Set("Permissions-Policy", "camera=(), microphone=()")
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Add("Set-Cookie", "__Host-id=sess_987654321; Secure; Path=/; HttpOnly; SameSite=Lax")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = AnalyzeSecurity(h)
	}
}

func BenchmarkParseRawHeaders(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseRawHeaders(benchRawHeadersPayload)
		if err != nil {
			b.Fatal(err)
		}
	}
}
