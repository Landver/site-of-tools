package linktools

import "testing"

func FuzzParseRawHeaders(f *testing.F) {
	f.Add("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nCache-Control: public, max-age=3600\r\nSet-Cookie: sid=123; Secure\r\n")
	f.Add("HTTP/2 404\r\nCache-Control: no-store\r\n")
	f.Add("invalid line\r\n:colonfirst\r\nkey: value\r\n")
	f.Add("")

	f.Fuzz(func(t *testing.T, raw string) {
		rep, err := ParseRawHeaders(raw)
		if err == nil && rep == nil {
			t.Fatal("nil report without error")
		}
	})
}
