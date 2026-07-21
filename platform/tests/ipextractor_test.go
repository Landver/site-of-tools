package tests

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

// TestRealIPExtraction locks in client-IP trust model wired by platform.NewApp
// (cfIPExtractor). Security-relevant → c.RealIP() feeds request log + geo/reputation
// lookups. No other test builds app via NewApp → regression dropping CF branch,
// inverting precedence, or trusting X-Forwarded-For from untrusted peer would
// otherwise pass whole suite.
func TestRealIPExtraction(t *testing.T) {
	app := platform.NewApp(nil, fstest.MapFS{}, false, nil) // nil RequestLog: persistence off
	app.GET("/ip", func(c *echo.Context) error { return c.String(http.StatusOK, c.RealIP()) })

	// httptest default RemoteAddr (192.0.2.1, TEST-NET-1) neither loopback nor
	// private → stands in for untrusted direct peer.
	const untrustedPeer = "192.0.2.1:1234"

	cases := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:    "CF-Connecting-IP wins over X-Forwarded-For",
			headers: map[string]string{"CF-Connecting-IP": "203.0.113.9", "X-Forwarded-For": "198.51.100.1"},
			want:    "203.0.113.9",
		},
		{
			name:       "XFF from an untrusted (public) peer is ignored",
			remoteAddr: untrustedPeer,
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.7"},
			want:       "192.0.2.1", // falls through to socket address
		},
		{
			name:       "XFF from a loopback peer (nginx) is trusted",
			remoteAddr: "127.0.0.1:5555",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.7"},
			want:       "198.51.100.7",
		},
		{
			name:       "no proxy headers falls back to the socket address",
			remoteAddr: untrustedPeer,
			want:       "192.0.2.1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/ip", nil)
			if tc.remoteAddr != "" {
				req.RemoteAddr = tc.remoteAddr
			}
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			app.ServeHTTP(rec, req)
			if got := rec.Body.String(); got != tc.want {
				t.Errorf("RealIP = %q, want %q", got, tc.want)
			}
		})
	}
}
