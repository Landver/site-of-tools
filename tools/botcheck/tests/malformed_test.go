package tests

import (
	"net/http"
	"strings"
	"testing"
)

func TestCheckMalformedBodyAnswers400(t *testing.T) {
	for name, tc := range map[string]struct {
		hdr  map[string]string
		want string
	}{
		"browser": {map[string]string{"Accept": "text/html"}, "Invalid fingerprint payload"},
		"htmx":    {map[string]string{"HX-Request": "true"}, "Invalid fingerprint payload"},
		"json":    {map[string]string{"Accept": "application/json"}, "invalid fingerprint payload"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := post(newTestApp(fakeLooker{}), "/check", `{not json`, tc.hdr)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("code = %d, want 400; body:\n%s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.want) {
				t.Errorf("body lacks %q:\n%s", tc.want, rec.Body.String())
			}
		})
	}
}
