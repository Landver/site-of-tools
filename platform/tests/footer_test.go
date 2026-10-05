package tests

import (
	"bytes"
	"testing"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/platform/goldentest"
	"github.com/Landver/site-of-tools/shared"
)

var footerFlags = []string{"Attribution", "SpamhausAttribution", "ShodanAttribution", "CertsAttribution", "RDAPAttribution"}

func renderFooter(t *testing.T, data map[string]any) string {
	t.Helper()
	r := platform.NewRenderer(false, nil, platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"})
	var buf bytes.Buffer
	if err := r.Render(nil, &buf, "partials/footer", data); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// TestFooterGolden pins the footer with no credit, each one alone, and all.
func TestFooterGolden(t *testing.T) {
	all := map[string]any{}
	got := map[string]string{"none": renderFooter(t, nil)}
	for _, f := range footerFlags {
		got[f] = renderFooter(t, map[string]any{f: true})
		all[f] = true
	}
	got["all"] = renderFooter(t, all)
	goldentest.JSON(t, "footer", got)
}
