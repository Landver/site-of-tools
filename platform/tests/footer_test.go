package tests

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
)

var footerFlags = []string{"Attribution", "SpamhausAttribution", "ShodanAttribution", "CertsAttribution", "RDAPAttribution"}

// The footer must render byte for byte the same for every combination of
// attribution flags. UPDATE_GOLDEN=1 rewrites testdata/footer.golden.json.
func TestFooterGolden(t *testing.T) {
	r := platform.NewRenderer(false, nil, platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"})
	got := map[string]string{}
	for mask := range 1 << len(footerFlags) {
		data := map[string]any{}
		var on []string
		for i, f := range footerFlags {
			data[f] = mask&(1<<i) != 0
			if data[f] == true {
				on = append(on, f)
			}
		}
		name := strings.Join(on, "+")
		if name == "" {
			name = "none"
		}
		var buf bytes.Buffer
		if err := r.Render(nil, &buf, "partials/footer", data); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got[name] = buf.String()
	}

	path := filepath.Join("testdata", "footer.golden.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(got); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (UPDATE_GOLDEN=1 creates it): %v", err)
	}
	var want map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("footer changed (-want +got):\n%s", diff)
	}
}
