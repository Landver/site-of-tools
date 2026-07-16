package tests

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Landver/site-of-tools/platform"
)

func TestAssetVersioner(t *testing.T) {
	fsys := fstest.MapFS{
		"js/app.js":    {Data: []byte("console.log(1)")},
		"css/site.css": {Data: []byte("body{}")},
	}
	asset := platform.AssetVersioner(fsys)

	app := asset("js/app.js")
	if !strings.HasPrefix(app, "/static/js/app.js?v=") {
		t.Fatalf("versioned url = %q, want /static/js/app.js?v=…", app)
	}
	if ver := strings.TrimPrefix(app, "/static/js/app.js?v="); len(ver) != 8 {
		t.Errorf("hash = %q, want 8 hex chars", ver)
	}

	// Memoised + deterministic: repeat and leading-slash forms resolve identically.
	if again := asset("js/app.js"); again != app {
		t.Errorf("second call = %q, want stable %q", again, app)
	}
	if withSlash := asset("/js/app.js"); withSlash != app {
		t.Errorf("leading-slash call = %q, want %q", withSlash, app)
	}

	// Different bytes ⇒ different hash.
	if css := asset("css/site.css"); css == app || !strings.Contains(css, "?v=") {
		t.Errorf("css url = %q, want a distinct versioned url", css)
	}

	// A missing file degrades to the unversioned URL rather than failing the render.
	if miss := asset("js/nope.js"); miss != "/static/js/nope.js" {
		t.Errorf("missing-file url = %q, want unversioned /static/js/nope.js", miss)
	}
}
