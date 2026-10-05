package tests

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
)

var creditIDs = []string{platform.CreditIP2Location, platform.CreditSpamhaus, platform.CreditShodan, platform.CreditCrtSh, platform.CreditRDAP}

func TestCreditFor(t *testing.T) {
	for _, id := range creditIDs {
		c, ok := platform.CreditFor(id)
		if !ok || c.ID != id || c.Source == "" || !strings.HasPrefix(c.URL, "https://") {
			t.Errorf("CreditFor(%q) = %+v, %v", id, c, ok)
		}
		if !strings.Contains(c.Notice, c.LinkText) || c.LinkText == "" {
			t.Errorf("%s: link text %q is not part of the notice %q", id, c.LinkText, c.Notice)
		}
	}
	if _, ok := platform.CreditFor("nope"); ok {
		t.Error("an unknown ID resolved")
	}

	c, _ := platform.CreditFor(platform.CreditShodan)
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"source":"Shodan InternetDB","notice":"corpberry.com uses © Shodan's InternetDB for open-port data.","url":"https://internetdb.shodan.io"}`
	if string(b) != want {
		t.Errorf("json = %s, want %s", b, want)
	}
}

// The footer and a page-less result must say the same words.
func TestFooterPrintsEachNotice(t *testing.T) {
	r := platform.NewRenderer(false, nil, platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"})
	data := map[string]any{}
	for _, f := range footerFlags {
		data[f] = true
	}
	var buf bytes.Buffer
	if err := r.Render(nil, &buf, "partials/footer", data); err != nil {
		t.Fatal(err)
	}
	text := strings.Join(strings.Fields(regexp.MustCompile(`<[^>]*>`).ReplaceAllString(buf.String(), "")), " ")
	for _, id := range creditIDs {
		c, _ := platform.CreditFor(id)
		if !strings.Contains(text, c.Notice) {
			t.Errorf("footer does not print %s's notice %q:\n%s", id, c.Notice, text)
		}
		if !strings.Contains(buf.String(), `<a href="`+c.URL+`"`) {
			t.Errorf("footer does not link %s to %s", id, c.URL)
		}
	}
}

func TestUnknownCreditFailsTheRender(t *testing.T) {
	src := fstest.MapFS{"templates/x.html": {Data: []byte(`{{define "x"}}{{with credit .}}{{.URL}}{{end}}{{end}}`)}}
	r := platform.NewRenderer(false, nil, platform.TemplateSource{Embed: src})
	var buf bytes.Buffer
	if err := r.Render(nil, &buf, "x", platform.CreditRDAP); err != nil || buf.String() != "https://rdap.org" {
		t.Errorf("known ID rendered %q, %v", buf.String(), err)
	}
	if err := r.Render(nil, &bytes.Buffer{}, "x", "nope"); err == nil {
		t.Error("a misspelt credit ID rendered without error")
	}
}
