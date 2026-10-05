package tests

import (
	"encoding/json"
	"io"
	"testing"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/platform/goldentest"
	"github.com/Landver/site-of-tools/shared"
)

func TestCreditJSONOmitsFooterFields(t *testing.T) {
	c, _ := platform.CreditFor(platform.CreditShodan)
	b, err := json.Marshal(c)
	want := `{"source":"Shodan InternetDB","notice":"corpberry.com uses © Shodan's InternetDB for open-port data.","url":"https://internetdb.shodan.io"}`
	if err != nil || string(b) != want {
		t.Errorf("json = %s, %v; want %s", b, err, want)
	}
}

func TestFooterGolden(t *testing.T) {
	got := map[string]string{"none": renderPartial(t, "partials/footer", nil)}
	for _, id := range []string{platform.CreditIP2Location, platform.CreditSpamhaus, platform.CreditShodan, platform.CreditCrtSh, platform.CreditRDAP} {
		c, _ := platform.CreditFor(id)
		got[c.Flag] = renderPartial(t, "partials/footer", map[string]any{c.Flag: true})
	}
	goldentest.JSON(t, "footer", got)
}

func TestUnknownCreditFailsTheRender(t *testing.T) {
	r := platform.NewRenderer(false, nil, platform.TemplateSource{Embed: shared.Templates})
	if err := r.Render(nil, io.Discard, "partials/credit", "nope"); err == nil {
		t.Error("a misspelt credit ID rendered without error")
	}
}
