package tests

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/tools/linktools"
)

const safeLinks = "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.example.com%2Farticle%3Fid%3D42%26utm_source%3Dnewsletter&data=05%7C02&reserved=0"

func newsletter(n int) string {
	var b strings.Builder
	b.WriteString("<html><body><p>Hi there,</p>")
	for i := range n {
		fmt.Fprintf(&b, `<p><a href="https://u1234567.ct.sendgrid.net/ls/click?upn=%s-%03d&utm_source=newsletter&utm_medium=email&utm_campaign=october">Story %d: what we shipped this week</a></p>`,
			strings.Repeat("u001.Gp2Xz7Q-2BqHk", 8), i, i)
	}
	for range 3 {
		b.WriteString(`<a href="https://example.com/unsubscribe?u=abc123">Unsubscribe</a> <a href="https://example.com/view?id=42">View in browser</a>`)
	}
	b.WriteString("</body></html>")
	return b.String()
}

func extractConcise(body map[string]any) {
	urls := body["urls"].([]any)
	for _, u := range urls {
		delete(u.(map[string]any), "positions")
	}
	if len(urls) > 30 {
		body["urls"] = urls[:30]
		notes, _ := body["notes"].([]any)
		body["notes"] = append(notes, map[string]any{"severity": "info",
			"title": fmt.Sprintf("The first 30 of %d links", len(urls)), "detail": "Pass detailed: true for all of them, with their positions in the text."})
	}
}

// Only full has a REST twin.
func TestLinkTrackingRulesAnswerOneQuestion(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/link", nil)
	cat := linktools.Rules()
	const u = "https://github.com/x?ref=main&utm_source=a"
	verdict, err := cat.Verdict(u)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args map[string]any
		want any
	}{
		{map[string]any{}, cat.Summary()},
		{map[string]any{"param": "REF"}, cat.Matches("REF")},
		{map[string]any{"url": u}, verdict},
	} {
		if diff := cmp.Diff(asJSON(t, tc.want), asJSON(t, object(t, call(t, cs, "link_tracking_rules", tc.args)))); diff != "" {
			t.Errorf("%v (-want +got):\n%s", tc.args, diff)
		}
	}
	failsWith(t, call(t, cs, "link_tracking_rules", map[string]any{"param": "ref", "url": u}), "at most one")
}

// Unlike REST's form, where an empty field is no change.
func TestLinkUTMAbsentKeepsEmptyRemoves(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/link", nil)
	const tagged = "https://example.com/landing?utm_source=old&utm_medium=email&id=1"
	for _, tc := range []struct {
		args map[string]any
		url  string
	}{
		{map[string]any{"url": tagged}, tagged},
		{map[string]any{"url": tagged, "utm_source": ""}, "https://example.com/landing?utm_medium=email&id=1"},
	} {
		if got := object(t, call(t, cs, "link_utm", tc.args)); got["url"] != tc.url {
			t.Errorf("utm %v = %v, want %s", tc.args, got["url"], tc.url)
		}
	}
}
