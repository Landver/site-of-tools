package tests

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/dnstools"
)

// Pasted shapes come out as the name meant, or unchanged for validDomain.
func TestNormalizeName(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ in, want string }{
		{"example.com", "example.com"},
		{"  example.com  ", "example.com"},
		{"EXAMPLE.COM.", "example.com"},
		{"https://example.com/pricing?plan=pro#top", "example.com"},
		{"HTTP://Example.COM", "example.com"},
		{"https://user:secret@www.example.com:8443/x", "www.example.com"},
		{"example.com/pricing", "example.com"},
		{"example.com:443", "example.com"},
		{"alice@example.com", "example.com"},
		{"mailto:alice@example.com?subject=hi", "example.com"},
		{"_dmarc.example.com", "_dmarc.example.com"},
		// IDN, label by label.
		{"bücher.de", "xn--bcher-kva.de"},
		{"BÜCHER.de", "xn--bcher-kva.de"},
		{"https://bücher.de/", "xn--bcher-kva.de"},
		{"_dmarc.bücher.de", "_dmarc.xn--bcher-kva.de"},
		{"例え。テスト", "xn--r8jz45g.xn--zckzah"},
		// IP literals stay literals.
		{"8.8.8.8", "8.8.8.8"},
		{"2001:db8::1", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"[2001:db8::1]:53", "2001:db8::1"},
		{"http://[2001:db8::1]:8080/", "2001:db8::1"},
		// Not names, left for validDomain.
		{"not a domain", "not a domain"},
		{"alice@", "alice@"},
		{"", ""},
	} {
		if got := dnstools.NormalizeName(tc.in); got != tc.want {
			t.Errorf("NormalizeName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUnicodeName(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ in, want string }{
		{"xn--bcher-kva.de", "bücher.de"},
		{"_dmarc.xn--bcher-kva.de", "_dmarc.bücher.de"},
		{"example.com", ""},
		{"", ""},
	} {
		if got := dnstools.UnicodeName(tc.in); got != tc.want {
			t.Errorf("UnicodeName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Handlers pass the service the cleaned name.
func TestHandlerNormalizesPastedInput(t *testing.T) {
	t.Parallel()
	f := &fakeLooker{set: sampleSet()}
	e := newApp(t, f, nil)

	rec := do(t, e, "/?name="+url.QueryEscape("https://Example.com/pricing?x=1"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body)
	}
	if f.lastName != "example.com" {
		t.Errorf("service was asked %q, want the URL's host", f.lastName)
	}
}

// An IP on /domain is refused before RDAP is asked.
func TestDomainRefusesAnIP(t *testing.T) {
	t.Parallel()
	e := newApp(t, &fakeLooker{set: sampleSet()}, nil)

	rec := do(t, e, "/domain?name=1.1.1.1", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), dnstools.ErrNeedDomain.Error()) {
		t.Errorf("body = %s, want the needs-a-domain error", rec.Body)
	}
}

// A subdomain's registry record is its registrable domain's.
func TestRegistrableDomain(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ in, want string }{
		{"www.github.com", "github.com"},
		{"github.com", "github.com"},
		{"a.b.example.co.uk", "example.co.uk"},
		{"co.uk", "co.uk"}, // a public suffix itself: left alone
	} {
		if got := dnstools.RegistrableDomain(tc.in); got != tc.want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
