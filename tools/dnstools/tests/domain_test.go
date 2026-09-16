package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/tools/dnstools"
)

// The RDAP and Certificate Transparency layer is pure decoding over fixed
// JSON, so it is tested against canned upstreams rather than rdap.org and
// crt.sh: no network, no rate limit, and the awkward shapes (jCard, multi-SAN
// rows, a 404) can be asked for on purpose.

// upstream records what the client asked for, so a test can assert the request
// as well as the answer.
type upstream struct {
	mu       sync.Mutex
	rdapPath string
	ctQuery  string
}

// canned serves one RDAP body and one crt.sh body, with the status codes to
// answer them with.
func canned(t *testing.T, rdap string, rdapCode int, ct string, ctCode int) (*dnstools.DomainClient, *upstream) {
	t.Helper()
	u := &upstream{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		u.mu.Lock()
		if strings.HasPrefix(r.URL.Path, "/domain/") {
			u.rdapPath = r.URL.RequestURI()
			u.mu.Unlock()
			w.WriteHeader(rdapCode)
			fmt.Fprint(w, rdap)
			return
		}
		u.ctQuery = r.URL.Query().Get("q")
		u.mu.Unlock()
		w.WriteHeader(ctCode)
		fmt.Fprint(w, ct)
	}))
	t.Cleanup(srv.Close)
	return dnstools.NewDomainClient(srv.URL, srv.URL, 5*time.Second), u
}

func rdapBody(expires time.Time) string {
	return `{
	  "objectClassName": "domain",
	  "ldhName": "example.com",
	  "status": ["client transfer prohibited", "ok"],
	  "events": [
	    {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
	    {"eventAction": "expiration", "eventDate": "` + expires.Format(time.RFC3339) + `"},
	    {"eventAction": "last changed", "eventDate": "2025-03-02T10:00:00Z"}
	  ],
	  "entities": [
	    {"roles": ["technical"], "vcardArray": ["vcard", [["fn", {}, "text", "Not The Registrar"]]]},
	    {"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar, Inc."]]]}
	  ],
	  "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}, {"ldhName": "ns2.example.com"}],
	  "secureDNS": {"delegationSigned": true}
	}`
}

func TestRegistrationDecodesTheRegistryRecord(t *testing.T) {
	t.Parallel()

	// Half a day past the 30-day mark, so the day count cannot hinge on how
	// long the test itself took.
	expires := time.Now().Add(30*24*time.Hour + 12*time.Hour).UTC()
	dc, _ := canned(t, rdapBody(expires), http.StatusOK, "[]", http.StatusOK)

	reg, err := dc.Registration(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Registration: %v", err)
	}
	if got, want := reg.Registrar, "Example Registrar, Inc."; got != want {
		t.Errorf("registrar = %q, want %q (the registrar-role entity's jCard fn)", got, want)
	}
	if got, want := reg.Registered, "1995-08-14"; got != want {
		t.Errorf("registered = %q, want %q", got, want)
	}
	if got, want := reg.Expires, expires.Format("2006-01-02"); got != want {
		t.Errorf("expires = %q, want %q", got, want)
	}
	if got, want := reg.Updated, "2025-03-02"; got != want {
		t.Errorf("updated = %q, want %q", got, want)
	}
	// DaysLeft is a pointer so "no expiry we could read" is not the same
	// answer as "expires today"; templates read it through these two.
	if !reg.DaysKnown() {
		t.Error("the registry published an expiry, but days left came back unknown")
	} else if reg.Days() != 30 {
		t.Errorf("days left = %d, want 30", reg.Days())
	}
	if !reg.SignedDelegation {
		t.Error("the registry says a DS record is published; SignedDelegation is false")
	}
	// Registry nameservers are compared against the zone's, so they arrive in
	// one case.
	if diff := cmp.Diff([]string{"ns1.example.com", "ns2.example.com"}, reg.Nameservers); diff != "" {
		t.Errorf("nameservers differ (-want +got):\n%s", diff)
	}
	// The EPP codes are the reason "why can't I transfer this" has an answer,
	// and raw they are unreadable.
	if len(reg.Statuses) != 2 {
		t.Fatalf("got %d statuses, want 2", len(reg.Statuses))
	}
	if reg.Statuses[0].Code != "client transfer prohibited" || reg.Statuses[0].Meaning == "" {
		t.Errorf("status %+v carries no plain-language meaning", reg.Statuses[0])
	}
}

func TestDomainClientDisabled(t *testing.T) {
	t.Parallel()

	if dc := dnstools.NewDomainClient("", "", time.Second); dc != nil {
		t.Errorf("both URLs blank should disable the client, got %+v", dc)
	}
	var nilClient *dnstools.DomainClient
	if _, err := nilClient.Registration(context.Background(), "example.com"); err == nil {
		t.Error("a disabled client should report that it is disabled, not answer")
	}
	if _, err := nilClient.CertNames(context.Background(), "example.com"); err == nil {
		t.Error("a disabled client should report that it is disabled, not answer")
	}
}

// RFC 7480 §5.3: a 404 is the registry saying "no such object". Reporting it
// as a failed lookup tells the user the opposite of what the registry said, on
// the most common question this page is asked.
//
// Pins rdap-404-denied; expected red until it is fixed.
func TestRegistrationNoRecordIsNotALookupFailure(t *testing.T) {
	t.Parallel()

	dc, _ := canned(t, `{"errorCode": 404}`, http.StatusNotFound, "[]", http.StatusOK)

	_, err := dc.Registration(context.Background(), "definitely-not-registered.example")
	if err == nil {
		t.Fatal("a 404 should still be an error, just a different one")
	}
	if strings.Contains(err.Error(), "upstream returned") {
		t.Errorf("404 surfaced as %q: the registry answered, it just has no record for the name", err)
	}
}

// A name carrying URL syntax must never come back labelled with one domain's
// string and another domain's record. Either the name is refused, or it
// reaches the registry whole.
//
// Pins the RDAP path-escaping half of the no-name-validation finding; expected
// red until it is fixed.
func TestRegistrationDoesNotMisattributeAnotherDomainsRecord(t *testing.T) {
	t.Parallel()

	dc, up := canned(t, rdapBody(time.Now().Add(365*24*time.Hour)), http.StatusOK, "[]", http.StatusOK)

	const name = "example.com?foo=bar"
	if _, err := dc.Registration(context.Background(), name); err != nil {
		return // refused up front, which is the other acceptable answer
	}
	up.mu.Lock()
	path := up.rdapPath
	up.mu.Unlock()
	if strings.Contains(path, "?") || !strings.Contains(path, "%3F") {
		t.Errorf("asked the registry for %q: the ? became query syntax, so another name's record is labelled %q", path, name)
	}
}

func TestCertNamesRollsUpPerName(t *testing.T) {
	t.Parallel()

	rows := `[
	  {"name_value": "www.example.com\nexample.com", "not_before": "2026-01-01T00:00:00", "not_after": "2026-04-01T00:00:00", "serial_number": "0a"},
	  {"name_value": "example.com", "not_before": "2025-11-01T00:00:00", "not_after": "2026-02-01T00:00:00", "serial_number": "0b"},
	  {"name_value": "*.example.com", "not_before": "2025-06-01T00:00:00", "not_after": "2026-06-01T00:00:00", "serial_number": "0c"}
	]`
	dc, up := canned(t, "{}", http.StatusOK, rows, http.StatusOK)

	ct, err := dc.CertNames(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("CertNames: %v", err)
	}
	// CT publishes per-certificate rows; the view people want is per-name.
	if got, want := ct.Total, 2; got != want {
		t.Errorf("total = %d, want %d distinct names", got, want)
	}
	if !ct.Wildcard {
		t.Error("a wildcard certificate covers this domain and must be declared: names under it never appear in CT")
	}
	byName := map[string]dnstools.Subdomain{}
	for _, n := range ct.Names {
		byName[n.Name] = n
	}
	apex, ok := byName["example.com"]
	if !ok {
		t.Fatalf("example.com missing from %v", ct.Names)
	}
	if apex.Certs != 2 {
		t.Errorf("example.com certs = %d, want 2", apex.Certs)
	}
	// FirstSeen is the earliest NotBefore; LastSeen is how long the name stays
	// covered, i.e. the latest NotAfter.
	if apex.FirstSeen != "2025-11-01" || apex.LastSeen != "2026-04-01" {
		t.Errorf("example.com seen %s..%s, want 2025-11-01..2026-04-01", apex.FirstSeen, apex.LastSeen)
	}
	// The wildcard row contributes the flag, not a literal "*." name.
	if _, ok := byName["*.example.com"]; ok {
		t.Error("the wildcard itself was listed as a subdomain")
	}
	up.mu.Lock()
	q := up.ctQuery
	up.mu.Unlock()
	if q != "%.example.com" {
		t.Errorf("crt.sh query = %q, want %q", q, "%.example.com")
	}
}

// A multi-SAN certificate can mention names in other registrable domains. They
// are somebody else's names, and listing them under "subdomains seen in
// certificate transparency" is a false claim about this domain.
//
// Pins the CT off-domain-SAN finding; expected red until it is fixed.
func TestCertNamesExcludesOffDomainSANs(t *testing.T) {
	t.Parallel()

	rows := `[{"name_value": "example.com\nshop.example.com\nexample.com.bh\nnotexample.com", "not_before": "2026-01-01T00:00:00", "not_after": "2026-04-01T00:00:00", "serial_number": "0a"}]`
	dc, _ := canned(t, "{}", http.StatusOK, rows, http.StatusOK)

	ct, err := dc.CertNames(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("CertNames: %v", err)
	}
	for _, n := range ct.Names {
		if n.Name != "example.com" && !strings.HasSuffix(n.Name, ".example.com") {
			t.Errorf("%q is not under example.com but is listed as one of its names", n.Name)
		}
	}
}

// crt.sh returns a row per logged certificate, and a precertificate and its
// final certificate share a serial. Counting rows reports twice the
// certificates that exist.
//
// Pins the CT row-counting finding; expected red until it is fixed.
func TestCertNamesCountsCertificatesNotRows(t *testing.T) {
	t.Parallel()

	rows := `[
	  {"name_value": "api.example.com", "not_before": "2026-01-01T00:00:00", "not_after": "2026-04-01T00:00:00", "serial_number": "04e1"},
	  {"name_value": "api.example.com", "not_before": "2026-01-01T00:00:00", "not_after": "2026-04-01T00:00:00", "serial_number": "04e1"}
	]`
	dc, _ := canned(t, "{}", http.StatusOK, rows, http.StatusOK)

	ct, err := dc.CertNames(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("CertNames: %v", err)
	}
	if len(ct.Names) != 1 {
		t.Fatalf("got %d names, want 1", len(ct.Names))
	}
	if ct.Names[0].Certs != 1 {
		t.Errorf("certs = %d for a precertificate and its final certificate (one serial), want 1", ct.Names[0].Certs)
	}
}

// Over the display cap the list says so rather than silently ending.
func TestCertNamesTruncationIsDeclared(t *testing.T) {
	t.Parallel()

	type row struct {
		NameValue string `json:"name_value"`
		NotBefore string `json:"not_before"`
		NotAfter  string `json:"not_after"`
	}
	var rows []row
	const total = 205
	for i := range total {
		rows = append(rows, row{
			NameValue: fmt.Sprintf("host%03d.example.com", i),
			NotBefore: "2026-01-01T00:00:00",
			NotAfter:  "2026-04-01T00:00:00",
		})
	}
	body, err := json.Marshal(rows)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	dc, _ := canned(t, "{}", http.StatusOK, string(body), http.StatusOK)

	ct, err := dc.CertNames(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("CertNames: %v", err)
	}
	if ct.Total != total {
		t.Errorf("total = %d, want %d: the count is of what CT knows, not of what we render", ct.Total, total)
	}
	if !ct.Truncated {
		t.Errorf("rendered %d of %d names without saying the list was cut", len(ct.Names), ct.Total)
	}
	if len(ct.Names) > ct.Total {
		t.Errorf("rendered %d names out of %d", len(ct.Names), ct.Total)
	}
}

// A `+` in a query string decodes back to a space, so a name carrying one is
// asked about as a different name. Either the name is refused, or it reaches
// the log whole.
//
// Pins the urlEscape finding; expected red until it is fixed.
func TestCertNamesQueryEscapesPlus(t *testing.T) {
	t.Parallel()

	dc, up := canned(t, "{}", http.StatusOK, "[]", http.StatusOK)

	const name = "foo+bar.example.com"
	if _, err := dc.CertNames(context.Background(), name); err != nil {
		return // refused up front, which is the other acceptable answer
	}
	up.mu.Lock()
	q := up.ctQuery
	up.mu.Unlock()
	if q != "%."+name {
		t.Errorf("crt.sh query = %q, want %q: the + was decoded as a space", q, "%."+name)
	}
}

// An upstream that is down must not look like an answer.
func TestCertNamesUpstreamFailure(t *testing.T) {
	t.Parallel()

	dc, _ := canned(t, "{}", http.StatusOK, "502 Bad Gateway", http.StatusBadGateway)
	if _, err := dc.CertNames(context.Background(), "example.com"); err == nil {
		t.Error("a 502 from the certificate log should be reported, not swallowed")
	}
}
