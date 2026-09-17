package dnstools

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/miekg/dns"
)

// The five decoders are pure, deterministic and network-free, so everything
// here is a table over records built from presentation format. Cases marked
// with a finding assert the behaviour the review asks for rather than the
// behaviour shipped today, and fail until that finding is fixed.

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return rr
}

func TestCAAFields(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		rr   string
		want []Field
	}{
		{
			name: "issue names the CA that may issue",
			rr:   `example.com. 300 IN CAA 0 issue "letsencrypt.org"`,
			want: []Field{{"May issue certificates", "letsencrypt.org"}},
		},
		{
			name: "issuewild is its own permission",
			rr:   `example.com. 300 IN CAA 0 issuewild "digicert.com"`,
			want: []Field{{"May issue wildcards", "digicert.com"}},
		},
		{
			name: "iodef is where violations go",
			rr:   `example.com. 300 IN CAA 0 iodef "mailto:security@example.com"`,
			want: []Field{{"Report violations to", "mailto:security@example.com"}},
		},
		{
			// The critical flag means a CA that doesn't understand the tag
			// must refuse to issue at all, so it has to be visible.
			name: "the critical flag is surfaced",
			rr:   `example.com. 300 IN CAA 128 issue "letsencrypt.org"`,
			want: []Field{{"May issue certificates", "letsencrypt.org"}, {"Flag", "128 (critical)"}},
		},
		{
			name: "an unknown tag falls back to the tag itself",
			rr:   `example.com. 300 IN CAA 0 futuretag "whatever"`,
			want: []Field{{"futuretag", "whatever"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := caaFields(mustRR(t, tc.rr).(*dns.CAA))
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("caaFields differs (-want +got):\n%s", diff)
			}
		})
	}
}

// RFC 8659 §4.2/§4.3: an empty issuer-domain-name authorises nobody, and `;`
// is how that is written. Rendering it as a permission states the exact
// opposite of what the zone published.
//
// Pins caa-issue-semicolon-inverted; expected red until it is fixed.
func TestCAAEmptyIssuerForbidsIssuance(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, rr string
	}{
		{"semicolon issuewild forbids every CA", `example.com. 300 IN CAA 0 issuewild ";"`},
		{"empty issue value forbids every CA", `example.com. 300 IN CAA 0 issue ""`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := caaFields(mustRR(t, tc.rr).(*dns.CAA))
			for _, f := range got {
				if strings.HasPrefix(f.Name, "May issue") {
					t.Errorf("rendered %q: %q as a permission; this record authorises nobody", f.Name, f.Value)
				}
			}
			if !strings.Contains(strings.ToLower(fieldText(got)), "no ca may issue") {
				t.Errorf("fields %v do not say that no CA may issue", got)
			}
		})
	}
}

func fieldText(f []Field) string {
	var b strings.Builder
	for _, x := range f {
		b.WriteString(x.Name + ": " + x.Value + "; ")
	}
	return b.String()
}

func TestSVCBFields(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		rr   string
		want []Field
	}{
		{
			// Priority 0 is AliasMode: the modern way to do a CNAME at the apex.
			name: "alias mode names the target it points at",
			rr:   `example.com. 300 IN HTTPS 0 svc.example.net.`,
			want: []Field{{"Mode", "alias, pointing at svc.example.net"}},
		},
		{
			name: "service mode decodes its parameters in order",
			rr:   `example.com. 300 IN HTTPS 1 cdn.example.net. alpn="h3,h2" port=8443 ipv4hint=192.0.2.1`,
			want: []Field{
				{"Priority", "1"},
				{"Endpoint", "cdn.example.net"},
				{"Protocols", "HTTP/3, HTTP/2"},
				{"Port", "8443"},
				{"IPv4 hint", "192.0.2.1"},
			},
		},
		{
			name: "an unknown ALPN token is shown as published",
			rr:   `example.com. 300 IN HTTPS 1 . alpn="h4"`,
			want: []Field{{"Priority", "1"}, {"Protocols", "h4"}},
		},
		{
			name: "no-default-alpn is stated rather than rendered blank",
			rr:   `example.com. 300 IN HTTPS 1 . no-default-alpn`,
			want: []Field{{"Priority", "1"}, {"Default ALPN", "disabled"}},
		},
		{
			name: "SVCB decodes the same way as HTTPS",
			rr:   `_dns.example.com. 300 IN SVCB 1 dot.example.net. alpn="dot"`,
			want: []Field{{"Priority", "1"}, {"Endpoint", "dot.example.net"}, {"Protocols", "DNS-over-TLS"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(tc.want, svcbFields(mustRR(t, tc.rr))); diff != "" {
				t.Errorf("svcbFields differs (-want +got):\n%s", diff)
			}
		})
	}
}

// The ECH parameter's presentation form is base64, not hex, so a byte count
// taken from the string length is wrong by a third — and an empty parameter
// publishes no keys at all, so it must not claim the SNI is encrypted.
//
// Pins ech-byte-count-wrong; expected red until it is fixed.
func TestECHByteCount(t *testing.T) {
	t.Parallel()

	raw := []byte{0xfe, 0x0d, 0x00, 0x41, 0x01, 0x02, 0x03, 0x04}
	rr := mustRR(t, `example.com. 300 IN HTTPS 1 . ech="`+base64.StdEncoding.EncodeToString(raw)+`"`)

	var ech string
	for _, f := range svcbFields(rr) {
		if f.Name == "ECH" {
			ech = f.Value
		}
	}
	if ech == "" {
		t.Fatal("a record publishing ech= produced no ECH field")
	}
	if !strings.Contains(ech, "8 bytes") {
		t.Errorf("ECH field = %q, want the %d decoded bytes the record actually carries", ech, len(raw))
	}

	// An empty ech= asserts a privacy property the record does not provide.
	empty := mustRR(t, `example.com. 300 IN HTTPS 1 . ech=""`)
	for _, f := range svcbFields(empty) {
		if f.Name != "ECH" {
			continue
		}
		if strings.Contains(f.Value, "encrypted") {
			t.Errorf("empty ech= renders %q, but no keys are published", f.Value)
		}
	}
}

func TestSOAFields(t *testing.T) {
	t.Parallel()

	got := soaFields(mustRR(t,
		`example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 900`).(*dns.SOA))
	want := []Field{
		{"Primary NS", "ns1.example.com."},
		{"Hostmaster", "hostmaster@example.com"},
		{"Serial", "2024010101"},
		{"Refresh", "2h"},
		{"Retry", "1h"},
		{"Expire", "14d"},
		{"Negative TTL", "15m"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("soaFields differs (-want +got):\n%s", diff)
	}
}

// A dot inside the local part is escaped on the wire, so splitting on the
// first literal dot produces an address nobody can write to.
//
// Pins the mboxEmail escaping finding; expected red until it is fixed.
func TestMboxEmailHonoursEscaping(t *testing.T) {
	t.Parallel()

	soa := mustRR(t,
		`example.com. 300 IN SOA ns1.example.com. first\.last.example.com. 1 7200 3600 1209600 900`).(*dns.SOA)
	if got, want := mboxEmail(soa.Mbox), "first.last@example.com"; got != want {
		t.Errorf("mboxEmail(%q) = %q, want %q", soa.Mbox, got, want)
	}
}

func TestTXTLabel(t *testing.T) {
	t.Parallel()

	cases := []struct{ value, want string }{
		{"v=spf1 include:_spf.example.com ~all", "SPF — which servers may send mail"},
		{`"v=DMARC1; p=reject"`, "DMARC — what to do with failing mail"},
		// Publishers are inconsistent about the marker's case.
		{"v=dmarc1; p=none", "DMARC — what to do with failing mail"},
		{"v=STSv1; id=20260101", "MTA-STS — enforced mail transport security"},
		{"google-site-verification=abc123", "Google — site ownership"},
		{"MS=ms12345678", "Microsoft — domain ownership"},
		// Unknown vendor, recognisable shape: say what it is, not who it is.
		{"acme-verification=xyz", "Domain ownership proof"},
		{"some free-form note", ""},
		{"", ""},
	}

	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			t.Parallel()
			if got := txtLabel(tc.value); got != tc.want {
				t.Errorf("txtLabel(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestProviderOf(t *testing.T) {
	t.Parallel()

	ns := func(hosts ...string) []Record {
		out := []Record{{Type: "A", Value: "192.0.2.1"}}
		for _, h := range hosts {
			out = append(out, Record{Type: "NS", Value: h})
		}
		return out
	}

	cases := []struct {
		name    string
		records []Record
		want    string
	}{
		{"cloudflare", ns("ada.ns.cloudflare.com.", "bob.ns.cloudflare.com."), "Cloudflare"},
		{"route 53 across TLDs", ns("ns-1707.awsdns-21.co.uk.", "ns-520.awsdns-01.net."), "AWS Route 53"},
		{"case is not the publisher's problem", ns("NS1.DIGITALOCEAN.COM."), "DigitalOcean"},
		// Better blank than a wrong guess.
		{"an unknown suffix names nobody", ns("ns1.some-host.example."), ""},
		{"no NS records at all", []Record{{Type: "A", Value: "192.0.2.1"}}, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := providerOf(tc.records); got != tc.want {
				t.Errorf("providerOf = %q, want %q", got, tc.want)
			}
		})
	}
}

// The question this answers is "who do I log into to change this", so a zone
// whose nameservers are mostly one operator's must name that operator, not
// whichever record happened to be first.
//
// Pins the providerOf first-match finding (netlifydns.com is missing from the
// table entirely); expected red until it is fixed.
func TestProviderOfNamesTheMajorityOperator(t *testing.T) {
	t.Parallel()

	records := []Record{
		{Type: "NS", Value: "dns1.p05.nsone.net."},
		{Type: "NS", Value: "dns1.netlifydns.com."},
		{Type: "NS", Value: "dns2.netlifydns.com."},
		{Type: "NS", Value: "dns3.netlifydns.com."},
	}
	if got := providerOf(records); got != "Netlify" {
		t.Errorf("providerOf = %q for a zone with three Netlify nameservers and one NS1 one, want Netlify", got)
	}
}
