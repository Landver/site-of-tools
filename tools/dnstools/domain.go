package dnstools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// ErrDisabled: this half of the client has no URL configured, so there is
// nothing to ask. Named rather than free-form so the transport layer can say
// "not available right now" instead of printing the word "disabled" at a
// visitor who never configured anything.
var ErrDisabled = errors.New("this lookup is switched off")

// errUpstreamNotFound: the upstream answered 404. Kept apart from a transport
// failure because for RDAP a 404 is an answer, not a breakdown.
var errUpstreamNotFound = errors.New("upstream has no record")

// errNoRDAPRecord: the registry answered, and what it said is that it holds no
// object for this name (RFC 7480 §5.3). Surfacing that as a failed lookup
// tells the reader the opposite of what the registry said, on the question
// this page is asked most.
var errNoRDAPRecord = errors.New("the registry has no record for this name: it is unregistered, or its TLD publishes no RDAP service")

// Registration and subdomain discovery: the two questions about a domain that
// DNS itself cannot answer.
//
// Both ride the same pattern as tools/iptools/shodan.go — dedicated client with
// an explicit timeout, a self-identifying User-Agent so an upstream can contact
// us rather than silently block us, nil receiver means disabled, and a failure
// is best-effort: it never breaks the page it decorates.

const domainUserAgent = "corpberry-dnstools/1.0 (+https://dns.corpberry.com; contact via github.com/Landver/site-of-tools)"

// Registration: what the registry knows, via RDAP — the sanctioned WHOIS
// replacement, keyless JSON over HTTPS (reports/whois-rdap-tools.md).
type Registration struct {
	Domain     string `json:"domain"`
	Registrar  string `json:"registrar,omitempty"`
	Registered string `json:"registered,omitempty"`
	Expires    string `json:"expires,omitempty"`
	Updated    string `json:"updated,omitempty"`
	// DaysLeft: nil when the registry published no expiry, or one we could not
	// parse. Zero means "expires within the day" and a negative value means
	// already expired, which a plain int cannot tell apart from "unknown".
	DaysLeft    *int     `json:"days_left,omitempty"`
	Statuses    []Status `json:"statuses,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
	// SignedDelegation: the registry says a DS record is published, i.e. DNSSEC
	// is delegated. A free DNSSEC fact with zero DNS queries.
	SignedDelegation bool `json:"signed_delegation"`
}

// Status: an EPP status code plus what it means in plain language. The codes
// are the reason "why can't I transfer this domain" has an answer, and raw
// they are unreadable.
type Status struct {
	Code    string `json:"code"`
	Meaning string `json:"meaning"`
}

// eppMeanings decodes the EPP status codes a registry reports. Static data.
var eppMeanings = map[string]string{
	"client transfer prohibited": "Locked by your registrar against transfers. Normal, and the usual anti-hijacking default.",
	"server transfer prohibited": "Locked by the registry against transfers.",
	"client delete prohibited":   "Your registrar is blocking deletion.",
	"server delete prohibited":   "The registry is blocking deletion.",
	"client update prohibited":   "Your registrar is blocking changes to the record.",
	"server update prohibited":   "The registry is blocking changes to the record.",
	"client renew prohibited":    "Your registrar is blocking renewal.",
	"client hold":                "Your registrar has pulled this domain from DNS. It will not resolve.",
	"server hold":                "The registry has pulled this domain from DNS. It will not resolve.",
	"pending transfer":           "A transfer to another registrar is in progress.",
	"pending delete":             "Scheduled for deletion.",
	"redemption period":          "Expired and in the grace window. Recoverable, usually for a fee.",
	"auto renew period":          "Recently auto-renewed; still inside the refund window.",
	"add period":                 "Registered very recently; inside the initial grace window.",
	"ok":                         "No restrictions. Note that this also means no transfer lock.",
	"active":                     "No restrictions.",
	"inactive":                   "No nameservers delegated, so nothing under this domain resolves.",
}

// Subdomain: one name seen in Certificate Transparency, rolled up across every
// certificate that mentioned it. CT publishes per-certificate rows; the view
// people actually want is per-name, which nothing in the corpus renders.
type Subdomain struct {
	Name      string `json:"name"`
	FirstSeen string `json:"first_seen,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
	Certs     int    `json:"certs"`
}

// CertNames: what Certificate Transparency knows about a domain. This is the
// working replacement for a zone transfer: public, complete for anything TLS,
// and it sends zero packets at the target.
type CertNames struct {
	Names []Subdomain `json:"names"`
	Total int         `json:"total"`
	// Truncated: more names existed than we show. Said out loud rather than
	// silently capped.
	Truncated bool `json:"truncated,omitempty"`
	// Wildcard: a wildcard certificate covers this domain, which is CT's blind
	// spot — names issued under it never appear here. Stating the limit is the
	// difference between a list and a claim.
	Wildcard bool `json:"wildcard,omitempty"`
}

// maxSubdomains bounds what we render. CT can return thousands of rows.
const maxSubdomains = 200

// maxResponseBytes bounds what we read from either upstream.
const maxResponseBytes = 8 << 20

// DomainClient talks to RDAP and Certificate Transparency. nil disables both.
type DomainClient struct {
	client  *http.Client
	rdapURL string
	ctURL   string
}

// NewDomainClient builds the client. Blank URLs disable that half.
func NewDomainClient(rdapURL, ctURL string, timeout time.Duration) *DomainClient {
	if rdapURL == "" && ctURL == "" {
		return nil
	}
	return &DomainClient{
		client:  &http.Client{Timeout: timeout},
		rdapURL: strings.TrimSuffix(rdapURL, "/"),
		ctURL:   strings.TrimSuffix(ctURL, "/"),
	}
}

func (d *DomainClient) get(ctx context.Context, endpoint string, into any) error {
	if d == nil {
		return ErrDisabled
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", domainUserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errUpstreamNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upstream returned %d", resp.StatusCode)
	}
	// Bounded: a CT response for a large domain can be many megabytes, and an
	// unbounded decode is a memory risk on a public endpoint. Reading one byte
	// past the cap is what tells our own truncation from a stream the upstream
	// cut short, so the page blames the right party.
	lr := &io.LimitedReader{R: resp.Body, N: maxResponseBytes + 1}
	if err := json.NewDecoder(lr).Decode(into); err != nil {
		if lr.N == 0 {
			return fmt.Errorf("upstream response exceeded %d MB", maxResponseBytes>>20)
		}
		return err
	}
	return nil
}

// rdapResponse: only the fields we render. RDAP returns a great deal more.
type rdapResponse struct {
	Status []string `json:"status"`
	Events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities []struct {
		Roles      []string          `json:"roles"`
		VCardArray []json.RawMessage `json:"vcardArray"`
		// Handle and PublicIDs: what is left to name the registrar by when it
		// publishes no jCard, which several registries do.
		Handle    string `json:"handle"`
		PublicIDs []struct {
			Type       string `json:"type"`
			Identifier string `json:"identifier"`
		} `json:"publicIds"`
	} `json:"entities"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	SecureDNS struct {
		DelegationSigned bool `json:"delegationSigned"`
	} `json:"secureDNS"`
}

// Registration fetches the registry record. rdap.org bootstraps to whichever
// registry serves the TLD, so one URL covers everything.
func (d *DomainClient) Registration(ctx context.Context, domain string) (*Registration, error) {
	if d == nil || d.rdapURL == "" {
		return nil, ErrDisabled
	}
	var r rdapResponse
	if err := d.get(ctx, d.rdapURL+"/domain/"+url.PathEscape(strings.TrimSuffix(domain, ".")), &r); err != nil {
		if errors.Is(err, errUpstreamNotFound) {
			return nil, errNoRDAPRecord
		}
		return nil, err
	}

	out := &Registration{Domain: domain, SignedDelegation: r.SecureDNS.DelegationSigned}
	for _, e := range r.Events {
		switch strings.ToLower(e.Action) {
		case "registration":
			out.Registered = date(e.Date)
		case "expiration":
			out.Expires = date(e.Date)
			if t, err := time.Parse(time.RFC3339, e.Date); err == nil {
				// Floor, not truncate: truncating toward zero calls a domain
				// with twenty hours left "0 days" and one that expired this
				// morning the same, which is how a live domain gets rendered
				// in red as expired.
				d := int(math.Floor(time.Until(t).Hours() / 24))
				out.DaysLeft = &d
			}
		case "last changed":
			out.Updated = date(e.Date)
		}
	}
	for _, st := range r.Status {
		out.Statuses = append(out.Statuses, Status{Code: st, Meaning: eppMeanings[strings.ToLower(st)]})
	}
	for _, ns := range r.Nameservers {
		out.Nameservers = append(out.Nameservers, strings.ToLower(ns.LDHName))
	}
	for _, e := range r.Entities {
		if !slicesContainsFold(e.Roles, "registrar") {
			continue
		}
		out.Registrar = vcardName(e.VCardArray)
		// Not every registry publishes a jCard for the registrar. Its handle,
		// or failing that the IANA id, still names something a reader can look
		// up; a blank row names nothing.
		if out.Registrar == "" {
			out.Registrar = strings.TrimSpace(e.Handle)
		}
		for i := 0; out.Registrar == "" && i < len(e.PublicIDs); i++ {
			out.Registrar = strings.TrimSpace(e.PublicIDs[i].Type + " " + e.PublicIDs[i].Identifier)
		}
		break
	}
	return out, nil
}

// DaysKnown reports whether the registry published an expiry we could read.
// Templates cannot compare through a pointer, and cannot tell a nil DaysLeft
// from one pointing at zero, so the countdown reaches them as these two.
func (r *Registration) DaysKnown() bool { return r != nil && r.DaysLeft != nil }

// Days is the countdown as a plain number: negative once the domain has
// expired, zero on its last day. Meaningless unless DaysKnown.
func (r *Registration) Days() int {
	if r == nil || r.DaysLeft == nil {
		return 0
	}
	return *r.DaysLeft
}

// ctRow: crt.sh's per-certificate shape.
type ctRow struct {
	NameValue string `json:"name_value"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	// SerialNumber: a precertificate and the certificate it precedes are two
	// logged rows carrying one serial, so rows are not certificates.
	SerialNumber string `json:"serial_number"`
}

// CertNames pulls every name Certificate Transparency has seen under a domain
// and rolls the per-certificate rows up per name.
func (d *DomainClient) CertNames(ctx context.Context, domain string) (*CertNames, error) {
	if d == nil || d.ctURL == "" {
		return nil, ErrDisabled
	}
	var rows []ctRow
	q := url.Values{
		"q":       {"%." + strings.TrimSuffix(domain, ".")},
		"output":  {"json"},
		"exclude": {"expired"},
	}
	if err := d.get(ctx, d.ctURL+"/?"+q.Encode(), &rows); err != nil {
		return nil, err
	}

	base := strings.ToLower(strings.TrimSuffix(domain, "."))
	agg := map[string]*Subdomain{}
	// counted: name + serial pairs already tallied, so the precertificate and
	// the final certificate count once between them.
	counted := map[string]bool{}
	wildcard := false
	for _, row := range rows {
		// One certificate can carry many names, newline separated.
		for _, n := range strings.Fields(row.NameValue) {
			n = strings.ToLower(strings.TrimSuffix(n, "."))
			wild := strings.HasPrefix(n, "*.")
			n = strings.TrimPrefix(n, "*.")
			// A multi-SAN certificate carries other people's names. They are
			// not subdomains of this domain, and listing them says they are.
			if n == "" || (n != base && !strings.HasSuffix(n, "."+base)) {
				continue
			}
			if wild {
				wildcard = true
				continue
			}
			s, ok := agg[n]
			if !ok {
				s = &Subdomain{Name: n}
				agg[n] = s
			}
			if key := n + "\x00" + row.SerialNumber; row.SerialNumber == "" || !counted[key] {
				counted[key] = true
				s.Certs++
			}
			if b := date(row.NotBefore); b != "" && (s.FirstSeen == "" || b < s.FirstSeen) {
				s.FirstSeen = b
			}
			// Validity END, not another copy of NotBefore: "last seen" means
			// how long this name stays covered, which is what NotAfter says.
			if a := date(row.NotAfter); a != "" && a > s.LastSeen {
				s.LastSeen = a
			}
		}
	}

	out := &CertNames{Total: len(agg), Wildcard: wildcard}
	for _, s := range agg {
		out.Names = append(out.Names, *s)
	}
	sort.Slice(out.Names, func(i, j int) bool { return out.Names[i].Name < out.Names[j].Name })
	if len(out.Names) > maxSubdomains {
		out.Names = out.Names[:maxSubdomains]
		out.Truncated = true
	}
	return out, nil
}

// date trims an RFC3339-ish timestamp to the day, which is all these fields
// are meaningfully accurate to.
func date(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

func slicesContainsFold(hay []string, needle string) bool {
	for _, h := range hay {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

// vcardName digs the display name out of RDAP's jCard array, which is a
// famously awkward nested-array format: ["vcard", [["fn", {}, "text", NAME]]].
func vcardName(raw []json.RawMessage) string {
	if len(raw) < 2 {
		return ""
	}
	var props [][]json.RawMessage
	if err := json.Unmarshal(raw[1], &props); err != nil {
		return ""
	}
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		var key string
		if json.Unmarshal(p[0], &key) != nil || key != "fn" {
			continue
		}
		var name string
		// An entity can publish an empty fn; the caller's fallback names the
		// registrar better than a blank row does.
		if json.Unmarshal(p[3], &name) == nil {
			if name = strings.TrimSpace(name); name != "" {
				return name
			}
		}
	}
	return ""
}
