package dnstools

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/Landver/site-of-tools/platform"
)

// ErrDisabled: no URL is configured, so transports can say "not available" instead.
var ErrDisabled = errors.New("this lookup is switched off")

// errUpstreamNotFound is a 404, which for RDAP is an answer, not a breakdown.
var errUpstreamNotFound = errors.New("upstream has no record")

var errUpstreamBusy = errors.New("busy, try again shortly")

// errNoRDAPRecord: the registry answered that it holds no object for the name (RFC 7480 §5.3).
var errNoRDAPRecord = errors.New("the registry has no record for this name: it is unregistered, or its TLD publishes no RDAP service")

// domainUserAgent identifies us, so an upstream can contact us rather than block us.
const domainUserAgent = "corpberry-dnstools/1.0 (+https://dns.corpberry.com; contact via github.com/Landver/site-of-tools)"

type Registration struct {
	Domain     string `json:"domain"`
	Registrar  string `json:"registrar,omitempty"`
	Registered string `json:"registered,omitempty"`
	Expires    string `json:"expires,omitempty"`
	Updated    string `json:"updated,omitempty"`
	// DaysLeft: nil when no readable expiry; 0 is the last day, negative is expired.
	DaysLeft    *int     `json:"days_left,omitempty"`
	Statuses    []Status `json:"statuses,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
	// SignedDelegation: the registry reports a DS record, so DNSSEC is delegated.
	SignedDelegation bool `json:"signed_delegation"`
}

type Status struct {
	Code    string `json:"code"`
	Meaning string `json:"meaning"`
}

var eppMeanings = map[string]string{
	"client transfer prohibited": "Locked against transfers by the registrar: the usual anti-hijacking default. To move the domain, its owner asks the registrar to lift the lock and send the transfer (auth) code.",
	"server transfer prohibited": "Locked against transfers by the registry.",
	"client delete prohibited":   "Locked against deletion by the registrar.",
	"server delete prohibited":   "Locked against deletion by the registry.",
	"client update prohibited":   "Locked by the registrar against changes to the registration (contacts, nameservers). DNS records are unaffected.",
	"server update prohibited":   "Locked by the registry against changes to the registration (contacts, nameservers). DNS records are unaffected.",
	"client renew prohibited":    "Locked against renewal by the registrar.",
	"server renew prohibited":    "Locked against renewal by the registry.",
	"client hold":                "The registrar has pulled this domain from DNS. It will not resolve.",
	"server hold":                "The registry has pulled this domain from DNS. It will not resolve.",
	"pending create":             "The registration is still being processed.",
	"pending renew":              "A renewal is in progress.",
	"pending update":             "A change to the record is in progress.",
	"pending transfer":           "A transfer to another registrar is in progress.",
	"pending restore":            "A restore out of the redemption period was requested; the registry is waiting on the paperwork.",
	"pending delete":             "Scheduled for deletion.",
	"redemption period":          "Expired and in the grace window. Recoverable, usually for a fee.",
	"auto renew period":          "Recently auto-renewed; still inside the refund window.",
	"renew period":               "Renewed manually very recently; still inside the refund window.",
	"transfer period":            "Transferred very recently; still inside the window where the transfer can be undone.",
	"add period":                 "Registered very recently; inside the initial grace window.",
	"ok":                         "No restrictions. Note that this also means no transfer lock.",
	"active":                     "No restrictions.",
	"inactive":                   "No nameservers delegated, so nothing under this domain resolves.",
}

type Subdomain struct {
	Name string `json:"name"`
	// FirstSeen/LastSeen span the validity of unexpired certificates, not sightings;
	// the wire names say so, the Go names are what templates and tests bind to.
	FirstSeen string `json:"valid_since,omitempty"`
	LastSeen  string `json:"covered_until,omitempty"`
	Certs     int    `json:"certs"`
}

type CertNames struct {
	Names     []Subdomain `json:"names"`
	Total     int         `json:"total"`
	Truncated bool        `json:"truncated,omitempty"`
	// Wildcard: a wildcard certificate covers the domain, so names under it never show here.
	Wildcard bool `json:"wildcard,omitempty"`
}

const (
	maxSubdomains    = 200
	maxResponseBytes = 8 << 20
)

// DomainClient talks to RDAP and Certificate Transparency. nil disables both.
type DomainClient struct {
	client             *http.Client
	rdapURL            string
	ctURL              string
	rdapLimit, ctLimit *rate.Limiter
}

var errRedirectRefused = errors.New("redirect refused")

// NewDomainClient builds the client. Blank URLs disable that half.
func NewDomainClient(rdapURL, ctURL string, timeout time.Duration) *DomainClient {
	if rdapURL == "" && ctURL == "" {
		return nil
	}
	// rdap.org and crt.sh throttle a busy address, and all our requests come from one.
	d := &DomainClient{
		rdapURL:   strings.TrimSuffix(rdapURL, "/"),
		ctURL:     strings.TrimSuffix(ctURL, "/"),
		rdapLimit: rate.NewLimiter(1, 5),
		ctLimit:   rate.NewLimiter(1, 5),
	}
	d.client = d.httpClient(timeout, platform.NewEgressGuard([]string{"80", "443"}, nil))
	return d
}

// WithEgressGuard sends every dial off the configured hosts through g. Nil-safe.
func (d *DomainClient) WithEgressGuard(g *platform.EgressGuard) *DomainClient {
	if d != nil {
		d.client = d.httpClient(d.client.Timeout, g)
	}
	return d
}

func (d *DomainClient) httpClient(timeout time.Duration, g *platform.EgressGuard) *http.Client {
	base := map[string]bool{}
	for _, raw := range []string{d.rdapURL, d.ctURL} {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			base[hostPort(u)] = true
		}
	}
	direct := &net.Dialer{Timeout: timeout}
	tr := g.Transport(timeout)
	gated := tr.DialContext
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if base[strings.ToLower(addr)] {
			return direct.DialContext(ctx, network, addr)
		}
		return gated(ctx, network, addr)
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			switch {
			case len(via) >= 10:
				return errors.New("stopped after 10 redirects")
			// Plain HTTP too: .kg and .mg RDAP has no HTTPS, and g vets the address.
			case req.URL.Scheme != "https" && req.URL.Scheme != "http":
				return errRedirectRefused
			case base[hostPort(req.URL)]:
				return nil
			}
			// By name too: our own vhosts resolve to public addresses.
			return g.AllowHost(req.URL.Hostname())
		},
		Transport: tr,
	}
}

func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	return strings.ToLower(net.JoinHostPort(u.Hostname(), port))
}

func (d *DomainClient) get(ctx context.Context, endpoint string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", domainUserAgent)
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		// Plain words: the raw error embeds the whole request URL.
		switch {
		case errors.Is(err, errRedirectRefused), errors.Is(err, platform.ErrBlockedAddress), errors.Is(err, platform.ErrBlockedPort):
			return fmt.Errorf("%s redirected somewhere this tool won't follow", req.URL.Host)
		case isTimeout(err) || errors.Is(err, context.DeadlineExceeded):
			return fmt.Errorf("%s timed out", req.URL.Host)
		}
		return fmt.Errorf("couldn't reach %s", req.URL.Host)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errUpstreamNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered with an error (%d)", req.URL.Host, resp.StatusCode)
	}
	// One byte past the cap tells our truncation from a stream the upstream cut short.
	lr := &io.LimitedReader{R: resp.Body, N: maxResponseBytes + 1}
	if err := json.NewDecoder(lr).Decode(into); err != nil {
		if lr.N == 0 {
			return fmt.Errorf("upstream response exceeded %d MB", maxResponseBytes>>20)
		}
		// Plain words: an HTML error page served as 200 would otherwise read as a JSON syntax error.
		return fmt.Errorf("%s sent a reply that couldn't be read as JSON", req.URL.Host)
	}
	return nil
}

type rdapResponse struct {
	// ObjectClassName/LDHName say what the body is about: a bootstrap redirect can land elsewhere.
	ObjectClassName string   `json:"objectClassName"`
	LDHName         string   `json:"ldhName"`
	Status          []string `json:"status"`
	Events          []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities []struct {
		Roles      []string `json:"roles"`
		VCardArray []any    `json:"vcardArray"`
	} `json:"entities"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	SecureDNS struct {
		DelegationSigned bool `json:"delegationSigned"`
	} `json:"secureDNS"`
}

// Registration fetches the registry record; rdap.org bootstraps to the TLD's registry.
func (d *DomainClient) Registration(ctx context.Context, domain string) (*Registration, error) {
	if d == nil || d.rdapURL == "" {
		return nil, ErrDisabled
	}
	if !d.rdapLimit.Allow() {
		return nil, errUpstreamBusy
	}
	asked := bareName(domain)
	var r rdapResponse
	if err := d.get(ctx, d.rdapURL+"/domain/"+url.PathEscape(asked), &r); err != nil {
		if errors.Is(err, errUpstreamNotFound) {
			return nil, errNoRDAPRecord
		}
		return nil, err
	}

	gotName := bareName(r.LDHName)
	// An IDN comes back as its A-label, so only names whose two forms match are compared.
	if (r.ObjectClassName != "" && !strings.EqualFold(r.ObjectClassName, "domain")) || (gotName != "" && isASCII(asked) && gotName != asked) {
		return nil, fmt.Errorf("the registry answered about something other than the domain %s", asked)
	}

	out := &Registration{Domain: cmp.Or(gotName, domain), SignedDelegation: r.SecureDNS.DelegationSigned}
	for _, e := range r.Events {
		switch strings.ToLower(e.Action) {
		case "registration":
			out.Registered = date(e.Date)
		case "expiration":
			out.Expires = date(e.Date)
			if t, err := time.Parse(time.RFC3339, e.Date); err == nil {
				// Floor, not truncate: an expiry this morning is -1, not the same 0 as 20 hours left.
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
		// Trailing dot off, so names compare equal to the zone's own NS records.
		out.Nameservers = append(out.Nameservers, bareName(ns.LDHName))
	}
	// The first registrar-role entity is sometimes an empty stub wrapping the named one.
	for _, e := range r.Entities {
		if out.Registrar == "" && slices.ContainsFunc(e.Roles, func(r string) bool { return strings.EqualFold(r, "registrar") }) {
			out.Registrar = vcardName(e.VCardArray)
		}
	}
	return out, nil
}

// DaysKnown and Days exist because templates can't tell a nil DaysLeft from a zero one.
func (r *Registration) DaysKnown() bool { return r != nil && r.DaysLeft != nil }

func (r *Registration) Days() int {
	if r == nil || r.DaysLeft == nil {
		return 0
	}
	return *r.DaysLeft
}

type ctRow struct {
	NameValue string `json:"name_value"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	// SerialNumber: a precertificate and its certificate are two rows with one serial.
	SerialNumber string `json:"serial_number"`
}

// CertNames rolls Certificate Transparency's per-certificate rows up per name.
func (d *DomainClient) CertNames(ctx context.Context, domain string) (*CertNames, error) {
	if d == nil || d.ctURL == "" {
		return nil, ErrDisabled
	}
	if !d.ctLimit.Allow() {
		return nil, errUpstreamBusy
	}
	var rows []ctRow
	q := url.Values{"q": {"%." + strings.TrimSuffix(domain, ".")}, "output": {"json"}, "exclude": {"expired"}}
	if err := d.get(ctx, d.ctURL+"/?"+q.Encode(), &rows); err != nil {
		return nil, err
	}

	base := bareName(domain)
	agg := map[string]Subdomain{}
	counted := map[string]bool{} // name+serial: a precertificate and its certificate count once
	wildcard := false
	for _, row := range rows {
		// One certificate can carry many names, newline separated.
		for _, n := range strings.Fields(row.NameValue) {
			n = bareName(n)
			wild := strings.HasPrefix(n, "*.")
			n = strings.TrimPrefix(n, "*.")
			// A multi-SAN certificate carries other domains' names; they are not subdomains.
			if n == "" || (n != base && !strings.HasSuffix(n, "."+base)) {
				continue
			}
			if wild {
				wildcard = true
				continue
			}
			s := agg[n]
			s.Name = n
			if key := n + "\x00" + row.SerialNumber; row.SerialNumber == "" || !counted[key] {
				counted[key] = true
				s.Certs++
			}
			if b := date(row.NotBefore); b != "" && (s.FirstSeen == "" || b < s.FirstSeen) {
				s.FirstSeen = b
			}
			if a := date(row.NotAfter); a != "" && a > s.LastSeen {
				s.LastSeen = a
			}
			agg[n] = s
		}
	}

	out := &CertNames{Total: len(agg), Wildcard: wildcard,
		Names: slices.SortedFunc(maps.Values(agg), func(a, b Subdomain) int { return strings.Compare(a.Name, b.Name) })}
	if len(out.Names) > maxSubdomains {
		out.Names = out.Names[:maxSubdomains]
		out.Truncated = true
	}
	return out, nil
}

// DomainReport is GET /domain's body; Err judges it as a whole.
type DomainReport struct {
	CertNames         *CertNames    `json:"certificate_names,omitempty"`
	CertNamesError    string        `json:"certificate_names_error,omitempty"`
	Delegated         bool          `json:"delegated,omitempty"`
	Name              string        `json:"name"`
	RegistrableDomain string        `json:"registrable_domain,omitempty"`
	Registration      *Registration `json:"registration,omitempty"`
	RegistrationError string        `json:"registration_error,omitempty"`

	RegErr  error `json:"-"`
	CertErr error `json:"-"`
}

// DomainInfo's error is bad input only: an upstream failing lands in the report.
func DomainInfo(ctx context.Context, svc Looker, dom *DomainClient, name string) (*DomainReport, error) {
	name = NormalizeName(name)
	if err := needDomain(name); err != nil {
		return nil, err
	}
	out := &DomainReport{Name: name}
	regName := RegistrableDomain(name)
	if regName != name {
		out.RegistrableDomain = regName
	}

	// errPanic stays only if a half panics before it answers.
	out.RegErr, out.CertErr = errPanic, errPanic
	var wg sync.WaitGroup
	wg.Add(2)
	go safe(func() { defer wg.Done(); out.Registration, out.RegErr = dom.Registration(ctx, regName) })
	go safe(func() { defer wg.Done(); out.CertNames, out.CertErr = dom.CertNames(ctx, name) })
	wg.Wait()

	if out.RegErr != nil {
		out.RegistrationError = out.RegErr.Error()
		// Nameservers mean registered, whatever the TLD's RDAP says (.de has none).
		if errors.Is(out.RegErr, errNoRDAPRecord) {
			if set, err := svc.LookupSet(ctx, regName, DefaultResolver, []string{"NS"}); err == nil && len(set.Found) > 0 {
				out.Delegated = true
				out.RegistrationError = "the registry publishes no RDAP record for this name; it has nameservers delegated to it, so it is registered"
			}
		}
	}
	if out.CertErr != nil {
		out.CertNamesError = out.CertErr.Error()
	}
	return out, nil
}

func (r *DomainReport) Err() error {
	switch {
	case errors.Is(r.RegErr, ErrDisabled) && errors.Is(r.CertErr, ErrDisabled):
		return ErrDisabled
	case r.RegErr != nil && r.CertErr != nil && !r.Delegated:
		// %s, not %w: one half being switched off must not read as both.
		return fmt.Errorf("registration: %s; certificate transparency: %s", r.RegistrationError, r.CertNamesError)
	}
	return nil
}

func date(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

// vcardName digs fn out of a jCard: ["vcard", [["fn", {}, "text", NAME]]].
func vcardName(card []any) string {
	if len(card) < 2 {
		return ""
	}
	props, _ := card[1].([]any)
	for _, p := range props {
		if prop, _ := p.([]any); len(prop) >= 4 && prop[0] == "fn" {
			if name, _ := prop[3].(string); strings.TrimSpace(name) != "" {
				return strings.TrimSpace(name)
			}
		}
	}
	return ""
}
