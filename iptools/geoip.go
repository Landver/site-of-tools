// Package iptools is the ip.corpberry.com tool: IP -> geolocation + ASN,
// plus optional proxy/VPN detection. geoip.go is the domain layer — pure Go, no HTTP.
package iptools

import (
	"errors"
	"fmt"
	"net"
	"slices"

	ip2location "github.com/ip2location/ip2location-go/v9"
	ip2proxy "github.com/ip2location/ip2proxy-go/v4"
)

// Result is the plain struct the transport layer renders as HTML or JSON.
type Result struct {
	IP          string  `json:"ip"`
	CountryCode string  `json:"country_code"`
	Country     string  `json:"country"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Timezone    string  `json:"timezone"`
	Latitude    float32 `json:"lat"`
	Longitude   float32 `json:"lon"`
	ASN         string  `json:"asn"`
	ASName      string  `json:"as_name"`
	Proxy       *Proxy  `json:"proxy,omitempty"`
}

// Proxy is the IP2Proxy view (VPN / proxy / threat). Populated only when the
// PX12 database is loaded and the lookup succeeds.
type Proxy struct {
	IsProxy    bool   `json:"is_proxy"`
	ProxyType  string `json:"proxy_type,omitempty"`
	UsageType  string `json:"usage_type,omitempty"`
	Threat     string `json:"threat,omitempty"`
	Provider   string `json:"provider,omitempty"`
	FraudScore string `json:"fraud_score,omitempty"`
	ISP        string `json:"isp,omitempty"`
	Domain     string `json:"domain,omitempty"`
	LastSeen   string `json:"last_seen,omitempty"`
}

// Service wraps the IP2Location + IP2Proxy readers. Handles are opened once at
// startup and shared across request goroutines (all reads are positional
// ReadAt — goroutine-safe, no full load into RAM). The v6 geo BINs also answer
// v4, but we keep both to route by address family; the single PX12 BIN answers
// both families.
type Service struct {
	db4, db6   *ip2location.DB
	asn4, asn6 *ip2location.DB
	proxy      *ip2proxy.DB // optional; nil disables the proxy section
}

// ErrUnavailable is returned when the geolocation databases were not loaded.
var ErrUnavailable = errors.New("geolocation databases are not loaded")

// OpenService opens DB11 (v4+v6) and ASN (v4+v6). px12 is optional: when
// non-empty it also opens the IP2Proxy database. Missing geo paths are not fatal
// to the caller — it returns (nil, ErrUnavailable) so the server can still start.
func OpenService(db11v4, db11v6, asnv4, asnv6, px12 string) (*Service, error) {
	if slices.Contains([]string{db11v4, db11v6, asnv4, asnv6}, "") {
		return nil, ErrUnavailable
	}
	db4, err := ip2location.OpenDB(db11v4)
	if err != nil {
		return nil, err
	}
	db6, err := ip2location.OpenDB(db11v6)
	if err != nil {
		return nil, err
	}
	asn4, err := ip2location.OpenDB(asnv4)
	if err != nil {
		return nil, err
	}
	asn6, err := ip2location.OpenDB(asnv6)
	if err != nil {
		return nil, err
	}
	s := &Service{db4: db4, db6: db6, asn4: asn4, asn6: asn6}
	if px12 != "" {
		p, err := ip2proxy.OpenDB(px12)
		if err != nil {
			return nil, fmt.Errorf("open ip2proxy: %w", err)
		}
		s.proxy = p
	}
	return s, nil
}

// Lookup resolves geolocation (DB11) + ASN, and proxy info (PX12, if loaded),
// for an IP string. A nil receiver yields ErrUnavailable.
func (s *Service) Lookup(ipStr string) (*Result, error) {
	if s == nil {
		return nil, ErrUnavailable
	}
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return nil, fmt.Errorf("%q is not a valid IP address", ipStr)
	}

	geoDB, asnDB := s.db6, s.asn6 // v6 BINs answer v4 too...
	if parsed.To4() != nil {
		geoDB, asnDB = s.db4, s.asn4 // ...but route native v4 to the v4 BINs.
	}

	geo, err := geoDB.Get_all(ipStr)
	if err != nil {
		return nil, err
	}
	as, err := asnDB.Get_all(ipStr)
	if err != nil {
		return nil, err
	}

	// clean() blanks IP2Location's "-" placeholder (reserved/private ranges and
	// records with no city/zip come back as "-"), matching how lookupProxy already
	// treats the proxy fields — so "-" never leaks into the JSON or HTML.
	return &Result{
		IP:          ipStr,
		CountryCode: clean(geo.Country_short),
		Country:     clean(geo.Country_long),
		Region:      clean(geo.Region),
		City:        clean(geo.City),
		Zip:         clean(geo.Zipcode),
		Timezone:    clean(geo.Timezone),
		Latitude:    geo.Latitude,
		Longitude:   geo.Longitude,
		ASN:         clean(as.Asn),
		ASName:      clean(as.As),
		Proxy:       s.lookupProxy(ipStr),
	}, nil
}

// lookupProxy is best-effort: nil if the proxy DB is off or the lookup errors
// (e.g. an address family the BIN doesn't cover), so it never breaks the geo result.
func (s *Service) lookupProxy(ipStr string) *Proxy {
	if s.proxy == nil {
		return nil
	}
	r, err := s.proxy.GetAll(ipStr)
	if err != nil {
		return nil
	}
	return &Proxy{
		IsProxy:    r.IsProxy > 0, // 0 = no, 1 = proxy, 2 = proxy (data center)
		ProxyType:  clean(r.ProxyType),
		UsageType:  clean(r.UsageType),
		Threat:     clean(r.Threat),
		Provider:   clean(r.Provider),
		FraudScore: clean(r.FraudScore),
		ISP:        clean(r.Isp),
		Domain:     clean(r.Domain),
		LastSeen:   clean(r.LastSeen),
	}
}

// clean blanks IP2Location/IP2Proxy's "-" placeholder for cleaner output. Both
// databases use "-" to mean "no value"; this maps it to "" so callers and
// templates render an empty field rather than a literal dash.
func clean(s string) string {
	if s == "-" {
		return ""
	}
	return s
}
