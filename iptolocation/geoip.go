// Package iptolocation is the ip.corpberry.com tool: IP -> geolocation + ASN.
// geoip.go is the domain layer — pure Go, no HTTP, no config coupling.
package iptolocation

import (
	"errors"
	"fmt"
	"net"

	ip2location "github.com/ip2location/ip2location-go/v9"
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
}

// Service wraps the IP2Location readers. Handles are opened once at startup and
// shared across request goroutines (Get_all uses positional reads and is
// goroutine-safe). The v6 BINs also answer v4, but we keep both to route by
// address family.
type Service struct {
	db4, db6   *ip2location.DB
	asn4, asn6 *ip2location.DB
}

// ErrUnavailable is returned when the databases were not loaded at startup.
var ErrUnavailable = errors.New("geolocation databases are not loaded")

// OpenService opens the DB11 (v4+v6) and ASN (v4+v6) handles from the given
// file paths. An empty path or open failure is not fatal to the caller: it
// returns (nil, ErrUnavailable / err) so the server can still start.
func OpenService(db11v4, db11v6, asnv4, asnv6 string) (*Service, error) {
	for _, p := range []string{db11v4, db11v6, asnv4, asnv6} {
		if p == "" {
			return nil, ErrUnavailable
		}
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
	return &Service{db4: db4, db6: db6, asn4: asn4, asn6: asn6}, nil
}

// Lookup resolves geolocation (DB11) + ASN for an IP string. A nil receiver
// (databases never loaded) yields ErrUnavailable.
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

	return &Result{
		IP:          ipStr,
		CountryCode: geo.Country_short,
		Country:     geo.Country_long,
		Region:      geo.Region,
		City:        geo.City,
		Zip:         geo.Zipcode,
		Timezone:    geo.Timezone,
		Latitude:    geo.Latitude,
		Longitude:   geo.Longitude,
		ASN:         as.Asn,
		ASName:      as.As,
	}, nil
}
