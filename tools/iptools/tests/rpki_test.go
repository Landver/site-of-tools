package tests

import (
	"net/netip"
	"testing"

	"github.com/Landver/site-of-tools/tools/iptools"
)

func TestRPKIValidationRFC6811(t *testing.T) {
	// Seed mock ROAs:
	// IPv4:
	// - 1.0.0.0/24 authorized for AS13335 (Cloudflare)
	// - 1.0.128.0/17 authorized for AS23969 and AS13335 (multi-homed)
	// IPv6:
	// - 2606:4700::/32 authorized for AS13335
	iptools.SeedRPKIForTest([]iptools.ROAEntry{
		{Prefix: netip.MustParsePrefix("1.0.0.0/24"), ASN: 13335, MaxLength: 24},
		{Prefix: netip.MustParsePrefix("1.0.128.0/17"), ASN: 23969, MaxLength: 19},
		{Prefix: netip.MustParsePrefix("1.0.128.0/17"), ASN: 13335, MaxLength: 19},
		{Prefix: netip.MustParsePrefix("2606:4700::/32"), ASN: 13335, MaxLength: 48},
	})

	// Valid IPv4 case
	res1 := iptools.ValidateRPKI("1.0.0.1", "13335")
	if res1 == nil || res1.Status != "valid" {
		t.Errorf("expected valid, got %+v", res1)
	}

	// Valid IPv4 multi-homed (either AS matches per RFC 6811)
	resMulti1 := iptools.ValidateRPKI("1.0.128.5", "23969")
	if resMulti1 == nil || resMulti1.Status != "valid" {
		t.Errorf("expected multi-homed AS23969 valid, got %+v", resMulti1)
	}
	resMulti2 := iptools.ValidateRPKI("1.0.128.5", "13335")
	if resMulti2 == nil || resMulti2.Status != "valid" {
		t.Errorf("expected multi-homed AS13335 valid, got %+v", resMulti2)
	}

	// Invalid IPv4: AS mismatch
	res2 := iptools.ValidateRPKI("1.0.0.1", "99999")
	if res2 == nil || res2.Status != "invalid" {
		t.Errorf("expected invalid AS mismatch, got %+v", res2)
	}

	// Valid IPv6 case
	resV6 := iptools.ValidateRPKI("2606:4700::1", "13335")
	if resV6 == nil || resV6.Status != "valid" {
		t.Errorf("expected valid IPv6, got %+v", resV6)
	}

	// NotFound case: no ROA covering 8.8.8.8
	res3 := iptools.ValidateRPKI("8.8.8.8", "15169")
	if res3 == nil || res3.Status != "not_found" {
		t.Errorf("expected not_found, got %+v", res3)
	}

	// Prefix / ASN formatting edge cases
	if res := iptools.ValidateRPKI("1.0.0.1", "AS13335"); res == nil || res.Status != "valid" {
		t.Errorf("AS prefix normalization failed: got %+v", res)
	}
	if res := iptools.ValidateRPKI("not-an-ip", "13335"); res != nil {
		t.Errorf("expected nil on invalid IP, got %+v", res)
	}
	if res := iptools.ValidateRPKI("1.0.0.1", "invalid-asn"); res != nil {
		t.Errorf("expected nil on invalid ASN, got %+v", res)
	}
}
