package tests

import (
	"net/netip"
	"testing"

	"github.com/Landver/site-of-tools/tools/iptools"
)

func TestRPKIValidationRFC6811(t *testing.T) {
	// Seed mock ROAs:
	// 1.0.0.0/24 authorized for AS13335 with maxLength 24
	// 1.0.128.0/17 authorized for AS23969 with maxLength 19
	iptools.SeedRPKIForTest([]iptools.TestROA{
		{Prefix: netip.MustParsePrefix("1.0.0.0/24"), ASN: 13335, MaxLength: 24},
		{Prefix: netip.MustParsePrefix("1.0.128.0/17"), ASN: 23969, MaxLength: 19},
	})

	// Valid case: exactly matches AS and length
	res1 := iptools.ValidateRPKI("1.0.0.1", "13335")
	if res1.Status != "valid" {
		t.Errorf("expected valid, got %+v", res1)
	}

	// Invalid case: AS mismatch
	res2 := iptools.ValidateRPKI("1.0.0.1", "99999")
	if res2.Status != "invalid" || res2.ROAASN != 13335 {
		t.Errorf("expected invalid AS mismatch, got %+v", res2)
	}

	// NotFound case: no ROA covering 8.8.8.8
	res3 := iptools.ValidateRPKI("8.8.8.8", "15169")
	if res3.Status != "not_found" {
		t.Errorf("expected not_found, got %+v", res3)
	}
}
