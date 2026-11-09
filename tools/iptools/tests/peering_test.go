package tests

import (
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/iptools"
)

func TestPeeringDBParsingAndLookup(t *testing.T) {
	rawJSON := `{
		"net": {
			"data": [
				{
					"id": 1,
					"asn": 13335,
					"name": "Cloudflare",
					"policy_general": "Open",
					"info_traffic": "100+ Tbps",
					"info_ratio": "Mostly Inbound",
					"info_scope": "Global",
					"website": "https://www.cloudflare.com"
				},
				{
					"id": 2,
					"asn": 15169,
					"name": "Google LLC",
					"policy_general": "Open",
					"info_traffic": "100+ Tbps",
					"info_ratio": "Balanced",
					"info_scope": "Global",
					"website": "https://www.google.com"
				}
			]
		},
		"netixlan": {
			"data": [
				{"net_id": 1, "name": "DE-CIX Frankfurt"},
				{"net_id": 1, "name": "AMS-IX"},
				{"net_id": 1, "name": "LINX Juniper LAN"},
				{"net_id": 2, "name": "Equinix Ashburn"}
			]
		}
	}`

	table, err := iptools.ParsePeeringDBDump(strings.NewReader(rawJSON))
	if err != nil {
		t.Fatalf("ParsePeeringDBDump failed: %v", err)
	}

	iptools.SetPeeringCacheForTest(table)

	cf := iptools.LookupPeering("AS13335")
	if cf == nil {
		t.Fatalf("LookupPeering(AS13335) returned nil")
	}
	if cf.Name != "Cloudflare" {
		t.Errorf("got name %q, want Cloudflare", cf.Name)
	}
	if cf.Policy != "Open" {
		t.Errorf("got policy %q, want Open", cf.Policy)
	}
	if cf.IXPCount != 3 {
		t.Errorf("got IXPCount %d, want 3", cf.IXPCount)
	}
	if len(cf.IXPs) != 3 || cf.IXPs[0] != "DE-CIX Frankfurt" {
		t.Errorf("unexpected IXPs: %v", cf.IXPs)
	}

	// Plain number lookup
	google := iptools.LookupPeering("15169")
	if google == nil || google.IXPCount != 1 {
		t.Fatalf("unexpected Google lookup: %+v", google)
	}

	// Unknown ASN
	unknown := iptools.LookupPeering("999999")
	if unknown != nil {
		t.Errorf("expected nil for unknown ASN, got %+v", unknown)
	}
}
