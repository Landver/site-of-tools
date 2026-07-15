// Package tests holds the black-box tests for the iptools package.
package tests

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Landver/site-of-tools/iptools"
)

func TestLookupNilService(t *testing.T) {
	var s *iptools.Service // never opened
	if _, err := s.Lookup("8.8.8.8"); !errors.Is(err, iptools.ErrUnavailable) {
		t.Errorf("nil service Lookup: got %v, want ErrUnavailable", err)
	}
}

func TestLookupBadIP(t *testing.T) {
	// A non-nil Service validates the IP before touching any DB handle.
	s := &iptools.Service{}
	if _, err := s.Lookup("not-an-ip"); err == nil {
		t.Fatal("expected an error for a malformed IP")
	}
}

// resolveDB returns p if it exists, else tries it relative to the repo root
// (this test file lives in <root>/iptools/tests/). "" if not found.
func resolveDB(p string) string {
	if p == "" {
		return ""
	}
	if _, err := os.Stat(p); err == nil {
		return p
	}
	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(filepath.Dir(thisFile))) // tests → iptools → root
	alt := filepath.Join(root, p)
	if _, err := os.Stat(alt); err == nil {
		return alt
	}
	return ""
}

// TestLookupIntegration exercises the real databases; it skips unless the
// IP2LOCATION_* env vars resolve to existing BINs, so CI/fresh clones stay green
// (the BINs are gitignored). To run locally:
//
//	set -a; . ./.env; set +a; go test ./iptools/tests -run Integration
func TestLookupIntegration(t *testing.T) {
	paths := []string{
		resolveDB(os.Getenv("IP2LOCATION_DB11_V4")),
		resolveDB(os.Getenv("IP2LOCATION_DB11_V6")),
		resolveDB(os.Getenv("IP2LOCATION_ASN_V4")),
		resolveDB(os.Getenv("IP2LOCATION_ASN_V6")),
	}
	for _, p := range paths {
		if p == "" {
			t.Skip("IP2LOCATION_* not set or BINs not found; skipping integration test")
		}
	}

	px12 := resolveDB(os.Getenv("IP2PROXY_PX12")) // optional
	svc, err := iptools.OpenService(paths[0], paths[1], paths[2], paths[3], px12)
	if err != nil {
		t.Fatalf("OpenService: %v", err)
	}
	got, err := svc.Lookup("8.8.8.8")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.CountryCode != "US" {
		t.Errorf("8.8.8.8 country = %q, want US", got.CountryCode)
	}
	if got.ASN != "15169" {
		t.Errorf("8.8.8.8 ASN = %q, want 15169", got.ASN)
	}
	if px12 != "" && got.Proxy == nil {
		t.Error("expected proxy data when the PX12 database is loaded")
	}
}
