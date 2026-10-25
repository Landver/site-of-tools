// Package tests: black-box tests for iptools.
package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/iptools"
)

func TestLookupNilService(t *testing.T) {
	var s *iptools.Service
	if _, err := s.Lookup(context.Background(), "8.8.8.8"); !errors.Is(err, iptools.ErrUnavailable) {
		t.Errorf("nil service Lookup: got %v, want ErrUnavailable", err)
	}
}

func TestLookupBadIP(t *testing.T) {
	// A non-nil Service validates the IP before touching a DB handle.
	s := &iptools.Service{}
	if _, err := s.Lookup(context.Background(), "not-an-ip"); err == nil {
		t.Fatal("expected an error for a malformed IP")
	}
}

func resolveDB(p string) string {
	if p == "" {
		return ""
	}
	if _, err := os.Stat(p); err == nil {
		return p
	}
	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	alt := filepath.Join(root, p)
	if _, err := os.Stat(alt); err == nil {
		return alt
	}
	return ""
}

// Skips unless IP2LOCATION_* resolve to real BINs, which are gitignored, so CI stays green.
func TestLookupIntegration(t *testing.T) {
	svc, px12 := integrationService(t)
	got, err := svc.Lookup(context.Background(), "8.8.8.8")
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

// integrationService skips the test without the BINs; px12 is "" when the proxy BIN isn't loaded.
func integrationService(t *testing.T) (svc *iptools.Service, px12 string) {
	t.Helper()
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
	px12 = resolveDB(os.Getenv("IP2PROXY_PX12"))
	svc, err := iptools.OpenService(paths[0], paths[1], paths[2], paths[3], px12)
	if err != nil {
		t.Fatalf("OpenService: %v", err)
	}
	return svc, px12
}

// DNS enrichment uses the plain service, which must leave the shared Shodan budget alone; ctx bounds the call.
func TestWithShodanLeavesPlainServiceOffline(t *testing.T) {
	svc, _ := integrationService(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	online := svc.WithShodan(iptools.NewShodan(srv.URL, time.Second))

	got, err := svc.Lookup(context.Background(), "8.8.8.8")
	if err != nil || got.ASN != "15169" || got.Shodan != nil || hits.Load() != 0 {
		t.Fatalf("plain lookup = %+v, %v after %d InternetDB calls; want ASN 15169 and no call", got, err, hits.Load())
	}
	got, err = online.Lookup(context.Background(), "8.8.8.8")
	if err != nil || got.Shodan == nil || hits.Load() != 1 {
		t.Errorf("online lookup = %+v, %v after %d InternetDB calls; want one", got, err, hits.Load())
	}
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	got, err = online.Lookup(gone, "8.8.8.8")
	if err != nil || got.ASN != "15169" || got.Shodan != nil || hits.Load() != 1 {
		t.Errorf("lookup after a hang-up = %+v, %v after %d InternetDB calls; want geo only, no new call", got, err, hits.Load())
	}
}
