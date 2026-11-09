package tests

import (
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/dnstools"
)

func TestCTCacheHitAndExpiry(t *testing.T) {
	cache := dnstools.NewCTCache(50 * time.Millisecond)

	data := &dnstools.CertNames{
		Total: 2,
		Names: []dnstools.Subdomain{
			{Name: "api.example.com", Certs: 1},
			{Name: "app.example.com", Certs: 2},
		},
	}

	cache.Set("example.com", data)

	got, ok := cache.Get("example.com")
	if !ok || got == nil {
		t.Fatalf("expected cache hit, got ok=%v", ok)
	}
	if got.Total != 2 {
		t.Errorf("got total %d, want 2", got.Total)
	}

	// Miss on non-existent domain
	if _, ok := cache.Get("missing.com"); ok {
		t.Errorf("expected miss on missing.com")
	}

	// Expiry test
	time.Sleep(60 * time.Millisecond)
	if _, ok := cache.Get("example.com"); ok {
		t.Errorf("expected cache entry to expire after 50ms")
	}
}
