package tests

import (
	"context"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/dnstools"
)

func TestValidateDNSSEC_EmptyAndBadInput(t *testing.T) {
	ctx := context.Background()
	if res := dnstools.ValidateDNSSEC(ctx, "", ""); res != nil {
		t.Errorf("expected nil for empty zone, got %+v", res)
	}
}

func TestValidateDNSSEC_LocalMock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// An unreachable port returns structured failure rather than panic
	res := dnstools.ValidateDNSSEC(ctx, "example.com", "127.0.0.1:54321")
	if res == nil {
		t.Fatalf("expected non-nil result on query error")
	}
	if res.Status != "insecure" || res.Details == "" {
		t.Errorf("unexpected status on unreachable resolver: %+v", res)
	}
}
