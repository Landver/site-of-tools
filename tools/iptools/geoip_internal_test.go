package iptools

import (
	"testing"
	"time"
)

// White-box: without the BINs no Lookup runs, so only the field shows Shodan was detached.
func TestOfflineDetachesShodanOnly(t *testing.T) {
	sh := NewShodan("http://127.0.0.1:1", time.Second)
	s := (&Service{}).WithShodan(sh)
	off := s.Offline()
	if off == s || off.shodan != nil {
		t.Errorf("Offline() = %p with shodan %v, want a copy without Shodan", off, off.shodan)
	}
	if s.shodan != sh {
		t.Error("Offline() detached Shodan from the original service")
	}
	if (*Service)(nil).Offline() != nil {
		t.Error("nil Service.Offline() != nil")
	}
}
