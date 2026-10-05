package iptools

import (
	"testing"
	"time"
)

// White-box: without the BINs a Lookup can't run, so the detached Shodan
// client is only visible from inside.
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
}
