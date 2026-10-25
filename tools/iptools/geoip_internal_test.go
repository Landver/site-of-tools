package iptools

import (
	"testing"
	"time"
)

// White-box: without the BINs Lookup can't run, so the attached Shodan client is visible only inside.
func TestWithShodanReturnsACopy(t *testing.T) {
	sh := NewShodan("http://127.0.0.1:1", time.Second)
	s := &Service{}
	online := s.WithShodan(sh)
	if online == s || online.shodan != sh {
		t.Errorf("WithShodan() = %p with shodan %v, want a copy carrying Shodan", online, online.shodan)
	}
	if s.shodan != nil {
		t.Error("WithShodan() attached Shodan to the original service")
	}
}
