// Package tests: black-box tests for platform package. Own folder → tests
// never sit among code they exercise; tradeoff: only platform's exported API
// usable.
package tests

import (
	"testing"

	"github.com/Landver/site-of-tools/platform"
)

func TestVHost(t *testing.T) {
	dev := platform.Config{Env: "dev", BaseDomain: "localhost", ListenAddr: ":8080"}
	prod := platform.Config{Env: "prod", BaseDomain: "corpberry.com", ListenAddr: ":8080"}
	tests := []struct {
		name string
		cfg  platform.Config
		sub  string
		want string
	}{
		{"dev apex", dev, "", "localhost:8080"}, // includes the port (v5 host match)
		{"dev sub", dev, "ip", "ip.localhost:8080"},
		{"prod apex", prod, "", "corpberry.com"}, // bare host in prod
		{"prod sub", prod, "ip", "ip.corpberry.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.VHost(tt.sub); got != tt.want {
				t.Errorf("VHost(%q) = %q, want %q", tt.sub, got, tt.want)
			}
		})
	}
}

func TestURL(t *testing.T) {
	dev := platform.Config{Env: "dev", BaseDomain: "localhost", ListenAddr: ":8080"}
	if got, want := dev.URL("ip"), "http://ip.localhost:8080"; got != want {
		t.Errorf("dev URL = %q, want %q", got, want)
	}
	prod := platform.Config{Env: "prod", BaseDomain: "corpberry.com", ListenAddr: ":8080"}
	if got, want := prod.URL("ip"), "https://ip.corpberry.com"; got != want {
		t.Errorf("prod URL = %q, want %q", got, want)
	}
}
