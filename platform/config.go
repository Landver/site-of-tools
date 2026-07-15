package platform

import (
	"os"
	"strings"
)

// Config is all runtime configuration, loaded from environment variables
// (12-factor). In dev a .env file at the repo root is loaded first.
type Config struct {
	Env        string // "dev" | "prod"
	ListenAddr string // e.g. ":8080"
	BaseDomain string // "localhost" (dev) | "corpberry.com" (prod)

	// IP2Location LITE database file paths.
	DB11V4 string
	DB11V6 string
	ASNV4  string
	ASNV6  string

	// IP2Proxy PX12 (proxy/VPN/threat). Optional — empty disables the proxy section.
	PX12 string
}

// Load reads config from the environment (after loading .env if present).
func Load() Config {
	loadDotEnv()
	return Config{
		Env:        getenv("APP_ENV", "dev"),
		ListenAddr: getenv("LISTEN_ADDR", ":8080"),
		BaseDomain: getenv("BASE_DOMAIN", "localhost"),
		DB11V4:     os.Getenv("IP2LOCATION_DB11_V4"),
		DB11V6:     os.Getenv("IP2LOCATION_DB11_V6"),
		ASNV4:      os.Getenv("IP2LOCATION_ASN_V4"),
		ASNV6:      os.Getenv("IP2LOCATION_ASN_V6"),
		PX12:       os.Getenv("IP2PROXY_PX12"),
	}
}

func (c Config) IsDev() bool { return c.Env != "prod" }

// VHost builds the Host key used by echo.NewVirtualHostHandler. sub == "" is the
// apex. In dev the browser sends the port in the Host header (e.g.
// "ip.localhost:8080"), so it is included; in prod nginx forwards a bare host.
func (c Config) VHost(sub string) string {
	host := c.BaseDomain
	if sub != "" {
		host = sub + "." + host
	}
	if c.IsDev() {
		host += portOf(c.ListenAddr)
	}
	return host
}

// URL returns a full origin (scheme + host) for a subdomain, e.g. for links.
func (c Config) URL(sub string) string {
	scheme := "https://"
	if c.IsDev() {
		scheme = "http://"
	}
	return scheme + c.VHost(sub)
}

// portOf turns ":8080" or "0.0.0.0:8080" into ":8080".
func portOf(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[i:]
	}
	return ""
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// loadDotEnv reads KEY=VALUE lines from ./.env without overriding vars already
// set in the real environment. No dependency; dev convenience only.
func loadDotEnv() {
	data, err := os.ReadFile(".env")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if _, exists := os.LookupEnv(k); !exists {
			os.Setenv(k, v)
		}
	}
}
