package platform

import (
	"bufio"
	"cmp"
	"io"
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

	// MongoDB connection. Optional — an empty MongoURI disables Mongo entirely
	// (platform.OpenMongo returns ErrMongoUnavailable and callers degrade, exactly
	// like the missing-BIN path). MongoDatabase is the app database name on the
	// shared server; it defaults to platform.DefaultMongoDatabase ("site-of-tools").
	// No feature uses Mongo yet — the connection is wired in config so a future
	// storage layer can sit below the domain services (ARCHITECTURE §10).
	MongoURI      string
	MongoDatabase string
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
		MongoURI:   os.Getenv("MONGODB_URI"),
		// Default the app database name so only MONGODB_URI is mandatory to enable Mongo.
		MongoDatabase: getenv("MONGODB_DATABASE", DefaultMongoDatabase),
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
	return cmp.Or(os.Getenv(k), def)
}

// loadDotEnv reads KEY=VALUE lines from ./.env and applies them to the process
// environment, never overriding a var already set. No dependency; dev convenience
// only. The parse and merge steps are split out (parseDotEnv/mergeEnv) so both are
// unit-testable without touching a real .env file or the ambient environment.
func loadDotEnv() {
	f, err := os.Open(".env")
	if err != nil {
		return
	}
	defer f.Close()
	mergeEnv(parseDotEnv(f))
}

// parseDotEnv parses KEY=VALUE lines from r into a map. Blank lines, "#" comments,
// and lines without "=" are skipped; the key and value are whitespace-trimmed (a
// value may itself contain "="). Pure — no environment access — so it is directly
// unit-testable.
func parseDotEnv(r io.Reader) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

// mergeEnv sets each pair in the process environment, skipping any key already
// present so the real environment always wins over .env (and .env.prod layered on
// top in prod). Split from loadDotEnv so the no-override rule can be tested.
func mergeEnv(pairs map[string]string) {
	for k, v := range pairs {
		if _, exists := os.LookupEnv(k); !exists {
			os.Setenv(k, v)
		}
	}
}
