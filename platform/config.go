package platform

import (
	"bufio"
	"cmp"
	"io"
	"os"
	"strings"
)

// Config: all runtime config, loaded from env vars (12-factor). Dev loads
// .env at repo root first.
type Config struct {
	Env        string // "dev" | "prod"
	ListenAddr string // e.g. ":8080"
	BaseDomain string // "localhost" (dev) | "corpberry.com" (prod)

	// IP2Location LITE DB file paths.
	DB11V4 string
	DB11V6 string
	ASNV4  string
	ASNV6  string

	// IP2Proxy PX12 (proxy/VPN/threat). Optional — empty → proxy section disabled.
	PX12 string

	// MongoDB conn. Optional — empty MongoURI disables Mongo entirely
	// (OpenMongo returns ErrMongoUnavailable, callers degrade — same as
	// missing-BIN path). MongoDatabase = app DB name on shared server,
	// defaults to DefaultMongoDatabase ("site-of-tools"). Used by IP-tool
	// lookup history + request-log corpus; empty MongoURI → both no-op, app
	// still boots (ARCHITECTURE §10).
	MongoURI      string
	MongoDatabase string
}

// Load reads config from env (after loading .env if present).
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
		// Default app DB name → only MONGODB_URI mandatory to enable Mongo.
		MongoDatabase: getenv("MONGODB_DATABASE", DefaultMongoDatabase),
	}
}

func (c Config) IsDev() bool { return c.Env != "prod" }

// VHost builds Host key for echo.NewVirtualHostHandler. sub == "" = apex. Dev
// browser sends port in Host header (e.g. "ip.localhost:8080") → included;
// prod nginx forwards bare host.
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

// URL returns full origin (scheme + host) for a subdomain, e.g. for links.
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

// loadDotEnv reads KEY=VALUE lines from ./.env → applies to process env,
// never overriding a var already set. No dependency; dev convenience only.
// Parse/merge split out (parseDotEnv/mergeEnv) → both unit-testable w/o real
// .env file or ambient env.
func loadDotEnv() {
	f, err := os.Open(".env")
	if err != nil {
		return
	}
	defer f.Close()
	mergeEnv(parseDotEnv(f))
}

// parseDotEnv parses KEY=VALUE lines from r into a map. Blank lines, "#"
// comments, lines w/o "=" skipped; key+value whitespace-trimmed (value may
// itself contain "="). Pure — no env access → directly unit-testable.
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

// mergeEnv sets each pair in process env, skipping keys already present →
// real env always wins over .env (and .env.prod layered on top in prod).
// Split from loadDotEnv so no-override rule is testable.
func mergeEnv(pairs map[string]string) {
	for k, v := range pairs {
		if _, exists := os.LookupEnv(k); !exists {
			os.Setenv(k, v)
		}
	}
}
