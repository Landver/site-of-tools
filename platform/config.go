package platform

import (
	"bufio"
	"cmp"
	"io"
	"os"
	"strings"
)

// Config is all runtime config, read from env vars; dev loads the repo-root .env first.
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

	// Shodan InternetDB base URL (free, keyless open-port lookups); blank disables enrichment.
	ShodanURL string

	// RDAP bootstrap + Certificate Transparency endpoints for the DNS tool; blank disables that lookup.
	RDAPURL  string
	CrtShURL string

	// LinkAPIKey is fail-closed: empty disables link creation, since an open shortener gets blocklisted.
	LinkAPIKey string

	// MCPOwnerKey gates /mcp/owner; apart from LinkAPIKey so each rotates alone.
	MCPOwnerKey string

	// MongoURI is optional: empty disables lookup history and the request log, and the app still boots.
	MongoURI      string
	MongoDatabase string

	// EgressDenyAddrs: the host's public IPs, invisible to net.InterfaceAddrs in a container.
	EgressDenyAddrs []string
}

// Load reads config from env (after loading .env if present).
func Load() Config {
	loadDotEnv()
	return Config{
		Env:             getenv("APP_ENV", "dev"),
		ListenAddr:      getenv("LISTEN_ADDR", ":8080"),
		BaseDomain:      getenv("BASE_DOMAIN", "localhost"),
		DB11V4:          os.Getenv("IP2LOCATION_DB11_V4"),
		DB11V6:          os.Getenv("IP2LOCATION_DB11_V6"),
		ASNV4:           os.Getenv("IP2LOCATION_ASN_V4"),
		ASNV6:           os.Getenv("IP2LOCATION_ASN_V6"),
		PX12:            os.Getenv("IP2PROXY_PX12"),
		ShodanURL:       getenv("SHODAN_INTERNETDB_URL", "https://internetdb.shodan.io"),
		RDAPURL:         getenv("RDAP_URL", "https://rdap.org"),
		CrtShURL:        getenv("CRTSH_URL", "https://crt.sh"),
		LinkAPIKey:      os.Getenv("LINK_API_KEY"),
		MongoURI:        os.Getenv("MONGODB_URI"),
		MongoDatabase:   getenv("MONGODB_DATABASE", DefaultMongoDatabase),
		EgressDenyAddrs: splitList(os.Getenv("EGRESS_DENY_ADDRS")),
		MCPOwnerKey:     os.Getenv("MCP_OWNER_KEY"),
	}
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (c Config) IsDev() bool { return c.Env != "prod" }

// VHost builds the echo.NewVirtualHostHandler key ("" = apex); dev Host headers carry the port, prod's don't.
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

// URL returns the subdomain's full origin (scheme + host).
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

// loadDotEnv applies ./.env to the process env; a dev convenience.
func loadDotEnv() {
	f, err := os.Open(".env")
	if err != nil {
		return
	}
	defer f.Close()
	mergeEnv(parseDotEnv(f))
}

// parseDotEnv skips blank lines, "#" comments and lines without "="; a value may itself contain "=".
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

// mergeEnv skips keys already set, so the real env (and .env.prod in prod) always wins over .env.
func mergeEnv(pairs map[string]string) {
	for k, v := range pairs {
		if _, exists := os.LookupEnv(k); !exists {
			os.Setenv(k, v)
		}
	}
}
