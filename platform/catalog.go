package platform

// ToolItem represents an individual tool inside a section.
type ToolItem struct {
	Key       string   `json:"key"`
	Name      string   `json:"name"`
	Path      string   `json:"path"`
	Subdomain string   `json:"subdomain"`
	ShortDesc string   `json:"short_desc"`
	Badges    []string `json:"badges"`
	Tech      []string `json:"tech"`
}

// ToolSection represents a category of tools in the navigation sidebar.
type ToolSection struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Subdomain string     `json:"subdomain"`
	Badge     string     `json:"badge"`
	Desc      string     `json:"desc"`
	Tools     []ToolItem `json:"tools"`
}

// Catalog returns the complete taxonomy of tools, categories, and technical tags.
func Catalog(cfg Config) []ToolSection {
	return defaultCatalog
}

var defaultCatalog = []ToolSection{
		{
			ID:        "cipher",
			Name:      "Cipher Tools",
			Subdomain: "cipher",
			Badge:     "13 tools",
			Desc:      "100% in-browser WebAssembly cryptography. Plaintext and keys never leave your device.",
			Tools: []ToolItem{
				{
					Key:       "encrypt",
					Name:      "Encrypt & Decrypt",
					Path:      "/encrypt",
					Subdomain: "cipher",
					ShortDesc: "Authenticated symmetric encryption and decryption with AAD",
					Badges:    []string{"AES-256-GCM", "ChaCha20"},
					Tech: []string{
						"AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305", "AES-256-CBC", "AES-128-CBC",
						"AEAD Auth", "Associated Data (AAD)", "PKCS#7 Padding", "Hex / Base64 Keys", "Random 96-bit Nonce", "WASM",
					},
				},
				{
					Key:       "jwt",
					Name:      "JWT Decoder & Signer",
					Path:      "/",
					Subdomain: "cipher",
					ShortDesc: "Decode, verify signature and sign JSON Web Tokens",
					Badges:    []string{"JWT", "EdDSA", "JWK"},
					Tech: []string{
						"JWT (RFC 7519)", "JWE (header)", "HS256..512", "RS256..512", "PS256..512",
						"ES256..512", "EdDSA (Ed25519)", "PEM", "JWK / JWKS", "Signature Verify",
						"Alg None Defense", "Sign Tokens",
					},
				},
				{
					Key:       "hash",
					Name:      "Hash & Checksums",
					Path:      "/hash",
					Subdomain: "cipher",
					ShortDesc: "Simultaneous multi-hash calculation and checksum matcher",
					Badges:    []string{"SHA-256", "BLAKE2", "MD5"},
					Tech: []string{
						"SHA-256", "SHA-512", "SHA-3 (256/512)", "BLAKE2b", "BLAKE2s", "Keccak-256",
						"MD5", "SHA-1", "CRC32 (IEEE)", "CRC32C", "Adler-32", "Checksum Matcher",
						"File Hashing", "BOM / CRLF Detect", "Hex & Base64",
					},
				},
				{
					Key:       "password",
					Name:      "Password Hasher",
					Path:      "/password",
					Subdomain: "cipher",
					ShortDesc: "Password hash generator & verifier with cost tuning",
					Badges:    []string{"Argon2id", "bcrypt"},
					Tech: []string{
						"Argon2id (RFC 9106)", "Argon2i", "bcrypt (Blowfish)", "scrypt (RFC 7914)",
						"PBKDF2", "Cost Tuning", "Memory Cost", "Salt Audit", "Verify Hash", "72-byte Limit Warn",
					},
				},
				{
					Key:       "hmac",
					Name:      "HMAC & Webhooks",
					Path:      "/hmac",
					Subdomain: "cipher",
					ShortDesc: "HMAC generator & webhook constant-time signature validator",
					Badges:    []string{"HMAC", "Webhooks"},
					Tech: []string{
						"HMAC-SHA256", "HMAC-SHA512", "HMAC-SHA3", "HMAC-MD5", "GitHub Webhooks",
						"Stripe Webhooks", "Slack Webhooks", "Constant-Time Verify", "Secret Key (UTF-8/Hex/B64)",
					},
				},
				{
					Key:       "keys",
					Name:      "Keys Converter",
					Path:      "/keys",
					Subdomain: "cipher",
					ShortDesc: "Keypair generator & PEM / JWK / OpenSSH converter",
					Badges:    []string{"Ed25519", "RSA", "ECDSA"},
					Tech: []string{
						"RSA (2048-4096)", "ECDSA (P-256/384/521)", "Ed25519", "PKCS#8", "PKCS#1",
						"SEC 1", "SPKI", "JWK (RFC 7517)", "OpenSSH Keys", "RFC 7638 Thumbprint", "SSH SHA256 Fingerprint",
					},
				},
				{
					Key:       "cert",
					Name:      "Certificates (X.509)",
					Path:      "/cert",
					Subdomain: "cipher",
					ShortDesc: "X.509 certificate & CSR decoder and chain verifier",
					Badges:    []string{"X.509", "CSR"},
					Tech: []string{
						"X.509 v3", "PEM / DER", "CSR (PKCS#10)", "SANs (DNS, IP)", "Chain Order Check",
						"Issuer Signatures", "Key Matching Test", "EKU / Key Usage", "Expiry Countdown", "SHA-256 Fingerprints",
					},
				},
				{
					Key:       "totp",
					Name:      "TOTP / 2FA Authenticator",
					Path:      "/totp",
					Subdomain: "cipher",
					ShortDesc: "TOTP / HOTP 2FA code generator & otpauth:// reader",
					Badges:    []string{"RFC 6238", "2FA"},
					Tech: []string{
						"RFC 6238 (TOTP)", "RFC 4226 (HOTP)", "otpauth:// URIs", "Base32 Secrets",
						"SHA-1 / SHA-256 / SHA-512", "6 / 7 / 8 Digits", "Live Countdown Bar", "Clock Skew Check (±1)", "QR Code",
					},
				},
				{
					Key:       "random",
					Name:      "Random & UUID",
					Path:      "/random",
					Subdomain: "cipher",
					ShortDesc: "Cryptographic random tokens, passwords & UUID v4/v7 generator",
					Badges:    []string{"UUIDv4/v7", "Passphrase"},
					Tech: []string{
						"UUID v4 (Random)", "UUID v7 (Timestamp-Ordered)", "crypto/rand", "Hex Tokens",
						"Base64url Tokens", "High-Entropy Passwords", "Custom Charsets", "Zero Modulo Bias", "Shannon Entropy",
					},
				},
				{
					Key:       "encode",
					Name:      "Encode / Decode",
					Path:      "/encode",
					Subdomain: "cipher",
					ShortDesc: "Base64, Hex, Base32 and Basic Auth converter",
					Badges:    []string{"Base64", "Hex", "Base32"},
					Tech: []string{
						"Base64 (RFC 4648)", "Base64URL", "Hex / 0x", "Base32", "Base32Hex",
						"UTF-8 Text", "HTTP Basic Auth", "Byte Offset Error Pointer",
					},
				},
				{
					Key:       "identify",
					Name:      "Magic String Identifier",
					Path:      "/identify",
					Subdomain: "cipher",
					ShortDesc: "Hash and token type identifier with hashcat modes",
					Badges:    []string{"Hash detector", "Hashcat"},
					Tech: []string{
						"Hashcat Modes (0, 100, 1400, 3200...)", "50+ Hash Types", "JWT / JWE",
						"PEM Keys & Certs", "OpenSSH Keys", "UUID Detection", "Ranked Candidates", "Cross-Tool Links",
					},
				},
				{
					Key:       "dpop",
					Name:      "DPoP Proofs",
					Path:      "/dpop",
					Subdomain: "cipher",
					ShortDesc: "RFC 9449 DPoP Proof Generator & Verifier for OAuth 2.0",
					Badges:    []string{"RFC 9449", "OAuth 2.0"},
					Tech: []string{
						"RFC 9449", "OAuth 2.0 Token Binding", "ES256 (P-256)", "RS256", "EdDSA",
						"Proof Generation", "Signature Verification", "htm / htu / ath / nonce Claims", "Embedded JWK Header",
					},
				},
				{
					Key:       "pkce",
					Name:      "PKCE Generator",
					Path:      "/pkce",
					Subdomain: "cipher",
					ShortDesc: "RFC 7636 PKCE Generator & Verifier for OAuth 2.0",
					Badges:    []string{"RFC 7636", "S256"},
					Tech: []string{
						"RFC 7636", "OAuth 2.0 PKCE", "code_verifier (43-128 chars)", "code_challenge",
						"S256 (SHA-256 Base64URL)", "Plain Challenge", "Challenge Verification",
					},
				},
			},
		},
		{
			ID:        "ip",
			Name:      "IP Tools",
			Subdomain: "ip",
			Badge:     "3 tools",
			Desc:      "IP geolocation, network ASN, proxy/VPN threat detection and subnet math",
			Tools: []ToolItem{
				{
					Key:       "lookup",
					Name:      "IP lookup & Threat Intel",
					Path:      "/",
					Subdomain: "ip",
					ShortDesc: "IP Geolocation, Network ASN & Proxy/VPN Threat Detector",
					Badges:    []string{"GeoIP", "ASN", "Proxy"},
					Tech: []string{
						"GeoIP (City, Country, Coords)", "Timezone", "ASN & ISP", "IP2Location DB11",
						"IP2Proxy PX12", "VPN / Proxy / Tor / DCH", "DROP / EDROP IP threat lists",
						"IPsum Abuse Score (1-8)", "Shodan Open Ports & CVEs", "Live IPv6 Browser Probe",
					},
				},
				{
					Key:       "cidr",
					Name:      "Subnet Calculator",
					Path:      "/cidr",
					Subdomain: "ip",
					ShortDesc: "CIDR Subnet Mask and IP Range Calculator",
					Badges:    []string{"CIDR", "IPv4/IPv6"},
					Tech: []string{
						"IPv4 & IPv6 CIDR", "Network Address", "Broadcast Address", "Netmask (Dotted & Hex)",
						"Wildcard Mask", "Usable Host Range", "Host Count Calculation", "RFC 3021 /31 Subnets", "Binary Representation",
					},
				},
				{
					Key:       "history",
					Name:      "Lookup History",
					Path:      "/history",
					Subdomain: "ip",
					ShortDesc: "Recent IP Lookup History",
					Badges:    []string{"Audit history"},
					Tech: []string{
						"Recent Searches", "Saved IPs", "Quick Pivot Links", "Local Audit History",
					},
				},
			},
		},
		{
			ID:        "botcheck",
			Name:      "Bot Check",
			Subdomain: "botcheck",
			Badge:     "1 tool",
			Desc:      "Transparent browser fingerprinting and automated bot detection audit",
			Tools: []ToolItem{
				{
					Key:       "botcheck",
					Name:      "Browser Fingerprint & Bot Score",
					Path:      "/",
					Subdomain: "botcheck",
					ShortDesc: "Score browser signals against bots, automation and proxies",
					Badges:    []string{"Fingerprint", "Score"},
					Tech: []string{
						"Human vs Bot Score (0-100)", "navigator.webdriver", "Headless Chrome / Puppeteer / Playwright",
						"Canvas 2D Fingerprint", "WebGL Vendor & Renderer", "AudioContext Oscillator",
						"Chrome Runtime Anomalies", "Screen / Window Dimension Check", "HTTP Request Header Ordering",
						"Client Hints (Sec-CH-UA)", "Datacenter ASN Cross-Check",
					},
				},
			},
		},
		{
			ID:        "dns",
			Name:      "DNS Tools",
			Subdomain: "dns",
			Badge:     "4 tools",
			Desc:      "Parallel DNS lookup, consistency propagation, DNSSEC root trace and domain RDAP",
			Tools: []ToolItem{
				{
					Key:       "lookup",
					Name:      "All DNS Records",
					Path:      "/",
					Subdomain: "dns",
					ShortDesc: "Full DNS Record Lookup across Cloudflare, Google and Quad9",
					Badges:    []string{"9 records", "PTR"},
					Tech: []string{
						"A & AAAA", "CNAME", "MX & Priority", "NS", "TXT & SPF", "SOA",
						"CAA", "HTTPS / SVCB", "PTR (Reverse DNS)", "Cloudflare / Google / Quad9",
						"TTL & Rcode", "Authoritative Flags (AA, RD)", "Query Latency (ms)",
					},
				},
				{
					Key:       "consistency",
					Name:      "Global Propagation",
					Path:      "/consistency",
					Subdomain: "dns",
					ShortDesc: "DNS Propagation & Consistency Checker against zone NS and public resolvers",
					Badges:    []string{"Nameservers", "Sync"},
					Tech: []string{
						"Authoritative NS Direct Queries", "Recursion Disabled (rd=0)", "Public Resolvers Comparison",
						"Cloudflare / Google / Quad9 / OpenDNS", "Propagation Health", "Serial Number Sync",
					},
				},
				{
					Key:       "trace",
					Name:      "Root DNS Trace",
					Path:      "/trace",
					Subdomain: "dns",
					ShortDesc: "Iterative Root DNS Delegation Trace & DNSSEC Validator",
					Badges:    []string{"DNSSEC", "Root walk"},
					Tech: []string{
						"Root Servers (.)", "TLD Nameservers", "Authoritative Nameservers", "Iterative Delegation Walk",
						"DNSSEC Chain Validation", "DS Digests Check", "RRSIG Signatures", "DNSKEY Verification",
					},
				},
				{
					Key:       "domain",
					Name:      "Domain & Certificates",
					Path:      "/domain",
					Subdomain: "dns",
					ShortDesc: "Domain Registration (RDAP) & Certificate Transparency Discovery",
					Badges:    []string{"RDAP", "crt.sh"},
					Tech: []string{
						"RDAP (RFC 7484)", "WHOIS Registrar & Dates", "Expiry Tracking",
						"Nameservers", "Domain Status Codes", "crt.sh Certificate Transparency", "Subdomain Discovery (up to 200)",
					},
				},
			},
		},
		{
			ID:        "link",
			Name:      "Link Tools",
			Subdomain: "link",
			Badge:     "9 tools",
			Desc:      "URL inspection, tracker stripping, redirect tracing and HTTP caching headers",
			Tools: []ToolItem{
				{
					Key:       "inspect",
					Name:      "URL Inspector & Sanitizer",
					Path:      "/",
					Subdomain: "link",
					ShortDesc: "Complete URL Anatomy Inspector, Tracker Stripper & SafeLinks Unwrapper",
					Badges:    []string{"All-in-One", "Trackers", "SafeLinks"},
					Tech: []string{
						"Tracking Parameter Stripper (UTM, fbclid, gclid)", "SafeLinks & Proofpoint Unwrap",
						"Scheme / Host / Port / Path", "Query & Fragment Parameter Breakdown",
						"Nested URL Unwrapping", "Punycode & Unicode Host", "Parameter Order Preservation",
					},
				},
				{
					Key:       "trace",
					Name:      "Redirect Tracer",
					Path:      "/trace",
					Subdomain: "link",
					ShortDesc: "HTTP Redirect Chain Hop-by-Hop Tracer",
					Badges:    []string{"Redirects", "HSTS"},
					Tech: []string{
						"301 / 302 / 303 / 307 / 308", "Meta Refresh & JS Redirects", "Hop Latency (ms)",
						"Set-Cookie Inspection", "Canonical Destination", "User-Agent Personas (Googlebot, Slackbot, cURL)", "SSRF Egress Guard",
					},
				},
				{
					Key:       "headers",
					Name:      "HTTP Headers & Cache",
					Path:      "/headers",
					Subdomain: "link",
					ShortDesc: "HTTP Response Headers, Cache-Control & Security Posture",
					Badges:    []string{"RFC 9111", "Security"},
					Tech: []string{
						"RFC 9111 Cache-Control", "max-age & s-maxage", "stale-while-revalidate", "stale-if-error", "immutable",
						"Browser vs CDN TTL Disparity", "ETag & Last-Modified", "Content-Security-Policy (CSP)",
						"HSTS & Preload", "COOP / COEP / CORP", "X-Frame-Options", "Referrer-Policy", "Secure / SameSite Cookies",
					},
				},
				{
					Key:       "diff",
					Name:      "URL Parameter Diff",
					Path:      "/diff",
					Subdomain: "link",
					ShortDesc: "URL Parameter & Value Comparator",
					Badges:    []string{"URL compare"},
					Tech: []string{
						"Side-by-Side Parameter Comparison", "Added Parameters", "Removed Parameters",
						"Modified Values", "Moved Parameters", "Staging vs Prod Debugger",
					},
				},
				{
					Key:       "extract",
					Name:      "Link Extractor",
					Path:      "/extract",
					Subdomain: "link",
					ShortDesc: "Bulk URL Extractor from Text",
					Badges:    []string{"Link extractor"},
					Tech: []string{
						"Bulk URL Harvester", "Regex Link Parser", "Markdown & HTML Text", "Deduplication", "Domain Grouping",
					},
				},
				{
					Key:       "utm",
					Name:      "UTM Builder",
					Path:      "/utm",
					Subdomain: "link",
					ShortDesc: "Campaign UTM Parameter Builder",
					Badges:    []string{"Campaign builder"},
					Tech: []string{
						"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "Whitespace Trimming", "Parameter Sorting",
					},
				},
				{
					Key:       "curl",
					Name:      "cURL Converter",
					Path:      "/curl",
					Subdomain: "link",
					ShortDesc: "URL to cURL & Request Syntax Builder",
					Badges:    []string{"cURL builder"},
					Tech: []string{
						"URL to cURL Command", "cURL to Request Parameters", "Headers & Cookies Flags (-H, -b)", "Method (-X)", "Data Payloads (-d)",
					},
				},
				{
					Key:       "encode",
					Name:      "URL Percent Encoding & RFC 3986",
					Path:      "/encode",
					Subdomain: "link",
					ShortDesc: "Percent-Encoding Converter & RFC 3986 Reserved Characters Reference",
					Badges:    []string{"RFC 3986", "Encoder"},
					Tech: []string{
						"RFC 3986 Percent-Encoding", "Path vs Query vs Fragment Rules", "+ vs %20 Space Encoding", "Reserved & Unreserved Characters", "Base64 / Base64URL", "HTML Entities",
					},
				},
				{
					Key:       "short",
					Name:      "Link Shortener",
					Path:      "/short",
					Subdomain: "link",
					ShortDesc: "Domain-Scoped Link Shortener",
					Badges:    []string{"Short links"},
					Tech: []string{
						"Domain-Scoped Short Links (/s/:code)", "Custom Slugs", "TTL Auto-Expiry", "Clean Tracking on Shorten", "Hit Counters",
					},
				},
			},
		},
		{
			ID:        "mail",
			Name:      "Mail Tools",
			Subdomain: "mail",
			Badge:     "4 tools",
			Desc:      "Enterprise email deliverability, security architecture, SEG identification, and sender reputation intelligence.",
			Tools: []ToolItem{
				{
					Key:       "health",
					Name:      "Domain & Email Intelligence",
					Path:      "/",
					Subdomain: "mail",
					ShortDesc: "All-in-one deliverability, SEG gateway, disposable detection & blacklist audit",
					Badges:    []string{"All-in-One", "SEG & MX", "Anti-Abuse"},
					Tech: []string{
						"Disposable & Burner Detection", "Free vs Corporate Classifier",
						"Proofpoint, Microsoft Defender, Google SEGs", "Direct-to-MX Bypass Detection",
						"Deep SPF 10-Lookup Tree Expansion", "DKIM Selectors Discovery", "MTA-STS & TLSRPT (RFC 8461/8460)",
						"BIMI & VMC Verification", "15+ DNSBL Multi-Blacklist Audit", "SPF / DMARC Deliverability Scoring",
					},
				},
				{
					Key:       "dmarc",
					Name:      "DMARC Report Visualizer",
					Path:      "/dmarc",
					Subdomain: "mail",
					ShortDesc: "DMARC Aggregate XML/GZ Report Visualizer",
					Badges:    []string{"DMARC RUA", "XML/GZ"},
					Tech: []string{
						"RFC 7489 (DMARC RUA)", ".xml and .xml.gz Upload", "Raw XML Paste",
						"SPF / DKIM Alignment Matrix", "Pass / Fail Policy Disposition", "Sending Source IPs",
						"ESP Auto-Classification (Google, M365, Amazon SES, SendGrid)", "Zero-Knowledge (In-Memory)",
					},
				},
				{
					Key:       "bimi",
					Name:      "BIMI & VMC Validator",
					Path:      "/bimi",
					Subdomain: "mail",
					ShortDesc: "BIMI SVG Tiny P/S & Verified Mark Certificate Validator",
					Badges:    []string{"SVG Tiny P/S", "VMC Certs"},
					Tech: []string{
						"BIMI (Brand Indicators)", "SVG Tiny Portable/Secure (Tiny P/S)", "Verified Mark Certificate (VMC)",
						"DigiCert, GlobalSign & SSL.com MVA Trust", "RFC 3709 Logotype", "Auto-Fix to Valid SVG Tiny 1.2",
					},
				},
				{
					Key:       "arc",
					Name:      "ARC Trace Analyzer",
					Path:      "/arc",
					Subdomain: "mail",
					ShortDesc: "Authenticated Received Chain (ARC) Header Analyzer",
					Badges:    []string{"RFC 8617", "Seals"},
					Tech: []string{
						"RFC 8617 (ARC)", "Authenticated Received Chain", "ARC-Seal (AS)",
						"ARC-Message-Signature (AMS)", "ARC-Authentication-Results (AAR)",
						"Multi-Hop Forwarding Audit", "Sequence Validation (i=1..N)", "Seal Integrity Check",
					},
				},
			},
		},
		{
			ID:        "mcp",
			Name:      "MCP Server",
			Subdomain: "mcp",
			Badge:     "1 gateway",
			Desc:      "Model Context Protocol endpoints for Claude, Cursor, and AI agents",
			Tools: []ToolItem{
				{
					Key:       "gateway",
					Name:      "AI Agent MCP Gateway",
					Path:      "/",
					Subdomain: "mcp",
					ShortDesc: "Model Context Protocol (MCP) Server for AI Agents",
					Badges:    []string{"JSON-RPC", "AI agents"},
					Tech: []string{
						"Model Context Protocol (MCP)", "Claude Desktop", "Cursor IDE", "VS Code",
						"OpenAI / ChatGPT", "Codex CLI", "Gemini CLI", "Zero-Key / Free Access", "Streaming JSON-RPC",
					},
				},
			},
		},
	}
