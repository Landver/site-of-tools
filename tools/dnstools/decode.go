package dnstools

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Decoding turns record values that are packed tuples or opaque conventions
// into something readable, without hiding the raw value.
//
// Three features from the inventory live here, all pure static data, no API:
//   - SOA timers decoded and humanised (a bare "10000 2400 604800 1800" is
//     unreadable, and its last field is why a fixed record still says NXDOMAIN)
//   - TXT strings labelled by their well-known prefix, so a wall of
//     verification tokens reads as the integrations it actually is
//   - the DNS provider named from the nameserver suffix

// caaForbids: what an empty issuer-domain-name means, per issuer property.
// Only these three properties carry one; iodef and the contact tags do not.
var caaForbids = map[string]string{
	"issue":     "no CA may issue certificates for this name",
	"issuewild": "no CA may issue wildcard certificates for this name",
	"issuemail": "no CA may issue S/MIME certificates for this name",
}

// caaFields decodes a CAA record: which certificate authorities may issue for
// this name, and where to report violations. Raw it is `0 issue "x"`, which
// reads as noise.
func caaFields(c *dns.CAA) []Field {
	tag := strings.ToLower(c.Tag)
	label := map[string]string{
		"issue":                "May issue certificates",
		"issuewild":            "May issue wildcards",
		"issuemail":            "May issue S/MIME certificates",
		"iodef":                "Report violations to",
		"contactemail":         "Contact",
		"contactphone":         "Contact",
		"cansignhttpexchanges": "May sign HTTP exchanges",
	}[tag]
	if label == "" {
		label = c.Tag
	}
	f := []Field{{label, c.Value}}
	// An issuer property whose issuer-domain-name is empty authorises nobody
	// (RFC 8659 §4.2/§4.3), and `;` is how zones write that. Printing it under
	// "May issue" states the exact opposite of what was published.
	if forbids, ok := caaForbids[tag]; ok {
		if issuer, _, _ := strings.Cut(c.Value, ";"); strings.TrimSpace(issuer) == "" {
			f = []Field{{"Certificates", forbids}}
		}
	}
	// The critical flag means a CA that doesn't understand this tag must
	// refuse to issue at all, so it's worth surfacing.
	if c.Flag != 0 {
		f = append(f, Field{"Flag", fmt.Sprintf("%d (critical)", c.Flag)})
	}
	return f
}

// svcbFields decodes the SvcParams of an HTTPS/SVCB record (RFC 9460): which
// protocols the host speaks, the addresses to skip an A lookup with, and
// whether Encrypted Client Hello is published.
//
// The corpus rates a full SvcParam decode as something nothing on the shelf
// does, and the ECH parameter in particular as decoded by literally nobody.
func svcbFields(rr dns.RR) []Field {
	var (
		priority uint16
		target   string
		params   []dns.SVCBKeyValue
	)
	switch v := rr.(type) {
	case *dns.HTTPS:
		priority, target, params = v.Priority, v.Target, v.Value
	case *dns.SVCB:
		priority, target, params = v.Priority, v.Target, v.Value
	default:
		return nil
	}

	var f []Field
	// Priority 0 is AliasMode: this record just points at another name, the
	// modern way to do a CNAME at the apex.
	if priority == 0 {
		return []Field{{"Mode", "alias, pointing at " + strings.TrimSuffix(target, ".")}}
	}
	f = append(f, Field{"Priority", fmt.Sprint(priority)})

	for _, p := range params {
		val := p.String()
		switch p.Key() {
		case dns.SVCB_ALPN:
			f = append(f, Field{"Protocols", humanALPN(val)})
		case dns.SVCB_PORT:
			f = append(f, Field{"Port", val})
		case dns.SVCB_IPV4HINT:
			f = append(f, Field{"IPv4 hint", val})
		case dns.SVCB_IPV6HINT:
			f = append(f, Field{"IPv6 hint", val})
		case dns.SVCB_ECHCONFIG:
			// The presentation form is base64, so its length is not a byte
			// count; the parsed value carries the real config. An empty one
			// publishes no keys, so it must not claim the SNI is encrypted.
			var n int
			if e, ok := p.(*dns.SVCBECHConfig); ok {
				n = len(e.ECH)
			}
			if n == 0 {
				f = append(f, Field{"ECH", "parameter present but empty, so no ECH keys are published"})
				break
			}
			f = append(f, Field{"ECH", fmt.Sprintf("published (%d bytes) — the TLS SNI is encrypted, so which site you visit isn't visible on the wire", n)})
		case dns.SVCB_NO_DEFAULT_ALPN:
			f = append(f, Field{"Default ALPN", "disabled"})
		default:
			f = append(f, Field{p.Key().String(), val})
		}
	}
	return f
}

// humanALPN turns "h3,h2" into something a non-specialist can read.
func humanALPN(v string) string {
	names := map[string]string{
		"h3": "HTTP/3", "h2": "HTTP/2", "http/1.1": "HTTP/1.1",
		"h3-29": "HTTP/3 (draft 29)", "dot": "DNS-over-TLS",
	}
	var out []string
	for _, a := range strings.Split(v, ",") {
		a = strings.TrimSpace(a)
		if n, ok := names[a]; ok {
			out = append(out, n)
		} else if a != "" {
			out = append(out, a)
		}
	}
	return strings.Join(out, ", ")
}

// soaFields decodes a SOA into its named parts. The numbers are the reason
// "why is my change not live yet" has an answer, so each gets a human duration.
func soaFields(s *dns.SOA) []Field {
	return []Field{
		{"Primary NS", s.Ns},
		// RNAME is an email with the first dot standing in for "@".
		{"Hostmaster", mboxEmail(s.Mbox)},
		{"Serial", fmt.Sprint(s.Serial)},
		{"Refresh", humanizeTTL(s.Refresh)},
		{"Retry", humanizeTTL(s.Retry)},
		{"Expire", humanizeTTL(s.Expire)},
		// The one people actually need: how long a "doesn't exist" is cached.
		{"Negative TTL", humanizeTTL(s.Minttl)},
	}
}

// mboxEmail turns a SOA RNAME (dns.cloudflare.com.) into the address it
// encodes (dns@cloudflare.com), which is what the field is for.
//
// A dot belonging to the local part travels escaped (first\.last.example.com.),
// so the "@" is the first dot that is not itself escaped — splitting on the
// first literal dot produces an address nobody can write to.
func mboxEmail(mbox string) string {
	m := strings.TrimSuffix(mbox, ".")
	for i := 0; i < len(m); i++ {
		switch m[i] {
		case '\\':
			i++
		case '.':
			if i == 0 {
				return m
			}
			return unescapeDots(m[:i]) + "@" + m[i+1:]
		}
	}
	return unescapeDots(m)
}

// unescapeDots strips the backslashes that kept a dot inside one label.
func unescapeDots(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// txtLabels maps a TXT prefix to what that record is actually for. Pure data:
// no lookup, no API, and it turns an unreadable apex into a list of the
// services a domain is wired into.
var txtLabels = []struct{ prefix, label string }{
	{"v=spf1", "SPF — which servers may send mail"},
	{"v=DMARC1", "DMARC — what to do with failing mail"},
	{"v=BIMI1", "BIMI — brand logo in inboxes"},
	{"v=STSv1", "MTA-STS — enforced mail transport security"},
	{"v=TLSRPTv1", "TLS-RPT — where to send TLS reports"},
	{"v=DKIM1", "DKIM — mail signing key"},
	{"google-site-verification=", "Google — site ownership"},
	{"MS=", "Microsoft — domain ownership"},
	{"ms-domain-verification=", "Microsoft — domain ownership"},
	{"apple-domain-verification=", "Apple — domain ownership"},
	{"atlassian-domain-verification=", "Atlassian — domain ownership"},
	{"facebook-domain-verification=", "Meta — domain ownership"},
	{"docusign=", "DocuSign"},
	{"stripe-verification=", "Stripe"},
	{"adobe-idp-site-verification=", "Adobe"},
	{"canva-site-verification=", "Canva"},
	{"zoom-domain-verification=", "Zoom"},
	{"ZOOM_verify_", "Zoom"},
	{"slack-domain-verification=", "Slack"},
	{"notion-domain-verification=", "Notion"},
	{"linkedin-site-verification=", "LinkedIn"},
	{"shopify-site-verification=", "Shopify"},
	{"tailscale-domain-verification=", "Tailscale"},
	{"TAILSCALE-", "Tailscale"},
	{"anthropic-domain-verification=", "Anthropic"},
	{"openai-domain-verification=", "OpenAI"},
	{"brevo-code:", "Brevo"},
	{"sendinblue-site-verification=", "Brevo (Sendinblue)"},
	{"trustpilot-", "Trustpilot"},
	{"calendly-site-verification=", "Calendly"},
	{"cursor-domain-verification=", "Cursor"},
	{"status-page-domain-verification=", "Atlassian Statuspage"},
	{"_globalsign-domain-verification=", "GlobalSign"},
	{"have-i-been-pwned-verification=", "Have I Been Pwned"},
	{"asv=", "Apple (ASV)"},
	{"docker-verification=", "Docker"},
}

// txtLabel names a TXT record's purpose from its prefix. Case-insensitive on
// the marker, because publishers are inconsistent about it.
func txtLabel(v string) string {
	t := strings.TrimSpace(strings.Trim(v, `"`))
	for _, l := range txtLabels {
		if len(t) >= len(l.prefix) && strings.EqualFold(t[:len(l.prefix)], l.prefix) {
			return l.label
		}
	}
	if strings.Contains(t, "-verification") {
		return "Domain ownership proof"
	}
	return ""
}

// providers maps a nameserver suffix to the DNS provider running the zone.
// Answers "who do I log into to change this", which is the first thing anyone
// needs and which no amount of raw records tells them.
var providers = []struct{ suffix, name string }{
	{"cloudflare.com", "Cloudflare"},
	{"awsdns", "AWS Route 53"},
	{"azure-dns", "Azure DNS"},
	{"ns-cloud", "Google Cloud DNS"},
	{"googledomains.com", "Google Domains"},
	{"nsone.net", "NS1"},
	{"dnsimple.com", "DNSimple"},
	{"digitalocean.com", "DigitalOcean"},
	{"vercel-dns.com", "Vercel"},
	{"netlify.com", "Netlify"},
	{"netlifydns.com", "Netlify"},
	{"fastly.net", "Fastly"},
	{"akam.net", "Akamai"},
	{"ultradns", "UltraDNS"},
	{"dnsmadeeasy.com", "DNS Made Easy"},
	{"name-services.com", "Enom"},
	{"namecheaphosting.com", "Namecheap"},
	{"registrar-servers.com", "Namecheap"},
	{"domaincontrol.com", "GoDaddy"},
	{"gandi.net", "Gandi"},
	{"hover.com", "Hover"},
	{"your-server.de", "Hetzner"},
	{"second-ns.de", "Hetzner"},
	{"ovh.net", "OVH"},
	{"hetzner.com", "Hetzner"},
	{"porkbun.com", "Porkbun"},
	{"bunny.net", "Bunny CDN"},
	{"wixdns.net", "Wix"},
	{"squarespacedns.com", "Squarespace"},
	{"shopifydns.com", "Shopify"},
}

// providerOf names the DNS provider from a zone's nameservers. Empty when the
// suffix isn't one we know, which is honest: better blank than a wrong guess.
//
// The answer is the operator most of the nameservers belong to, not whichever
// record came back first: a zone delegated to three Netlify servers and one
// legacy NS1 one is logged into at Netlify.
func providerOf(records []Record) string {
	seen := map[string]int{}
	best, bestN := "", 0
	for _, r := range records {
		if r.Type != "NS" {
			continue
		}
		ns := strings.ToLower(strings.TrimSuffix(r.Value, "."))
		for _, p := range providers {
			if !strings.Contains(ns, p.suffix) {
				continue
			}
			seen[p.name]++
			if seen[p.name] > bestN {
				best, bestN = p.name, seen[p.name]
			}
			break
		}
	}
	return best
}
