package dnstools

import (
	"fmt"
	"slices"
	"strings"

	"github.com/miekg/dns"
)

// caaForbids: what an empty issuer means, for the three properties that take one.
var caaForbids = map[string]string{
	"issue":     "no CA may issue certificates for this name",
	"issuewild": "no CA may issue wildcard certificates for this name",
	"issuemail": "no CA may issue S/MIME certificates for this name",
}

// caaFields decodes a CAA record: who may issue for this name, and where to report violations.
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
	// An empty issuer (`;`) authorises nobody (RFC 8659 §4.2/§4.3); "May issue" would invert it.
	if forbids, ok := caaForbids[tag]; ok {
		if issuer, _, _ := strings.Cut(c.Value, ";"); strings.TrimSpace(issuer) == "" {
			f = []Field{{"Certificates", forbids}}
		}
	}
	// Only bit 0 (0x80) is Issuer Critical (RFC 8659 §4.1); other bits are undefined, so no verdict.
	switch {
	case c.Flag&0x80 != 0:
		f = append(f, Field{"Flag", fmt.Sprintf("%d (critical)", c.Flag)})
	case c.Flag != 0:
		f = append(f, Field{"Flag", fmt.Sprint(c.Flag)})
	}
	return f
}

// svcbFields decodes an HTTPS/SVCB record's SvcParams (RFC 9460), ECH included.
func svcbFields(rr dns.RR) []Field {
	var s *dns.SVCB
	switch v := rr.(type) {
	case *dns.HTTPS:
		s = &v.SVCB
	case *dns.SVCB:
		s = v
	default:
		return nil
	}

	target := strings.TrimSuffix(s.Target, ".")
	// Priority 0 is AliasMode; a root target there means "not available here" (RFC 9460 §2.4.2).
	if s.Priority == 0 {
		if target == "" {
			return []Field{{"Mode", "alias with a root target: this service is explicitly not available here"}}
		}
		return []Field{{"Mode", "alias, pointing at " + target}}
	}
	f := []Field{{"Priority", fmt.Sprint(s.Priority)}}
	// A root target is the owner name itself (RFC 9460 §2.5), so there is nothing to add.
	if target != "" {
		f = append(f, Field{"Endpoint", target})
	}

	for _, p := range s.Value {
		val := p.String()
		switch p.Key() {
		case dns.SVCB_ALPN:
			f = append(f, Field{"Protocols", humanALPN(val)})
		case dns.SVCB_PORT:
			f = append(f, Field{"Port", val})
		// A space after each comma lets a long hint list wrap between addresses.
		case dns.SVCB_IPV4HINT:
			f = append(f, Field{"IPv4 hint", strings.ReplaceAll(val, ",", ", ")})
		case dns.SVCB_IPV6HINT:
			f = append(f, Field{"IPv6 hint", strings.ReplaceAll(val, ",", ", ")})
		case dns.SVCB_ECHCONFIG:
			// The base64 length isn't a byte count; an empty config publishes no keys.
			var n int
			if e, ok := p.(*dns.SVCBECHConfig); ok {
				n = len(e.ECH)
			}
			if n == 0 {
				f = append(f, Field{"ECH", "parameter present but empty, so no ECH keys are published"})
				break
			}
			f = append(f, Field{"ECH", fmt.Sprintf("published (%d bytes): browsers that support ECH can hide which site they're visiting from the network", n)})
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

// soaFields decodes a SOA into named parts, each timer as a human duration.
func soaFields(s *dns.SOA) []Field {
	f := []Field{{"Primary NS", s.Ns}}
	// A root RNAME encodes no address, so the row is left out rather than shown empty.
	if m := mboxEmail(s.Mbox); m != "" {
		f = append(f, Field{"Hostmaster", m})
	}
	f = append(f, []Field{
		{"Serial", fmt.Sprint(s.Serial)},
		{"Refresh", humanizeTTL(s.Refresh)},
		{"Retry", humanizeTTL(s.Retry)},
		{"Expire", humanizeTTL(s.Expire)},
		{"Negative TTL", humanizeTTL(s.Minttl)}, // how long a "doesn't exist" is cached
	}...)
	return f
}

// mboxEmail turns an RNAME into an address: "@" is the first dot not escaped, as in first\.last.
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

// txtLabels maps a TXT prefix to what the record is for.
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

// txtLabel names a TXT record's purpose from its prefix, case-insensitively: publishers vary.
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

// providerOf names the provider most nameservers belong to, dropping a lone legacy straggler;
// a zone split between providers names each ("NS1 + AWS Route 53"). Unknown suffixes give "".
func providerOf(records []Record) string {
	seen := map[string]int{}
	var order []string
	for _, r := range records {
		if r.Type != "NS" {
			continue
		}
		ns := strings.ToLower(strings.TrimSuffix(r.Value, "."))
		for _, p := range providers {
			if !strings.Contains(ns, p.suffix) {
				continue
			}
			if seen[p.name] == 0 {
				order = append(order, p.name)
			}
			seen[p.name]++
			break
		}
	}
	if len(order) == 0 {
		return ""
	}
	slices.SortStableFunc(order, func(a, b string) int { return seen[b] - seen[a] })
	names := order[:1]
	for _, n := range order[1:] {
		if seen[n] >= 2 || seen[n] == seen[order[0]] {
			names = append(names, n)
		}
	}
	return strings.Join(names, " + ")
}
