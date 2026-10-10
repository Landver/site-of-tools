package dnstools

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/miekg/dns"
)

// caaTags: the CAA properties we name, and what an empty issuer means for those that take one.
var caaTags = map[string]struct{ label, forbids string }{
	"issue":     {"May issue certificates", "no CA may issue certificates for this name"},
	"issuewild": {"May issue wildcards", "no CA may issue wildcard certificates for this name"},
	"iodef":     {"Report violations to", ""},
}

// caaFields decodes a CAA record: who may issue for this name, and where to report violations.
func caaFields(c *dns.CAA) []Field {
	tag := caaTags[strings.ToLower(c.Tag)]
	f := []Field{{cmp.Or(tag.label, c.Tag), c.Value}}
	// An empty issuer (`;`) authorises nobody (RFC 8659 §4.2/§4.3); "May issue" would invert it.
	if issuer, _, _ := strings.Cut(c.Value, ";"); tag.forbids != "" && strings.TrimSpace(issuer) == "" {
		f = []Field{{"Certificates", tag.forbids}}
	}
	// Bit 0 (0x80) is Issuer Critical (RFC 8659 §4.1); only then is a Flag row shown, raw value included.
	if c.Flag&0x80 != 0 {
		f = append(f, Field{"Flag", fmt.Sprintf("%d (critical)", c.Flag)})
	}
	return f
}

// svcbFields decodes an HTTPS/SVCB record's SvcParams (RFC 9460), ECH included.
func svcbFields(s *dns.SVCB) []Field {
	target := strings.TrimSuffix(s.Target, ".")
	// Priority 0 is AliasMode; a root target there means "not available here" (RFC 9460 §2.4.2).
	if s.Priority == 0 {
		return []Field{{"Mode", "alias, pointing at " + cmp.Or(target, "the root: this service is explicitly not available here")}}
	}
	f := []Field{{"Priority", fmt.Sprint(s.Priority)}}
	// A root target is the owner name itself (RFC 9460 §2.5), so there is nothing to add.
	if target != "" {
		f = append(f, Field{"Endpoint", target})
	}

	for _, p := range s.Value {
		name, val := p.Key().String(), p.String()
		switch p.Key() {
		case dns.SVCB_ALPN:
			name, val = "Protocols", humanALPN(val)
		case dns.SVCB_PORT:
			name = "Port"
		// A space after each comma lets a long hint list wrap between addresses.
		case dns.SVCB_IPV4HINT:
			name, val = "IPv4 hint", strings.ReplaceAll(val, ",", ", ")
		case dns.SVCB_IPV6HINT:
			name, val = "IPv6 hint", strings.ReplaceAll(val, ",", ", ")
		case dns.SVCB_ECHCONFIG:
			// The base64 length isn't a byte count; an empty config publishes no keys.
			name, val = "ECH", "parameter present but empty, so no ECH keys are published"
			if e, ok := p.(*dns.SVCBECHConfig); ok && len(e.ECH) > 0 {
				val = fmt.Sprintf("published (%d bytes): browsers that support ECH can hide which site they're visiting from the network", len(e.ECH))
			}
		case dns.SVCB_NO_DEFAULT_ALPN:
			name, val = "Default ALPN", "disabled"
		}
		f = append(f, Field{name, val})
	}
	return f
}

// humanALPN turns "h3,h2" into something a non-specialist can read.
func humanALPN(v string) string {
	names := map[string]string{
		"h3": "HTTP/3", "h2": "HTTP/2", "http/1.1": "HTTP/1.1",
		"h3-29": "HTTP/3 (draft 29)", "dot": "DNS-over-TLS",
	}
	out := strings.Split(v, ",")
	for i, a := range out {
		if n, ok := names[a]; ok {
			out[i] = n
		}
	}
	return strings.Join(out, ", ")
}

// soaFields decodes a SOA into named parts, each timer as a human duration.
func soaFields(s *dns.SOA) []Field {
	f := []Field{{"Primary NS", s.Ns}}
	// The RNAME's first dot is the @. A root RNAME, or an escaped dot (first\.last), is left undecoded.
	if local, domain, ok := strings.Cut(strings.TrimSuffix(s.Mbox, "."), "."); ok && local != "" && !strings.Contains(local, `\`) {
		f = append(f, Field{"Hostmaster", local + "@" + domain})
	}
	return append(f,
		Field{"Serial", fmt.Sprint(s.Serial)},
		Field{"Refresh", humanizeTTL(s.Refresh)},
		Field{"Retry", humanizeTTL(s.Retry)},
		Field{"Expire", humanizeTTL(s.Expire)},
		Field{"Negative TTL", humanizeTTL(s.Minttl)}, // how long a "doesn't exist" is cached
	)
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
	t := strings.ToLower(strings.TrimSpace(strings.Trim(v, `"`)))
	for _, l := range txtLabels {
		if strings.HasPrefix(t, strings.ToLower(l.prefix)) {
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

// knownProvider names the DNS provider a bare nameserver name belongs to, or "".
func knownProvider(ns string) string {
	for _, p := range providers {
		if strings.Contains(ns, p.suffix) {
			return p.name
		}
	}
	return ""
}

// providerOf names the provider most nameservers belong to, dropping a lone legacy straggler;
// a zone split between providers names each ("NS1 + AWS Route 53"). Unknown suffixes give "".
func providerOf(records []Record) string {
	seen := map[string]int{}
	var order []string
	for _, r := range records {
		if name := knownProvider(bareName(r.Value)); r.Type == "NS" && name != "" {
			if seen[name] == 0 {
				order = append(order, name)
			}
			seen[name]++
		}
	}
	slices.SortStableFunc(order, func(a, b string) int { return seen[b] - seen[a] })
	var names []string
	for i, n := range order {
		if i == 0 || seen[n] >= 2 || seen[n] == seen[order[0]] {
			names = append(names, n)
		}
	}
	return strings.Join(names, " + ")
}
