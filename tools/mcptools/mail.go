package mcptools

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/mailtools"
)

type mailDMARCArgs struct {
	XML      string `json:"xml,omitempty" jsonschema:"the report's XML text"`
	Base64   string `json:"base64,omitempty" jsonschema:"the report file's bytes base64-encoded, for a .xml.gz or a .xml"`
	Detailed bool   `json:"detailed,omitempty" jsonschema:"list every source IP and every report row"`
}

type mailBIMIArgs struct {
	SVG string `json:"svg" jsonschema:"the SVG logo's markup"`
}

type mailARCArgs struct {
	Headers string `json:"headers" jsonschema:"the message's raw headers, ARC-Seal, ARC-Message-Signature and ARC-Authentication-Results among them"`
}

type mailDomainArgs struct {
	Domain string `json:"domain" jsonschema:"a domain, e.g. stripe.com, or an email address"`
}

type mailTargetArgs struct {
	Target string `json:"target" jsonschema:"an IPv4 address, e.g. 198.51.100.7, or a domain"`
}

const dmarcSources = 30

type mailTools struct{ svc *mailtools.Service }

func mailSpecs(d Deps) []toolSpec {
	lim, t := d.MailLimits, mailTools{svc: d.Mail}
	spec := func(heavy bool, tool *mcp.Tool, add func(*mcp.Server, *mcp.Tool)) toolSpec {
		s := toolSpec{tool: tool, deadline: quickDeadline, limiter: lim.Pure, add: add}
		if heavy {
			s.deadline, s.limiter, s.cap = heavyDeadline, lim.Heavy, lim.HeavyCap
		}
		return s
	}
	specs := []toolSpec{
		spec(true, &mcp.Tool{
			Name:  "mail_dmarc_parse",
			Title: "Read a DMARC report",
			Description: "Read a DMARC aggregate report (the RFC 7489 rua XML a mailbox provider sends, plain or gzipped): who sent it and for which dates, " +
				"the policy published, message totals and pass rate, and the senders rolled up by provider (Google, Microsoft 365, Amazon SES, SendGrid…) and by IP. " +
				"Pass the XML as xml, or the file's bytes base64-encoded as base64; one request carries at most 1 MB, and a report at most 5,000 rows. " +
				"Lists the 30 busiest source IPs; detailed: true lists every IP and every report row. " + thirdParty,
			InputSchema: inputSchema[mailDMARCArgs](),
			Annotations: readOnly(false),
		}, handle(t.dmarcParse)),
		spec(false, &mcp.Tool{
			Name:  "mail_bimi_validate",
			Title: "Check a BIMI logo",
			Description: "Check an SVG logo against the BIMI SVG Tiny P/S rules Gmail and Apple Mail enforce: the SVG namespace, version 1.2, baseProfile tiny-ps, " +
				"a square viewBox, at most 32 KB, and no scripts, event handlers, javascript: links or external resources. " +
				"When the root's attributes are what fails, auto_fixed_svg is the logo with them corrected; content problems are named for you to fix. " +
				`Example: svg <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">…</svg>.`,
			InputSchema: inputSchema[mailBIMIArgs](minLength("svg", 1)),
			Annotations: readOnly(false),
		}, handle(t.bimiValidate)),
		spec(false, &mcp.Tool{
			Name:  "mail_arc_analyze",
			Title: "Check ARC header structure",
			Description: "Check the structure of a message's ARC headers (RFC 8617): every forwarding hop i=1, 2, … has its ARC-Seal, ARC-Message-Signature and " +
				"ARC-Authentication-Results, numbered without gaps or repeats, with cv= values in the order the RFC requires, and any arc=fail a receiver recorded. " +
				"Signatures are not verified, so an intact structure is not proof the message is authentic. Pass the raw headers. " + thirdParty,
			InputSchema: inputSchema[mailARCArgs](minLength("headers", 1)),
			Annotations: readOnly(false),
		}, handle(t.arcAnalyze)),
		spec(false, &mcp.Tool{
			Name:  "mail_classify_domain",
			Title: "Disposable, free or company email",
			Description: "Say whether an email address or domain is disposable (a throwaway inbox service), free webmail (Gmail, Yahoo, Proton…) or a company's own domain, " +
				"from curated lists refreshed daily; a subdomain of a listed domain counts as listed, and match_reason names the entry. " +
				"Nothing is looked up. For a domain's mail setup, use mail_domain_health. Example: domain someone@mailinator.com.",
			InputSchema: inputSchema[mailDomainArgs](minLength("domain", 1)),
			Annotations: readOnly(false),
		}, handle(t.classify)),
	}
	if d.Mail == nil {
		return specs
	}
	return append(specs,
		spec(true, &mcp.Tool{
			Name:  "mail_domain_health",
			Title: "Audit a domain's email",
			Description: "Audit a domain's email setup from this server: SPF and its DNS lookup count, the DMARC policy in force (an inherited sp= included), " +
				"DKIM on common selectors, MTA-STS, the MX hosts and the security gateway in front of them, BIMI and its certificate, and blocklist listings, " +
				"scored out of 100 with a recommendation per finding. Pass a domain or an email address. " +
				"For the blocklists alone use mail_check_dnsbl. Example: domain stripe.com. " + thirdParty,
			InputSchema: inputSchema[mailDomainArgs](minLength("domain", 1)),
			Annotations: readOnly(true),
		}, handle(t.domainHealth)),
		spec(true, &mcp.Tool{
			Name:  "mail_check_dnsbl",
			Title: "Check DNS blocklists",
			Description: "Look up an IPv4 address or a domain on public DNS blocklists (Spamhaus, Barracuda, SpamCop, Mailspike and others) from this server: " +
				"each list's verdict and what its answer code means. A domain is checked on the domain lists and by its primary mail server's address. " +
				"For a domain's whole mail setup, use mail_domain_health. Example: target 198.51.100.7. " + thirdParty,
			InputSchema: inputSchema[mailTargetArgs](minLength("target", 1)),
			Annotations: readOnly(true),
		}, handle(t.checkDNSBL)),
	)
}

func (t mailTools) dmarcParse(_ context.Context, a mailDMARCArgs) (any, error) {
	var r io.Reader
	switch {
	case a.Base64 != "":
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(a.Base64))
		if err != nil {
			return nil, fmt.Errorf("base64: %w", err)
		}
		r = bytes.NewReader(raw)
	case a.XML != "":
		r = strings.NewReader(a.XML)
	default:
		return nil, errors.New("provide either xml or base64")
	}
	rep, err := mailtools.ParseDMARCReport(r)
	if err != nil || a.Detailed {
		return rep, err
	}
	out, err := object(rep)
	if err != nil {
		return nil, err
	}
	delete(out, "records")
	if len(rep.Sources) > dmarcSources {
		out["sources"], out["sources_truncated"] = rep.Sources[:dmarcSources], true
	}
	return out, nil
}

func (t mailTools) bimiValidate(_ context.Context, a mailBIMIArgs) (any, error) {
	return mailtools.ValidateBIMI(a.SVG)
}

func (t mailTools) arcAnalyze(_ context.Context, a mailARCArgs) (any, error) {
	return mailtools.AnalyzeARC(a.Headers)
}

func (t mailTools) classify(_ context.Context, a mailDomainArgs) (any, error) {
	return mailtools.ActiveClassifier().Classify(a.Domain), nil
}

func (t mailTools) checkDNSBL(ctx context.Context, a mailTargetArgs) (any, error) {
	return withSpamhaus(t.svc.DNSBL(ctx, a.Target))
}

func (t mailTools) domainHealth(ctx context.Context, a mailDomainArgs) (any, error) {
	return withSpamhaus(t.svc.AuditDomainHealth(ctx, a.Domain))
}

// withSpamhaus credits the blocklist answers, as every result built on licensed data does.
func withSpamhaus(rep any, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	out, err := object(rep)
	if err != nil {
		return nil, err
	}
	out["attribution"] = credits(platform.CreditSpamhaus)
	return out, nil
}
