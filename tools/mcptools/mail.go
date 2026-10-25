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

	"github.com/Landver/site-of-tools/tools/mailtools"
)

type mailDMARCArgs struct {
	XML    string `json:"xml,omitempty" jsonschema:"the raw DMARC XML text, or base64-encoded XML or gzip payload"`
	Base64 string `json:"base64,omitempty" jsonschema:"base64-encoded .xml or .xml.gz report payload"`
}

type mailBIMIArgs struct {
	SVG string `json:"svg" jsonschema:"the raw SVG logo markup"`
}

type mailARCArgs struct {
	Headers string `json:"headers" jsonschema:"the raw forwarded email headers containing ARC-Seal, ARC-Message-Signature, and ARC-Authentication-Results"`
}

type mailDomainArgs struct {
	Domain string `json:"domain" jsonschema:"the email domain name (e.g. stripe.com) or email address"`
}

type mailTargetArgs struct {
	Target string `json:"target" jsonschema:"the IP address (e.g. 198.51.100.1) or domain name to check against blacklists"`
}

type mailTools struct {
	svc *mailtools.Service
}

func mailSpecs(d Deps) []toolSpec {
	lim := d.MailLimits
	t := mailTools{svc: d.Mail}

	var specs []toolSpec
	pure := func(name, title, desc string, open bool, schema any, add func(*mcp.Server, *mcp.Tool)) {
		specs = append(specs, toolSpec{
			toolset: "mail",
			tool: &mcp.Tool{
				Name:        name,
				Title:       title,
				Description: desc,
				InputSchema: schema,
				Annotations: readOnly(open),
			},
			deadline: quickDeadline,
			limiter:  lim.Pure,
			add:      add,
		})
	}

	heavy := func(name, title, desc string, open bool, schema any, add func(*mcp.Server, *mcp.Tool)) {
		specs = append(specs, toolSpec{
			toolset: "mail",
			tool: &mcp.Tool{
				Name:        name,
				Title:       title,
				Description: desc,
				InputSchema: schema,
				Annotations: readOnly(open),
			},
			deadline: heavyDeadline,
			limiter:  lim.Heavy,
			cap:      lim.HeavyCap,
			add:      add,
		})
	}

	heavy("mail_dmarc_parse", "Parse DMARC Aggregate Report",
		"Parse and aggregate an RFC 7489 DMARC XML (or .xml.gz) report: message counts, pass rate %, SPF/DKIM alignment, and sending IPs classified by ESP (Google, Microsoft 365, Amazon SES, SendGrid, etc.).",
		false, inputSchema[mailDMARCArgs](), handle(t.dmarcParse))

	pure("mail_bimi_validate", "Validate BIMI SVG Logo",
		"Validate an SVG logo against strict BIMI SVG Tiny P/S standards (version 1.2, baseProfile tiny-ps, square 1:1 aspect ratio, <= 32 KB, no scripts or event handlers) for Gmail and Apple Mail.",
		false, inputSchema[mailBIMIArgs](minLength("svg", 1)), handle(t.bimiValidate))

	pure("mail_bimi_autofix", "Auto-Fix BIMI SVG Logo",
		"Auto-fix an SVG logo into compliant BIMI SVG Tiny P/S: updates version 1.2, baseProfile, square viewBox, and strips dangerous scripts, foreignObjects, and inline event handlers.",
		false, inputSchema[mailBIMIArgs](minLength("svg", 1)), handle(t.bimiAutoFix))

	pure("mail_arc_analyze", "Analyze ARC Authentication Chain",
		"Analyze RFC 8617 Authenticated Received Chain (ARC) headers: verifies hop sequence (i=1, 2, ...), cv validation states, and reports whether mailing list / forwarding preserved message authenticity.",
		false, inputSchema[mailARCArgs](minLength("headers", 1)), handle(t.arcAnalyze))

	pure("mail_check_disposable", "Check Disposable Email Domain",
		"Check if an email address or domain is a temporary, burner, or disposable email service using the canonical community blocklist and wildcard patterns.",
		false, inputSchema[mailDomainArgs](minLength("domain", 1)), handle(t.checkDisposable))

	pure("mail_classify_domain", "Classify Email Domain (Free vs Corporate)",
		"Classify an email address or domain into B2B corporate custom domain versus personal free consumer webmail (Gmail, Yahoo, Mail.ru, Proton, etc.).",
		false, inputSchema[mailDomainArgs](minLength("domain", 1)), handle(t.classifyDomain))

	if d.Mail == nil {
		return specs
	}

	heavy("mail_detect_gateway", "Detect Secure Email Gateway (SEG)",
		"Inspect MX records and fingerprint enterprise security gateways (Proofpoint, Mimecast, Microsoft Defender, Google Workspace, Cisco IronPort, Barracuda) and direct-to-MX bypass risks.",
		true, inputSchema[mailDomainArgs](minLength("domain", 1)), handle(t.detectGateway))

	heavy("mail_check_dnsbl", "Check Multi-DNSBL Blacklists",
		"Audit an IP address or domain across 15+ authoritative global DNSBL/RBL spam blacklists (Spamhaus, Barracuda BRBL, SpamCop, Mailspike) in parallel.",
		true, inputSchema[mailTargetArgs](minLength("target", 1)), handle(t.checkDNSBL))

	heavy("mail_domain_health", "Audit Domain Email Health",
		"Comprehensive email infrastructure and deliverability audit: combines SEG gateway detection, BIMI/VMC verification, disposable check, and DNSBL reputation.",
		true, inputSchema[mailDomainArgs](minLength("domain", 1)), handle(t.domainHealth))

	return specs
}

func (t mailTools) dmarcParse(_ context.Context, _ *mcp.CallToolRequest, a mailDMARCArgs) (any, error) {
	var r io.Reader
	if a.Base64 != "" {
		dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(a.Base64))
		if err != nil {
			return nil, fmt.Errorf("invalid base64 payload: %w", err)
		}
		r = bytes.NewReader(dec)
	} else if a.XML != "" {
		s := strings.TrimSpace(a.XML)
		if !strings.HasPrefix(s, "<") {
			if dec, err := base64.StdEncoding.DecodeString(s); err == nil {
				r = bytes.NewReader(dec)
			} else {
				r = strings.NewReader(s)
			}
		} else {
			r = strings.NewReader(s)
		}
	} else {
		return nil, errors.New("provide either xml or base64")
	}

	return mailtools.ParseDMARCReport(r)
}

func (t mailTools) bimiValidate(_ context.Context, _ *mcp.CallToolRequest, a mailBIMIArgs) (any, error) {
	return mailtools.ValidateBIMI(a.SVG)
}

func (t mailTools) bimiAutoFix(_ context.Context, _ *mcp.CallToolRequest, a mailBIMIArgs) (any, error) {
	fixed, err := mailtools.AutoFixBIMI(a.SVG)
	if err != nil {
		return nil, err
	}
	return map[string]string{"svg": fixed}, nil
}

func (t mailTools) arcAnalyze(_ context.Context, _ *mcp.CallToolRequest, a mailARCArgs) (any, error) {
	return mailtools.AnalyzeARC(a.Headers)
}

func (t mailTools) checkDisposable(_ context.Context, _ *mcp.CallToolRequest, a mailDomainArgs) (any, error) {
	return mailtools.ActiveClassifier().Classify(a.Domain), nil
}

func (t mailTools) classifyDomain(_ context.Context, _ *mcp.CallToolRequest, a mailDomainArgs) (any, error) {
	return mailtools.ActiveClassifier().Classify(a.Domain), nil
}

func (t mailTools) detectGateway(ctx context.Context, _ *mcp.CallToolRequest, a mailDomainArgs) (any, error) {
	return mailtools.DetectGateway(ctx, a.Domain)
}

func (t mailTools) checkDNSBL(ctx context.Context, _ *mcp.CallToolRequest, a mailTargetArgs) (any, error) {
	return t.svc.DNSBL(ctx, a.Target)
}

func (t mailTools) domainHealth(ctx context.Context, _ *mcp.CallToolRequest, a mailDomainArgs) (any, error) {
	return t.svc.AuditDomainHealth(ctx, a.Domain)
}
