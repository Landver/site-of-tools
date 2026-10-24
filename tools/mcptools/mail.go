package mcptools

import (
	"context"
	"encoding/base64"
	"errors"
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

type mailTools struct {
	lim *mailtools.Limits
}

func mailSpecs(d Deps) []toolSpec {
	lim := d.MailLimits
	if lim == nil {
		lim = mailtools.NewLimits()
	}
	t := mailTools{lim: lim}

	var specs []toolSpec
	pure := func(name, title, desc string, schema any, add func(*mcp.Server, *mcp.Tool)) {
		specs = append(specs, toolSpec{
			toolset: "mail",
			tool: &mcp.Tool{
				Name:        name,
				Title:       title,
				Description: desc,
				InputSchema: schema,
				Annotations: readOnly(false),
			},
			deadline: quickDeadline,
			limiter:  lim.Pure,
			add:      add,
		})
	}

	pure("mail_dmarc_parse", "Parse DMARC Aggregate Report",
		"Parse and aggregate an RFC 7489 DMARC XML (or .xml.gz) report: message counts, pass rate %, SPF/DKIM alignment, and sending IPs classified by ESP (Google, Microsoft 365, Amazon SES, SendGrid, etc.).",
		inputSchema[mailDMARCArgs](), handle(t.dmarcParse))

	pure("mail_bimi_validate", "Validate BIMI SVG Logo",
		"Validate an SVG logo against strict BIMI SVG Tiny P/S standards (version 1.2, baseProfile tiny-ps, square 1:1 aspect ratio, <= 32 KB, no scripts or event handlers) for Gmail and Apple Mail.",
		inputSchema[mailBIMIArgs](minLength("svg", 1)), handle(t.bimiValidate))

	pure("mail_bimi_autofix", "Auto-Fix BIMI SVG Logo",
		"Auto-fix an SVG logo into compliant BIMI SVG Tiny P/S: updates version 1.2, baseProfile, square viewBox, and strips dangerous scripts, foreignObjects, and inline event handlers.",
		inputSchema[mailBIMIArgs](minLength("svg", 1)), handle(t.bimiAutoFix))

	pure("mail_arc_analyze", "Analyze ARC Authentication Chain",
		"Analyze RFC 8617 Authenticated Received Chain (ARC) headers: verifies hop sequence (i=1, 2, ...), cv validation states, and reports whether mailing list / forwarding preserved message authenticity.",
		inputSchema[mailARCArgs](minLength("headers", 1)), handle(t.arcAnalyze))

	return specs
}

func (t mailTools) dmarcParse(_ context.Context, _ *mcp.CallToolRequest, a mailDMARCArgs) (any, error) {
	var r io.Reader
	if a.Base64 != "" {
		dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(a.Base64))
		if err != nil {
			return nil, errors.New("invalid base64 payload: " + err.Error())
		}
		r = strings.NewReader(string(dec))
	} else if a.XML != "" {
		s := strings.TrimSpace(a.XML)
		// Check if it's base64 encoded
		if !strings.HasPrefix(s, "<") {
			if dec, err := base64.StdEncoding.DecodeString(s); err == nil {
				r = strings.NewReader(string(dec))
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
