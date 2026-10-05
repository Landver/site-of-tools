package mcptools

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Landver/site-of-tools/tools/linktools"
)

type shortCreateArgs struct {
	URL   string `json:"url" jsonschema:"the destination, an http or https URL on a public host"`
	Slug  string `json:"slug,omitempty" jsonschema:"the code to use, e.g. q4-report"`
	TTL   string `json:"ttl,omitempty" jsonschema:"how long the link lives, a Go duration such as 720h; left out, it never expires"`
	Note  string `json:"note,omitempty" jsonschema:"a label for the list, up to 256 bytes"`
	Clean bool   `json:"clean,omitempty" jsonschema:"strip tracking parameters from url first"`
}

type shortListArgs struct {
	Limit int `json:"limit,omitempty" jsonschema:"how many links to list"`
}

type shortRevokeArgs struct {
	Code string `json:"code" jsonschema:"the code to revoke"`
}

type ownerTools struct {
	owner *linktools.Shortener
	log   *slog.Logger
}

// ownerSpecs serve at /mcp/owner only, never beside tools returning third-party text.
func ownerSpecs(d Deps, log *slog.Logger) []toolSpec {
	if !d.Owner.HasKey() {
		return nil
	}
	t := ownerTools{owner: d.Owner, log: log}
	lim := d.LinkLimits.Short
	return []toolSpec{
		{
			toolset: "link",
			tool: &mcp.Tool{
				Name:  "link_short_create",
				Title: "Create a short link",
				Description: "Create a short link on corpberry.com that redirects to url, for good or for ttl (a Go duration such as 720h, at least 1m). " +
					"slug picks the code (2 to 64 lowercase letters, digits and hyphens) in place of a random one, " +
					"note labels it in link_short_list, and clean: true strips tracking parameters from url first. " +
					"The link is public the moment it exists and its code is never reissued, so check the destination before creating one.",
				InputSchema: inputSchema[shortCreateArgs](minLength("url", 1)),
				Annotations: acts(true, false, true),
			},
			deadline: fetchDeadline,
			limiter:  lim,
			add:      handle(t.create),
		},
		{
			toolset: "link",
			tool: &mcp.Tool{
				Name:  "link_short_list",
				Title: "List short links",
				Description: "List the newest short links, newest first: each one's code, target, note, creation and expiry, " +
					"revocation and hit count. limit caps how many.",
				InputSchema: inputSchema[shortListArgs](between("limit", 1, linktools.RecentLimit), defaultTo("limit", linktools.RecentLimit)),
				Annotations: readOnly(false),
			},
			deadline: fetchDeadline,
			limiter:  lim,
			narrow:   "Ask for fewer with limit.",
			add:      handle(t.list),
		},
		{
			toolset: "link",
			tool: &mcp.Tool{
				Name:  "link_short_revoke",
				Title: "Revoke a short link",
				Description: "Revoke a short link: from now on it answers no such link, for good, and its code is never reissued. " +
					"Pass the code, the part after /s/, e.g. q4-report.",
				InputSchema: inputSchema[shortRevokeArgs](minLength("code", 1)),
				Annotations: acts(true, true, false),
			},
			deadline: fetchDeadline,
			limiter:  lim,
			add:      handle(t.revoke),
		},
	}
}

func (t ownerTools) create(ctx context.Context, _ *mcp.CallToolRequest, a shortCreateArgs) (any, error) {
	req := linktools.CreateRequest{URL: a.URL, Slug: a.Slug, TTL: a.TTL, Note: a.Note, Clean: a.Clean}
	created, err := t.owner.CreateFrom(ctx, req, callerFrom(ctx).ip)
	if err != nil {
		return nil, publicError(t.log, "link_short_create", err)
	}
	return created, nil
}

func (t ownerTools) list(ctx context.Context, _ *mcp.CallToolRequest, a shortListArgs) (any, error) {
	links, err := t.owner.Recent(ctx, int64(a.Limit))
	if err != nil {
		return nil, publicError(t.log, "link_short_list", err)
	}
	if links == nil {
		links = []linktools.Link{}
	}
	return map[string]any{"links": links}, nil
}

func (t ownerTools) revoke(ctx context.Context, _ *mcp.CallToolRequest, a shortRevokeArgs) (any, error) {
	code := strings.TrimSpace(a.Code)
	switch err := t.owner.Revoke(ctx, code); {
	case errors.Is(err, linktools.ErrLinkNotFound):
		return nil, errors.New("No such short link.")
	case err != nil:
		return nil, publicError(t.log, "link_short_revoke", err)
	}
	return map[string]string{"status": "revoked", "code": code}, nil
}
