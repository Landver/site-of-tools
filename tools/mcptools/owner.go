package mcptools

import (
	"context"
	"log/slog"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Landver/site-of-tools/tools/linktools"
)

type shortListArgs struct {
	Limit int `json:"limit,omitempty" jsonschema:"how many links to list"`
}

type shortRevokeArgs struct {
	Code string `json:"code" jsonschema:"the code to revoke, or its whole short URL"`
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
	specs := []toolSpec{
		{
			tool: &mcp.Tool{
				Name:  "link_short_create",
				Title: "Create a short link",
				Description: "Create a short link on corpberry.com that redirects to url, for good or for ttl (a Go duration such as 720h, at least 1m). " +
					"slug picks the code (2 to 64 lowercase letters, digits and hyphens) in place of a random one, " +
					"note labels it in link_short_list, and clean: true strips tracking parameters from url first. " +
					"The link is public the moment it exists and its code is never reissued, so check the destination before creating one.",
				InputSchema: inputSchema[linktools.CreateRequest](minLength("url", 1)),
				Annotations: acts(true, false, true),
			},
			add: handle(t.create),
		},
		{
			tool: &mcp.Tool{
				Name:  "link_short_list",
				Title: "List short links",
				Description: "List the newest short links, newest first: each one's code, target, note, creation and expiry, " +
					"revocation and hit count. limit caps how many.",
				InputSchema: inputSchema[shortListArgs](between("limit", 1, linktools.RecentLimit), defaultTo("limit", linktools.RecentLimit)),
				Annotations: readOnly(false),
			},
			add: handle(t.list),
		},
		{
			tool: &mcp.Tool{
				Name:  "link_short_revoke",
				Title: "Revoke a short link",
				Description: "Revoke a short link for good: from now on it answers as an unknown link, and its code is never reissued. " +
					"Pass the code or the whole short URL link_short_create returned, e.g. q4-report.",
				InputSchema: inputSchema[shortRevokeArgs](minLength("code", 1)),
				Annotations: acts(true, true, false),
			},
			add: handle(t.revoke),
		},
	}
	for i := range specs {
		specs[i].deadline, specs[i].limiter = fetchDeadline, d.LinkLimits.Short
	}
	return specs
}

func (t ownerTools) create(ctx context.Context, a linktools.CreateRequest) (any, error) {
	link, err := t.owner.Create(ctx, a, callerFrom(ctx).ip)
	if err != nil {
		return nil, publicError(t.log, "link_short_create", err)
	}
	return link, nil
}

func (t ownerTools) list(ctx context.Context, a shortListArgs) (any, error) {
	links, err := t.owner.Recent(ctx, int64(a.Limit))
	if err != nil {
		return nil, publicError(t.log, "link_short_list", err)
	}
	if links == nil {
		links = []linktools.Link{}
	}
	return map[string]any{"links": links}, nil
}

func (t ownerTools) revoke(ctx context.Context, a shortRevokeArgs) (any, error) {
	code, ok := t.owner.Code(a.Code)
	if !ok {
		return nil, publicError(t.log, "link_short_revoke", linktools.ErrLinkNotFound)
	}
	if err := t.owner.Revoke(ctx, code); err != nil {
		return nil, publicError(t.log, "link_short_revoke", err)
	}
	return map[string]string{"status": "revoked", "code": code}, nil
}
