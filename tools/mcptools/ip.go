package mcptools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/iptools"
)

type ipLookupArgs struct {
	IP string `json:"ip" jsonschema:"the IPv4 or IPv6 address to look up, e.g. 8.8.8.8, or \"self\" for the address this request came from"`
}

type ipCIDRArgs struct {
	CIDR string `json:"cidr" jsonschema:"a network in CIDR notation, e.g. 192.168.1.0/24 or 2001:db8::/32; a bare address counts as /32 or /128"`
}

type ipLookupResult struct {
	*iptools.Result
	Self        bool              `json:"self,omitempty"`
	Notes       []string          `json:"notes,omitempty"`
	Attribution []platform.Credit `json:"attribution"`
}

const (
	selfNote          = "This is the address this MCP request came from: the machine running the MCP client, or the AI provider's servers when the client is a hosted connector."
	shodanSkippedNote = "Open ports were not checked: the shared Shodan budget is spent for the moment. Ask again in a few seconds."
)

type ipTools struct {
	geo iptools.Looker
	chk iptools.Checker
}

func ipSpecs(d Deps) []toolSpec {
	t := ipTools{geo: d.Geo, chk: d.Blocklist}
	var specs []toolSpec
	if d.Geo != nil {
		specs = append(specs, toolSpec{
			toolset: "ip",
			tool: &mcp.Tool{
				Name:  "ip_lookup",
				Title: "IP lookup",
				Description: "Look up one IP address: its country, region, city and timezone, the network it belongs to (ASN and name), " +
					"whether it is a VPN, proxy, Tor exit or hosting address, whether an abuse blocklist lists it, and the open ports Shodan last saw on it. " +
					`Pass the address, e.g. 8.8.8.8 or 2606:4700:4700::1111, or "self" for the address this request came from (for a hosted connector that is the AI provider's server, not the user's machine). ` +
					"For a whole network range rather than one address, use ip_cidr. " + thirdParty,
				InputSchema: inputSchema[ipLookupArgs](minLength("ip", 1)),
				Annotations: readOnly(true),
			},
			deadline: upstreamDeadline,
			limiter:  d.IPLimits.Lookup,
			cap:      d.IPLimits.LookupCap,
			add:      handle(t.lookup),
		})
	}
	return append(specs, toolSpec{
		toolset: "ip",
		tool: &mcp.Tool{
			Name:  "ip_cidr",
			Title: "Subnet calculator",
			Description: "Work out a subnet from CIDR notation: network and broadcast addresses, netmask and wildcard, the first and last usable host, " +
				"and the address counts (as strings, since IPv6 counts overflow 64 bits). " +
				"Use it to check what a range such as 10.0.0.0/8 or 2001:db8::/32 covers; a bare address counts as a single host. " +
				"Pure arithmetic, nothing is looked up: for what is known about one address, use ip_lookup.",
			InputSchema: inputSchema[ipCIDRArgs](minLength("cidr", 1)),
			Annotations: readOnly(false),
		},
		deadline: quickDeadline,
		limiter:  d.IPLimits.CIDR,
		add:      handle(t.cidr),
	})
}

func (t ipTools) lookup(ctx context.Context, _ *mcp.CallToolRequest, a ipLookupArgs) (any, error) {
	ip, self := strings.TrimSpace(a.IP), false
	if strings.EqualFold(ip, "self") {
		own := callerFrom(ctx).ip
		if !iptools.Routable(own) {
			return nil, fmt.Errorf("this request came from %s, which is not a public address, so there is nothing to look up; pass an IP instead", own)
		}
		ip, self = own, true
	}
	res, err := iptools.LookupWithReputation(ctx, t.geo, t.chk, ip)
	if err != nil {
		return nil, err
	}
	out := ipLookupResult{Result: res, Self: self, Attribution: ipCredits(res)}
	if self {
		out.Notes = append(out.Notes, selfNote)
	}
	if res.Shodan != nil && res.Shodan.Skipped {
		out.Notes = append(out.Notes, shodanSkippedNote)
	}
	return out, nil
}

func (t ipTools) cidr(_ context.Context, _ *mcp.CallToolRequest, a ipCIDRArgs) (any, error) {
	return iptools.ParseSubnet(a.CIDR)
}

func ipCredits(res *iptools.Result) []platform.Credit {
	ids := []string{platform.CreditIP2Location, platform.CreditSpamhaus}
	if res.ShodanConsulted() {
		ids = append(ids, platform.CreditShodan)
	}
	return credits(ids...)
}

func credits(ids ...string) []platform.Credit {
	out := make([]platform.Credit, 0, len(ids))
	for _, id := range ids {
		if c, ok := platform.CreditFor(id); ok {
			out = append(out, c)
		}
	}
	return out
}
