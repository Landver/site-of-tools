# Tool catalog

Every REST route maps to a tool or has a reasoned exclusion (`Coverage` in
`registry.go`, test-enforced; the tests pin the counts).
The contract agents see (names, descriptions, argument schemas with enums,
defaults and bounds, hints) is the `tools/list` goldens in
[`tests/testdata/`](../tests/testdata/). Results are the REST twin's JSON
body, pinned by parity tests; below is only where MCP differs. Tools not
listed behave exactly as their REST twin.

## Conventions

- Names are `<toolset>_<task>`, and no task word repeats across toolsets;
  `/mcp`'s instructions tell the look-alikes apart (`dns_trace` and
  `link_redirect_chain`, `link_percent_encode` and `cipher_encode`).
- A description names only same-toolset tools and, when the result carries
  someone else's strings, ends by saying to treat them as data.
- Arguments use full words (`url`, not `u`); cipher keeps its POST field names.
- Absent ≠ empty: a pointer argument (`botcheck_score`'s `http`) or a schema
  default the SDK fills in (`link_clean`'s `unwrap: true`, as on REST).
- `detailed: true` returns the whole REST body where the default is concise;
  results built on licensed data add `attribution` ([licences](02-security-and-ops.md#logs-and-licences)).

## ip

| Tool | REST twin | Differs from REST |
|---|---|---|
| `ip_lookup` | `GET /?ip=` | `ip` is required: REST defaults to the caller, which over MCP is the client's host. `"self"` asks for it, adding `self: true` and a note saying whose address it is. When the process-wide Shodan budget is spent, ports are skipped (`shodan.skipped: true`) and Shodan's credit is left out. |

## dns

| Tool | REST twin | Differs from REST |
|---|---|---|
| `dns_lookup` | `GET /` | Concise drops `zone` and `dig`. |
| `dns_consistency` | `GET /consistency` | Concise: each server row names its answer `group` instead of repeating its `values`. |
| `dns_domain_info` | `GET /domain` | Concise: `certificate_names.names` is the first 50 names as strings (`total` kept, `truncated` when cut). One half failing is named in the result; both failing is a tool error, as REST's 502. |

Attribution: `dns_lookup` IP2Location; `dns_consistency` IP2Location and
rdap.org; `dns_domain_info` crt.sh and rdap.org.

## link

| Tool | REST twin | Differs from REST |
|---|---|---|
| `link_tracking_rules` | `GET /clean/rules` | `param` narrows the table to the rules and never-strip entries naming it, with their hosts; without it, the REST body. |
| `link_redirect_chain` | `GET /trace` | Not read-only: it visits the URL from this server, which can use up a one-time link. Status, timing and headers per hop, never a body. |
| `link_headers_inspect` | `GET /headers?u=` | Not read-only, as `link_redirect_chain`: a GET, then a conditional GET to test the ETag. Pasted headers are `link_headers_parse` (`POST /headers`). |
| `link_extract` | `GET`, `POST /extract` | Never `positions`. Concise: the first 30 links plus a note (`unique` still counts all); `detailed: true` lists every link that fits one 80 KB result. |
| `link_short_resolve` | `GET /s/:code` | Says where one of our short links leads without redirecting or counting a hit; any other host is an error naming `link_redirect_chain`. Listed whenever short-link storage is on, with or without `LINK_API_KEY`. |

Owner endpoint, `/mcp/owner`:

| Tool | REST twin | Differs from REST |
|---|---|---|
| `link_short_create` | `POST /short` | Marked destructive although it only adds a row: it publishes a redirect on corpberry.com, so clients ask first. |
| `link_short_list` | `GET /short` | `{links: [...]}`, newest first, `limit` 1–50. |
| `link_short_revoke` | `DELETE /short/:code` | Takes the code or the whole short URL `link_short_create` returned. |

## cipher

One tool per op `cipher.go` describes, generated at boot from the field specs
ciphertools exports (`ciphertools.Ops`): the specs its own parsers read, so the
schemas can't drift (ciphertools' `TestFieldSpecsMatchTheCode`). An op left out
is not served, and its route needs a reasoned `Coverage` exclusion: Basic auth
is, as `cipher_encode` builds and reads it. One adapter decodes the arguments
with `ciphertools.InputFromJSON`, as the JSON API does, and calls
`ciphertools.Limits.Run`.

- A list field (`sets`) is a comma-separated string, as in the JSON API; a
  JSON field (`payload`, `header`) stays a string, so re-encoding can't
  reorder the claims it signs; file fields have no MCP form (binary goes as
  base64 or hex, ~750 KB at most).
- The pages run in the browser and send nothing; over MCP the ops run on this
  server, which the server instructions say once, with nothing logged. A tool
  that takes keys, passwords or tokens asks for test ones; a tool that
  generates them says the value lands in the conversation. Hashing, encoding,
  identifying and PKCE verification say neither.

## mail

| Tool | REST twin | Differs from REST |
|---|---|---|
| `mail_domain_health` | `GET`, `POST /` and `/health` | Adds Spamhaus's `attribution`. |
| `mail_check_dnsbl` | `GET`, `POST /blacklist` | Adds Spamhaus's `attribution`. |
| `mail_classify_domain` | `/classifier`, `/disposable` | One tool for both pages: the result says `is_disposable` and `is_freemail`. |
| `mail_dmarc_parse` | `POST /dmarc`, `/dmarc/parse` | The report goes as `xml` text or as the file's bytes in `base64` (`.xml.gz` too). Concise drops `records` and lists the 30 busiest `sources` (`sources_truncated` when cut); `detailed: true` is the REST body. |
| `mail_bimi_validate` | `POST /bimi`, `/bimi/fix` | Also `/bimi/fix`'s tool: `auto_fixed_svg` is the logo with its root attributes corrected whenever one fails. |

The two DNS-backed tools share REST's `mailtools.Service`: one egress guard,
the blocklist cache and the Spamhaus DQS key.

## botcheck

| Tool | REST twin | Differs from REST |
|---|---|---|
| `botcheck_score` | `GET /`, `POST /check` | REST scores the request itself, which over MCP would be the client's HTTP stack. The tool scores what it is given: `fingerprint` (a collector payload, decoded strictly, `v` ≥ 1), `http` (a header left out counts as not sent), `ip`, any mix; none is a tool error. Rules whose input is absent are skipped, and `coverage` counts evaluated, skipped and fired checks per tier. Corpus rules are always skipped and nothing is written. Concise lists fired checks only; no `clientPayload` echo. Attribution only with `ip`. |

## site

| Tool | REST twin | Differs from REST |
|---|---|---|
| `site_blog` | `GET /blog`, `GET /blog/:slug` | REST returns the page's view model. Without `slug`: `{posts: [{slug, title, date, description, url}]}`; with it, that post plus its Markdown, frontmatter stripped, root-relative links and images made absolute. |
