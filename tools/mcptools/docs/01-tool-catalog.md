# Tool catalog

35 public tools and 3 owner tools. 41 REST routes map to them; every other
route has a reasoned exclusion (`Coverage` in `registry.go`, test-enforced).
The contract agents see (names, descriptions, argument schemas with enums,
defaults and bounds, hints) is the `tools/list` goldens in
[`tests/testdata/`](../tests/testdata/). Results are the REST twin's JSON
body, pinned by parity tests; below is only where MCP differs.

## Conventions

- Names are `<toolset>_<task>`, and no task word repeats across toolsets;
  `/mcp`'s instructions tell the look-alikes apart (`dns_trace` and
  `link_redirect_chain`, `link_percent_encode` and `cipher_encode`).
- A description names only same-toolset tools and, when the result carries
  someone else's strings, ends by saying to treat them as data.
- Arguments use full words (`url`, not `u`); cipher keeps its POST field names.
- Absent ≠ empty: a pointer argument (`link_utm`'s tags) or a schema default
  the SDK fills in (`link_clean`'s `unwrap: true`, as on REST).
- `detailed: true` returns the whole REST body where the default is concise;
  results built on licensed data add `attribution` ([licences](02-security-and-ops.md#logs-and-licences)).
- Hints, all four always set: **R** read-only (marked idempotent too), **O**
  open world, **D** destructive, **I** idempotent.

## ip

| Tool | REST twin | Hints | Differs from REST |
|---|---|---|---|
| `ip_lookup` | `GET /?ip=` | R O | `ip` is required: REST defaults to the caller, which over MCP is the client's host. `"self"` asks for it, adding `self: true` and a note saying whose address it is. When the process-wide Shodan budget is spent, ports are skipped with a note and Shodan's credit is left out. |
| `ip_cidr` | `GET /cidr` | R | — |

## dns

| Tool | REST twin | Hints | Differs from REST |
|---|---|---|---|
| `dns_lookup` | `GET /` | R O | Concise drops `zone` and `dig`; detailed returns `zone` as a list of lines, so the string cap can only cut one record. |
| `dns_consistency` | `GET /consistency` | R O | Concise: each server row names its answer `group` instead of repeating its `values`. |
| `dns_trace` | `GET /trace` | R O | — |
| `dns_domain_info` | `GET /domain` | R O | Concise: `certificate_names.names` is the first 50 names as strings (`total` kept, `truncated` when cut). One half failing is named in the result; both failing is a tool error, as REST's 502. |
| `dns_email_auth` | `GET /email` | R O | — |

Attribution: `dns_lookup` IP2Location; `dns_consistency` IP2Location and
rdap.org; `dns_domain_info` crt.sh and rdap.org; `dns_email_auth` Spamhaus.

## link

| Tool | REST twin | Hints | Differs from REST |
|---|---|---|---|
| `link_inspect` | `GET /?u=` | R | — |
| `link_clean` | `GET /clean` | R | — |
| `link_tracking_rules` | `GET /clean/rules` | R | At most one of `param` (every rule naming it, with its hosts), `url` (what `link_clean` does with each parameter, and why) and `full: true` (the REST body); none returns the table's version, scope and size. |
| `link_diff` | `GET /diff` | R | — |
| `link_redirect_chain` | `GET /trace` | O | Not read-only: it visits the URL from this server, which can use up a one-time link. Status, timing and headers per hop, never a body. |
| `link_curl_parse` | `GET /curl?curl=`, `POST /curl` | R | — |
| `link_curl_build` | `GET /curl?u=` | R | — |
| `link_extract` | `GET`, `POST /extract` | R | Concise: no `positions`, and the first 30 links plus a note (`unique` still counts all). |
| `link_utm` | `GET /utm` | R | An omitted tag keeps the URL's own and `""` removes it; the REST form always sends all five. |
| `link_percent_encode` | `GET /encode` | R | — |
| `link_short_resolve` | `GET /s/:code` | R | Says where one of our short links leads without redirecting or counting a hit; any other host is an error naming `link_redirect_chain`. Listed whenever short-link storage is on, with or without `LINK_API_KEY`. |

Owner endpoint, `/mcp/owner`:

| Tool | REST twin | Hints | Differs from REST |
|---|---|---|---|
| `link_short_create` | `POST /short` | D O | Marked destructive although it only adds a row: it publishes a redirect on corpberry.com, so clients ask first. |
| `link_short_list` | `GET /short` | R | `{links: [...]}`, newest first, `limit` 1–50. |
| `link_short_revoke` | `DELETE /short/:code` | D I | — |

## cipher

One tool per op, generated at boot from the field specs ciphertools exports
(`ciphertools.Ops`): the specs its own parsers read, so the schemas can't
drift (ciphertools' `TestFieldSpecsMatchTheCode`). An op without a description
in `cipher.go` stops the boot. One adapter builds the `ciphertools.Input` a
form post would and calls `ciphertools.Run`. All are R.

| Tool | `POST` | Tool | `POST` |
|---|---|---|---|
| `cipher_jwt_decode` | `/jwt/decode` | `cipher_keys_generate` | `/keys/generate` |
| `cipher_jwt_sign` | `/jwt/sign` | `cipher_keys_inspect` | `/keys/inspect` |
| `cipher_hash` | `/hash` | `cipher_cert` | `/cert` |
| `cipher_hmac` | `/hmac` | `cipher_totp` | `/totp` |
| `cipher_password_hash` | `/password/hash` | `cipher_random` | `/random` |
| `cipher_password_verify` | `/password/verify` | `cipher_encode` | `/encode` |
| `cipher_encrypt` | `/encrypt` | `cipher_basic_auth` | `/encode/basic` |
| | | `cipher_identify` | `/identify` |

- A list field (`sets`) is a JSON array; a JSON field (`payload`, `header`)
  stays a string, so re-encoding can't reorder the claims it signs; file
  fields have no MCP form (binary goes as base64 or hex, ~750 KB at most).
- The pages run in the browser and send nothing; over MCP inputs and outputs
  (generated keys, random values) pass through this server and the user's AI
  provider, so every description ends "use test material only".

## botcheck

| Tool | REST twin | Hints | Differs from REST |
|---|---|---|---|
| `botcheck_score` | `GET /`, `POST /check` | R O | REST scores the request itself, which over MCP would be the client's HTTP stack. The tool scores what it is given: `fingerprint` (a collector payload, decoded strictly, `v` ≥ 1), `http` (a header left out counts as not sent), `ip`, any mix; none is a tool error. Rules whose input is absent are skipped, and `coverage` counts evaluated, skipped and fired checks per tier. Corpus rules are always skipped and nothing is written. Concise lists fired checks only; no `clientPayload` echo. Attribution only with `ip`. |

## site

| Tool | REST twin | Hints | Differs from REST |
|---|---|---|---|
| `site_blog` | `GET /blog`, `GET /blog/:slug` | R | REST returns the page's view model. Without `slug`: `{posts: [{slug, title, date, description, url}]}`; with it, that post plus its Markdown, frontmatter stripped, relative links and images resolved against the post's URL (code untouched). |

## Not tools

| Route or feature | Why |
|---|---|
| `GET corpberry.com/`, the JSON tool catalog | `tools/list`, the instructions and the landing page's JSON replace it. |
| `GET corpberry.com/blog/feed.xml` | RSS; `site_blog` covers the posts. |
| `GET ip.corpberry.com/history` | Addresses other visitors looked up; no agent task needs them. |
| `GET botcheck.corpberry.com/botcheck-sw.js` | The collector's service worker; collection happens in the browser under test. |
| `GET link.corpberry.com/encoding`, `/extension/privacy` | Static documents with no JSON form. |
| `GET cipher.corpberry.com/` and its 10 other page shells | Pages for the in-browser engine; the ops they post to are tools. |
| The IP page's IPv6 self-check, the Link Tools extension | Browser-side, or a client of the REST routes: not endpoints. |
| `/sitemap.xml`, `/robots.txt`, `/static/*` | SEO and assets. |
