# Architecture — package layout, types, routes, wiring

Follows [`ARCHITECTURE §4`](../../../docs/ARCHITECTURE.md) (domain below
transport, one feature speaks three representations) and `CLAUDE.md` rules #1,
#2 and #5. Nothing here is novel; it is `dnstools` in a different problem
domain, and where this doc's first draft diverged from `dnstools` it was wrong.

---

## 1. Package layout

`tools/linktools/`, Go package `linktools`, subdomain `link.corpberry.com`
(dev: `link.localhost:8080`). Self-contained, one folder.

```
tools/linktools/
├── types.go        shared domain types: Inspection, Param, Layer, Note, Kind
├── url.go          domain — Parse: anatomy + ordered query decomposition (A1, A2, A12)
├── rebuild.go      domain — Rebuild: the write half of Inspection (A15)
├── decode.go       domain — the decode ladder + value classifier (A3)
├── clean.go        domain — tracking-param stripping + wrapper unwrapping (A4, A5, A16)
├── rules.go        data   — the rule tables: 95 trackers, 64 never-strip, 21 wrappers
├── diff.go         domain — compare two Inspections (A13)
├── encode.go       domain — every encoding of one value at once (A14)
├── extract.go      domain — URLs out of pasted HTML/Markdown/text (A18)
├── curlgen.go      domain — URL <-> curl, both directions (A19)
├── trace.go        domain — redirect chain + UA personas (A6, A17)
├── short.go        domain — alias create/resolve service (A7)
├── store.go        below domain — Mongo repository for short.go (rule #5)
├── resolvecache.go below domain — resolveCache (TTL cache) + hitBatcher (batched hit writer)
├── handler.go      transport — Register, negotiation, rate limits, SitemapPages
├── embed.go        //go:embed templates
├── templates/
├── tests/          black-box, exported API only
├── extension/      the browser extension — no .go files, invisible to the toolchain
└── docs/           these files
```

There is no `canonical.go`: canonicalisation turned out to be twenty lines
(`canonicalise` in `url.go`) rather than a file's worth, because the lossy half
— stripping — lives in `clean.go` and the lossless half is just lowercasing,
default-port removal and `removeDotSegments`.

Phase boundaries map onto files cleanly. `handler.go` grows by one route group
per phase.

### Why these splits

- **`url.go` vs `decode.go`.** The ladder is called from inside `Parse` for
  nested values *and* stands alone. Keeping it separate means it can be
  depth-capped and fuzzed on its own terms.
- **`clean.go` vs `canonical.go`.** Stripping is lossy and needs a rule table;
  normalising is not. Merging them makes "normalise but don't strip" impossible,
  which is what a signed URL needs.
- **`rules.go` separate.** 300+ lines of data. It is also the file that changes
  most often and the one whose sourcing is still an open decision
  ([02 §4](02-build-fit.md#4-what-we-are-not-matching-and-the-clearurls-decision)).
- **`store.go` below `short.go`.** Rule #5: no driver types reach `handler.go`.
- **`resolvecache.go` beside `store.go`, not inside it.** `LinkStore` holds both
  of them, but neither is persistence: they are the two bounds on `/s/:code`,
  the one unauthenticated, un-rate-limited route in the suite
  ([04 §7](04-short-links.md#7-abuse-controls-summarised)). Keeping them out
  leaves `store.go` a plain document mapping, and lets the negative-cache and
  coalescing rules — the parts with the interesting failure modes — be read and
  tested without a database in the picture.

---

## 2. Domain types

The shape of `Inspection` is the whole design of the flagship page.

```go
// Inspection is one parsed URL. Field order mirrors the URL's own left-to-right
// shape so a template can walk it without reordering. Parse is pure and opens no
// connection — but see docs/06 §5: the URL still reaches Mongo, stdout, nginx and
// Cloudflare through the ordinary request path, so this is "we don't fetch it",
// not "it never leaves the box".
type Inspection struct {
	Input       string    `json:"input"`
	Canonical   string    `json:"canonical,omitempty"`
	Scheme      string    `json:"scheme"`
	User        string    `json:"user,omitempty"`
	HasPass     bool      `json:"has_password,omitempty"` // value never echoed
	Host        string    `json:"host"`
	HostASCII   string    `json:"host_ascii,omitempty"`   // punycode form
	HostUnicode string    `json:"host_unicode,omitempty"` // display form
	Port        string    `json:"port,omitempty"`
	DefaultPort bool      `json:"default_port,omitempty"`
	Path        string    `json:"path,omitempty"`
	Segments    []Segment `json:"segments,omitempty"`
	Params      []Param   `json:"params,omitempty"`
	Fragment    string    `json:"fragment,omitempty"`
	FragParams  []Param   `json:"fragment_params,omitempty"` // OAuth implicit flow
	Unwrapped   string    `json:"unwrapped,omitempty"`       // A16: the real target
	Notes       []Note    `json:"notes,omitempty"`
}

// Param is one key=value pair in the order it appeared. Repeated keys produce
// one Param each — collapsing to last-wins hides a real class of bug.
type Param struct {
	Index     int      `json:"index"`
	Key       string   `json:"key"`
	RawKey    string   `json:"raw_key,omitempty"`   // set only when decoding changed it
	Value     string   `json:"value"`
	RawValue  string   `json:"raw_value,omitempty"`
	Repeat    bool     `json:"repeat,omitempty"`    // 2nd+ occurrence of this key
	Valueless bool     `json:"valueless,omitempty"` // "?debug", no "=" at all
	Kind      Kind     `json:"kind,omitempty"`      // number, bool, url, json, jwt, base64, uuid, timestamp
	List      []string `json:"list,omitempty"`      // split when the value is delimited
	Delimiter string   `json:"delimiter,omitempty"` // named, never applied silently
	Layers    []Layer  `json:"layers,omitempty"`    // the decode ladder, when it went deeper
	Tracking  string   `json:"tracking,omitempty"`  // rule name, when clean.go would strip this
	Warn      string   `json:"warn,omitempty"`      // bad escape, ambiguous "+", non-UTF8
}

type Layer struct {
	Depth  int    `json:"depth"`
	Method string `json:"method"` // "percent", "base64url", "json", "jwt-payload"
	Value  string `json:"value"`
}

// Note reuses the fail/warn/ok/info vocabulary dnstools already renders.
type Note struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
}
```

`Tracking` on `Param` is what makes the suite cohere: Inspect can mark a known
tracker without Clean being involved, because both read one table.

### Dependency shape — follow dnstools exactly

The first draft made every dependency an interface. That breaks the repo's
"nil means off" contract: a `(*Tracer)(nil)` stored in a `Tracer` interface is
**not** `== nil`, so the 503 branch never runs and the first call panics into a
recovered 500. `dnstools` holds its optional dependencies as **concrete pointer
fields** (`dom *DomainClient`, and `iptools` does the same with `shodan
*Shodan`) precisely so the nil check works.

- **One stateless `*Service` does all the pure work** — parse, rebuild, clean,
  unwrap, diff, extract, curl. It is passed as a **concrete `*Service`**, not
  behind an interface. The `Inspector` interface still exists in `url.go` and is
  what the tests fake, but `Register` does not take it: an interface parameter
  here would buy nothing and would reintroduce the nil-in-interface trap below
  for the one dependency that must never be nil.
- **`*Tracer` and `*Shortener` are concrete pointers** with nil-receiver-safe
  methods and a `linktools.ErrDisabled` sentinel, in the `dnstools.DomainClient`
  shape. `NewShortener` returns `nil` when `links == nil || apiKey == ""`;
  `NewTracer` returns `nil` when handed a nil guard.
- **`svc` is not optional.** A nil one is a wiring mistake, so `Register`
  panics on it — exactly as `dnstools.Register` does for `svc`.
- **`base`** is the tool's own origin, used to print copy-pasteable `curl`
  examples on each page. `Shortener` holds its own copy and owns the `/s/`
  prefix, so this is the bare origin.

```go
func Register(e *echo.Echo, svc *Service, trace *Tracer, short *Shortener, base string)
```

---

## 3. Route table

```
GET  /                 Inspect              ?u=<url>                  [p0]
GET  /diff             Compare two URLs     ?a=<url>&b=<url>          [p0]
GET  /curl             URL <-> curl         ?u=<url> | ?curl=<cmd>    [p0]
GET  /encoding         Percent-encoding reference (static)            [p0]
GET  /clean            Clean                ?u=<url>&sort=&strip=     [p1]
GET  /clean/rules      The rule table, versioned — the extension caches this
GET  /utm              Campaign URL builder                           [p1]
GET  /encode           Encode / decode playground                     [p1]
GET  /short            Short-link console                [X-Api-Key]  [p2]
POST /short            Create an alias                   [X-Api-Key]  [p2]
GET  /s/:code          The redirect itself                            [p2]
GET  /trace            Trace                ?u=<url>&ua=<persona>     [p3]
GET  /extract          URLs out of pasted text
POST /extract          Same, for input too large for a query string

GET  /extension/privacy  Privacy policy for the extension listing
GET  /sitemap.xml      platform.RegisterSEO
GET  /robots.txt       platform.RegisterSEO
```

**`GET /clean/rules` is content-negotiated, not a `.json` endpoint.** A `.json`
suffix hard-codes one representation and would be the only route in the repo
doing so, against golden rule #2. JSON to the extension and to `curl`, a
human-readable rules page to a browser — which is also what discharges
[02 §4](02-build-fit.md#4-what-we-are-not-matching-and-the-clearurls-decision)'s
promise to state the catalog's scope — and the table fragment to htmx.

**`GET /short` is key-gated.** The first draft left it public while
[04 §3](04-short-links.md#3-codes) argued that code entropy protects the alias
space. A public console listing every alias and target hands over the whole
corpus with no guessing, and turns `hits`/`last_hit_at` into a read-receipt
oracle. Unauthenticated callers get the create form and nothing else.

Conventions inherited without change:

- **Query-param only, GET-shaped**, so every result is a shareable URL. `?u=` on
  every page, so switching pages carries the URL across.
- **A bare hit** is the empty form to a browser, an empty fragment to htmx, and
  `400` to a JSON caller — `dnstools.needName`'s shape, here `needURL`.
- **`503` not `502`** when a dependency is switched off.

### Negotiation: a local `reply`, not `platform.Respond`

`platform.Respond` is **apex-only** — it is called in `site/` and by no tool in
the repo — and it cannot work here for a concrete reason: every page template
includes `{{template "partials/head" .}}`, which dereferences `.Title`, `.Desc`,
`.OGType`, `.Canonical` and friends. A missing *map* key renders empty; a
**struct** without those fields makes `html/template` return an execution error
and the page 500s. Passing the view-model map to `Respond` instead leaks
`Title`/`Desc`/`Active` into the JSON body.

So all routes use a local helper in the `dnstools` shape — JSON gets the domain
struct, HTML gets a `map[string]any`:

```go
func reply(c *echo.Context, code int, body any, vm map[string]any, page, frag string) error
```

`/s/:code` is the one route that is not negotiated at all: it is a redirect for
every caller, including `Accept: application/json`, because an extension
resolving a link wants the behaviour, not the metadata.

### Reserved paths

`/s/:code` under a prefix means page names and alias names can never collide —
[04 §2](04-short-links.md#2-where-the-redirect-lives). Custom slugs are still
validated against a reserved list so a future move to root-level codes stays
possible:

```go
// Every page name, plus the ones a future page might want. Cheap to over-reserve
// now; impossible to reclaim later without breaking a link someone already has.
var reserved = []string{
	"s", "clean", "trace", "short", "preview", "api", "static", "extension",
	"diff", "curl", "encoding", "encode", "utm", "extract", "qr", "rules",
	"robots.txt", "sitemap.xml", "health", "favicon.ico", "admin", "login",
}
```

The sub-nav cannot hold ten entries. Group them: **Inspect · Clean · Short ·
Trace** as the primary switcher, with Diff, curl, UTM, Encode, Extract and the
encoding reference behind a "More" item, in the shape `iptools` already uses for
its secondary pages.

---

## 4. Templates

`{{define}}` names must be unique across the whole parsed set
([`platform/render.go`](../../../platform/render.go) parses every source into
one `*template.Template`), so everything here is prefixed `link/`.

A file is not a define. `reply` is handed a *page* name and a *fragment* name
and picks one, so wherever both representations exist they need **distinct**
names — and because a page template renders its own fragment inline
(`{{template "link/cleaned" .}}` inside `link/clean`), a shared name would be
infinite recursion rather than reuse. Hence the `-ed` pairs:

```
nav.html        link/nav                       suite sub-nav: four primary entries + a "More" group
index.html      link/index                     Inspect, page
inspect.html    link/inspect                   Inspect, fragment — also rendered inside link/curled
clean.html      link/clean + link/cleaned      page + fragment
rules.html      link/rules + link/rulerow      the rule table, human-readable; rulerow is one row, reused per class
trace.html      link/trace                     page
chain.html      link/chain                     Trace fragment
short.html      link/short + link/created      console page + the created-alias fragment
privacy.html    link/privacy                   extension privacy policy
diff.html       link/diff + link/diffed        A13, a second view over two Inspections
curl.html       link/curl + link/curled        A19
encoding.html   link/encoding                  A20, static reference
utm.html        link/utm + link/utmbuilt       A11
encode.html     link/encode + link/encoded     A14
extract.html    link/extract + link/extracted  A18
notes.html      link/notes                     the shared severity-note list
error.html      link/error + link/ratelimited  the generic error fragment, and the 429 one
```

Two names are passed as *both* halves of a pair, deliberately.
`/clean/rules` renders `link/rules` to page and fragment alike — the table is
the entire page, so there is nothing smaller to swap. `GET /short` does the same
with `link/short`: the console is the form plus the list, and htmx only ever
replaces the whole thing. `POST /short` is the route that needs the pair, and it
gets `link/created`.

Three constraints that bite here specifically:

- **Duplicate `{{define}}` names fail silently.** `template.ParseFS` allows
  redefinition — last file wins, no error. Copying `dns/nav` into `link/nav.html`
  and forgetting to rename the define would replace the DNS tool's sub-nav at
  runtime rather than failing the build. Guard it with a test
  ([07 §6](07-testing.md#6-handler-and-template-tests)).
- **Tailwind only sees literal class strings.** Severity colours written out per
  branch, never composed in Go. `dnstools`' `notes.html` is the working example.
- **Never render user input into an `href` unchecked.** `html/template` does
  neuter `javascript:` in URL context, but the Inspect page's job is displaying
  hostile URLs. Render as text; link only when the scheme passed the allowlist.
  [06 §8](06-security-and-abuse.md#8-rendering-hostile-urls).

---

## 5. Storage

One collection, `links`. Schema and indexes in
[04 §4](04-short-links.md#4-storage). Nothing else persists anything:
**deliberately no inspection history.** `dnstools` declined a lookup history on
the grounds that a domain plus a requester IP is closer to "who looked up what"
than `iptools`' IP history; a pasted URL is strictly worse, since it may carry a
session token.

That intent is currently defeated by `platform`'s request log, which records
every `?u=` regardless of what this package writes
([06 §5](06-security-and-abuse.md#5-the-request-log-will-eat-pasted-urls)). The
claim in this section is only true once that is fixed.

---

## 6. `main.go` wiring

Two hunks, not one. The store's index creation **must** happen inside the
existing `idxCtx` window: `cancelIdx()` runs at `main.go:58`, long before the
tool app blocks at ~line 130. Calling `NewLinkStore(idxCtx, …)` down there
compiles fine and hands it a cancelled context, so **neither index is ever
created** — which silently invalidates
[04 §3](04-short-links.md#3-codes)'s "let the unique index do it" collision
strategy.

```go
// (1) inside the idxCtx window, after `blocklist := iptools.NewBlockList(...)`,
//     BEFORE cancelIdx():
links := linktools.NewLinkStore(idxCtx, mdb.DB()) // nil db -> nil store -> creation off

// (2) after the dnstools app block:
// link.corpberry.com — URL inspect / clean / trace / short links. Parsing is
// pure; only /trace dials out, and only through the egress gate in trace.go.
short := linktools.NewShortener(links, cfg.LinkAPIKey, cfg.URL("link")) // nil when either is absent; ShortURL owns the "/s/" prefix
tracer := linktools.NewTracer(10 * time.Second)                              // nil -> /trace answers 503
linkApp := platform.NewApp(renderer, staticFS, cfg.IsDev(), reqlog)
linktools.Register(linkApp, linktools.NewService(), tracer, short)

// import + renderer source + SEO + vhost map, beside the existing entries:
platform.TemplateSource{Embed: linktools.Templates, DevDir: "tools/linktools/templates"},
platform.RegisterSEO(linkApp, cfg.URL("link"), linktools.SitemapPages)
cfg.VHost("link"): linkApp,
```

Config gains one field in `platform/config.go`:

```go
// Short-link creation API key. Empty disables the write path AND the console
// entirely — the redirect path (/s/:code) stays public. Deliberately
// fail-closed: an unset key means nobody can create links, never that anybody can.
LinkAPIKey string
// ...
LinkAPIKey: os.Getenv("LINK_API_KEY"),
```

And `site/site.go`'s catalog gains an entry. The three existing entries are
single sentences describing capability; none says "free", "open source" or "JSON
API included", because all three are true of every tool on the site:

```go
{
	Name: "Link Tools",
	Desc: "Take a URL apart: every query parameter decoded, ordered and typed, with repeated keys, comma-lists and nested encodings made readable; then strip its tracking parameters, follow where it redirects, and shorten what's left.",
	URL:  cfg.URL("link"),
},
```

**Pre-existing, worth fixing while that file is open:** the apex `home`
handler's `Desc` still advertises only "Bot check … and IP Tools" and was never
updated for DNS Tools. Adding a fourth tool without fixing it makes it two tools
stale.

`SitemapPages` lists tool pages only. `/s/:code`, `POST /short` and
`/extension/privacy` have no business in a sitemap — and `/s/:code` additionally
needs `X-Robots-Tag: noindex`
([06 §10](06-security-and-abuse.md#10-operational-controls)).

---

## 7. Deployment delta

Per [`DEPLOYMENT §3`](../../../docs/DEPLOYMENT.md), a new subdomain is three
things outside the binary: a proxied Cloudflare DNS record, an nginx block
copied from the `dns` one (with `proxy_set_header Host $host;`, or host routing
collapses), and `nginx -t` + reload.

Note that `deploy/nginx/` **does not exist in this repo** — the canonical blocks
live on the host per DEPLOYMENT §3. Either create the directory as that doc
describes, or drop the reference. And because this tool introduces
`created_ip` as forensic evidence, the `CF-Connecting-IP` trust invariant from
DEPLOYMENT §4 needs reconfirming for this vhost specifically
([06 §9](06-security-and-abuse.md#9-claims-that-need-qualifying)) —
`dnstools/docs/02-build-fit.md` already asks every new subdomain to do this.

Plus `LINK_API_KEY` in the production `.env`. No new bind mount: this tool ships
no data files, and Mongo creates `links` lazily on first write.
