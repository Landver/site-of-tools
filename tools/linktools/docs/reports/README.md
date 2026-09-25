# Research corpus — Link Tools

Firsthand reports behind [the build plan](../README.md). Same shape as
[`dnstools/docs/reports/`](../../../dnstools/docs/reports/): one file per tool,
driven live, findings quoted rather than remembered.

**Method.** Every parser was given the same probe URL, so the reports compare
like for like:

```
https://example.com/a/b/../c?cityIdList=95&subdistrictIds=6%2C7%2C8%2C9%2C10%2C11&currencyId=1&rooms=1%2C2&id=1&id=2&debug&q=a+b&x=%2520&bad=%zz&utm_source=test&t=YWJjK2RlZg%3D%3D#frag=1&token=abc
```

It exercises, in one string: dot segments (`/a/b/../c`), percent-encoded comma
lists, repeated keys (`id`), a valueless key (`debug`), plus-encoding (`a+b`),
double encoding (`%2520`), a **broken escape** (`%zz`), a tracking parameter,
base64 with padding and a `+` in the alphabet (`t`), and **fragment parameters**
carrying a token.

| Report | Category | Method |
|---|---|---|
| [urldecoder-org.md](urldecoder-org.md) | Percent-decoder | driven |
| [calcbe-query-string-parser.md](calcbe-query-string-parser.md) | Query parser | driven |
| [jsonutilities-query-string-parser.md](jsonutilities-query-string-parser.md) | Query parser | driven |
| [httpstatus-io.md](httpstatus-io.md) | Redirect tracer | driven |
| [wheregoes-com.md](wheregoes-com.md) | Redirect tracer | driven |
| [unshorten-it.md](unshorten-it.md) | Unshorteners | driven, incl. their APIs |
| [metadata-preview-tools.md](metadata-preview-tools.md) | OG / preview | driven |
| [extension-shelf.md](extension-shelf.md) | Browser extensions | listings + Chromium source |
| [tracking-parameter-reference.md](tracking-parameter-reference.md) | Rule catalog | ClearURLs measured + hand-built table |
| [wrapper-formats.md](wrapper-formats.md) | Wrapper formats | algorithms executed |
| [go-url-stdlib-behaviour.md](go-url-stdlib-behaviour.md) | Reference | executed |
| [firsthand-ui-observations.md](firsthand-ui-observations.md) | Cross-cutting | synthesis |

All driven 2026-09-25.

## The findings that changed the plan

1. **The parsers are better than assumed.** calcbe preserves order, keeps
   repeats as rows, *and catches malformed escapes*. Three claimed gaps, already
   closed.
2. **Two parsers disagree on `+`, silently, on the same input.** calcbe returns
   `a+b`, jsonutilities returns `a b`. Neither flags it. The strongest single
   argument in the corpus for showing both readings.
3. **ClearURLs is missing the click IDs that matter most** — `gbraid`, `wbraid`,
   `gclsrc` and `ttclid` appear in zero of its 733 rules. A hand-written table
   beats the public catalog at the head of the distribution and only loses the
   regional ESP tail. Decision settled at 80%: hand-write.
4. **Adopting ClearURLs would break "delete query parameters only" four ways**,
   not one: 64 redirections, 4 rawRules that cut a path segment or fragment, 10
   blocklist entries, and a rule-compilation shape whose delimiter class
   includes `/` and `#`. Adoption is a rewrite, not a data import.
5. **The double-decode instinct is backwards.** Safe Links `url=` must be decoded
   **exactly once**; a second pass eats the target's own `%20`. The stop rule is
   "re-decode only while the result is not yet an absolute URL".
6. **metatags.io renders the *previous* site's preview when a fetch fails** — a
   confident, plausible, entirely wrong answer. The strongest argument for
   failing loudly.
7. **The BYO-key extension model is empirically dead.** Shlink's published MV3
   extension, which requires your own server, has 337 users after four years.
   Raises the lean against publishing ours.

## What none of the parsers do

Split delimited lists, decode more than one layer *with structure*, parse
fragment parameters, recognise a nested URL / JSON / JWT, offer a free JSON API,
or let you edit a value and get a URL back.

## The recurring bug worth naming

Three separate tools ship a **view that is honest and an export that is not**:
calcbe's table flags `%zz` and its copy button rewrites it to `%25zz`;
jsonutilities preserves order in its table and loses it in its JSON object;
metatags.io's "Get Code" emits its own logo as `og:image`. Whatever we render,
the copy button must emit the same thing.
