# Testing plan

Per `CLAUDE.md` rule #6 and [`ARCHITECTURE §9`](../../../docs/ARCHITECTURE.md):
black-box tests in `tests/`, white-box beside the code only where the subject is
unexported, `go test ./... -race`, pre-push hook stays green.

**This suite is the most testable thing in the repo.** Most features are pure
functions from a string to a struct: no BINs, no upstream, no network, no skips.

---

## 1. What goes where

| File | Location | Why |
|---|---|---|
| `tests/url_test.go` | black-box | `Parse` is exported; the corpus drives the public API |
| `tests/rebuild_test.go` | black-box | `Rebuild` — round-trip property tests |
| `tests/clean_test.go` | black-box | `Clean` is exported |
| `tests/handler_test.go` | black-box | `httptest` + `app.ServeHTTP`, fakes injected through `Inspector` |
| `tests/short_test.go` | black-box | Against a fake store; the Mongo run is separate, §5 |
| `decode_test.go` | **beside the code** | The rungs are unexported, and the caps are the thing worth testing |
| `rules_test.go` | **beside the code** | Table invariants |
| `trace_test.go` | **beside the code** | Needs the loopback seam, §4 |

---

## 2. The URL corpus

A table-driven golden corpus in `tests/testdata/`, one case per pathology from
[01 A1](01-feature-inventory.md#a1-query-string-decomposition--the-flagship).
The first is non-negotiable — it is the example the tool was asked for:

```
cityIdList=95&subdistrictIds=6%2C7%2C8%2C9%2C10%2C11%2C13%2C14%2C15%2C16%2C17%2C18%2C19%2C24&currencyId=1&rooms=1%2C2
```

| Case | Asserts |
|---|---|
| The example above | 4 params in order; `subdistrictIds` splits to 14; delimiter named `,` |
| `?b=1&a=2` | Order preserved — **the test that fails if anyone reaches for `url.ParseQuery`** |
| `?id=1&id=2` | Two params, second `Repeat: true`; neither dropped |
| `?debug` vs `?debug=` | `Valueless` differs; values both empty |
| `?q=a+b` | `a b` in the query; and `/a+b/` stays `a+b` in a **path** segment |
| `?t=YWJjK2RlZg%3D%3D` + a `+` | Both readings offered, neither chosen silently |
| `?x=%2520` | Ladder: `%2520` → `%20` → ` `, three rungs |
| `?x=%zz`, `?x=%2` | `Warn` set; the rest of the query still parses |
| `?a=1;b=2&c=3` | Semicolon form detected **and `c=3` still parsed** — `ParseQuery` returns partial values alongside its error, so a cross-check written as `if err != nil` throws away what the stdlib did parse |
| `https://paypal.com@evil.tld/` | Host is `evil.tld`; a `fail`-severity note |
| `https://xn--80ak6aa92e.com` | Both forms present and flagged as differing |
| `https://аррӏе.com` (Cyrillic) | Mixed-script label flagged — via `unicode.Scripts`, not idna |
| `/a/b/../c` | Canonical `/a/c`; both shown |
| `/a/b/..` | Canonical `/a/` — **trailing slash preserved** per RFC 3986 §5.2.4, which `path.Clean` drops |
| `/a%2Fb/c` | Two segments, not three |
| `https://example.com/a?b=1#frag` | **No spurious "parsers disagree" note** — `ParseRequestURI` puts the fragment in `RawQuery` by design |
| `#access_token=…&state=…` | Fragment params parsed |
| `?u=https%3A%2F%2Fx.com%3Fa%3D1` | Nested URL recognised, sub-parse offered |
| `?j=%7B%22a%22%3A1%7D` | Nested JSON recognised |
| `?t=eyJhbGciOi…` | JWT header+payload decoded; **no signature claim made** |
| A SafeLinks / urldefense wrapper | A16: real target extracted and named |
| `?x=` + 1 MB of base64 | Size cap trips; note emitted, no OOM |
| `not a url at all` | Clean error, not a panic |
| `javascript:alert(1)` | Parsed and displayed; never linked |

Compare with `go-cmp`, as the rest of the repo does.

**Round-trip property (A15):** for every corpus entry, `Rebuild(Parse(u))` must
parse back to an equal `Inspection`. That one property catches most encoding
mistakes without writing a case per encoding rule.

---

## 3. Rule-table invariants

`rules_test.go` asserts properties of the data, so the table can grow without
the test rotting:

- No duplicate parameter keys; every rule has a non-empty name and a source note
  (both [04 §9](04-short-links.md#9-api-contract) and the Clean page promise to
  name the rule that removed something).
- Every regex-shaped rule compiles, and is anchored.
- **No rule matches a parameter in a never-strip allowlist**: `q`, `id`, `page`,
  `token`, `code`, `state`, `redirect_uri`. Stripping an OAuth parameter breaks
  logins; this test is the guard.
- **No rule rewrites scheme, host, port or path** — only deletes query
  parameters. [04 §9](04-short-links.md#9-api-contract) depends on this to keep
  create-time validation meaningful.

---

## 4. Trace, and the loopback problem

The egress gate rejects loopback, which is where `httptest` servers live.

**The dnstools precedent, quoted accurately this time:** `dnstools` uses a
**package-level var** `resolverOverride func(key string) (string, bool)` in
`dns.go` (~line 841), nil in production, assigned once in `TestMain`
(`testserver_test.go`) behind an `sync.RWMutex`-guarded map because tests run in
parallel. (`dnstools` has no HTTP egress *allowlist* at all — the `IsLoopback`
checks in `email.go` and `spread.go` are MTA-STS-host and nameserver-address
validation, and `tests/egress_test.go` is a skip guard for hosts without UDP/53,
not a gate test.)

**Do the same job with an unexported field on `Tracer`** — per-instance, no
global, no `TestMain`, race-free without the mutex. Still a rule #6 exception,
so `trace_test.go` sits beside the code.

Then build chains locally: 3 hops; a loop; 11 hops (cap trips); a `javascript:`
`Location`; a protocol-relative `//evil.tld/` `Location`; a meta-refresh body; a
`Refresh:` **header**; a 403 shaped like bot protection; a hop that never
answers.

**Separately, and highest-value of all: assert the gate as a pure function over
`netip.Addr`.** No server needed:

```
127.0.0.1  ::1  10.0.0.1  172.16.0.1  192.168.1.1  169.254.169.254
100.64.0.1  fc00::1  ::ffff:127.0.0.1  0.0.0.0  192.0.0.1  198.18.0.1
240.0.0.1  64:ff9b::7f00:1  2002:7f00:1::  2001::1
```

Plus the header-level rules from
[06 §2](06-security-and-abuse.md#the-manual-redirect-walk): no `Referer`
forwarded, no `Authorization` across hosts, no cookie jar, downgrade flagged.
And assert `Proxy` is nil and `DisableKeepAlives` is true on the transport —
both are silent bypasses if someone "tidies" them away later.

One live-network test, following commits `2bf5a0e` and `40c39db`: trace one
known-stable real redirect, and **skip — not fail — when the upstream doesn't
answer**.

---

## 5. Mongo-backed tests

`MONGODB_TEST_URI`; skip when absent so CI and fresh clones stay green.

- **Unique-index collision**: insert the same code twice, assert the retry
  succeeds with a different code. Assert the index actually exists — its
  creation error is not swallowed
  ([04 §4](04-short-links.md#indexes)).
- **Expiry is enforced in code**: a document whose `expires_at` is in the past
  but which is still present must not resolve. This is the important one; don't
  test that Mongo's background reaper fires, since it runs on its own ~60s cycle
  and waiting on it is a flake generator.
- **`RevokedAt` blocks resolution**, and a revoked slug is not reissuable.
- **Nil store**: `NewLinkStore(ctx, nil)` returns nil and every method on the nil
  value is safe — the `iptools.History` contract.

---

## 6. Handler and template tests

Through `httptest` with fakes, asserting the three representations from one URL:

- `Accept: */*` → JSON (the domain struct, with no `Title`/`Desc` leaking in).
- `Accept: text/html` → full page.
- `HX-Request: true` → fragment only, never a full page into the swap slot.
- Bare hit, no `?u=` → empty form / empty fragment / `400`.
- **Nil `*Tracer` → `503`.** Valid only because `Tracer` is a concrete pointer;
  as an interface this test would pass while production panicked
  ([03 §2](03-architecture.md#dependency-shape--follow-dnstools-exactly)).
- **Empty `LINK_API_KEY` → `POST /short` is `503`, not `201`**, and
  `GET /short` shows no list. The fail-closed property is what keeps the domain
  off a blocklist.
- Wrong key and missing key → `401`, same body.

**Plus one template test that nothing else catches:** render every `link/*`
template name, and assert `Lookup("dns/nav")` still resolves to the DNS
sub-nav. `template.ParseFS` allows redefinition — last file wins, **no error**
— so a copied-and-unrenamed `{{define}}` silently replaces another tool's
partial at runtime.

---

## 7. Fuzzing

- `FuzzParse` — must never panic, for any input. It takes attacker-controlled
  strings by definition.
- `FuzzDecodeLadder` — never panic, always terminate, always respect the depth
  and size caps.
- `FuzzRebuild` — `Rebuild(Parse(x))` must always produce something `Parse`
  accepts.

Seed all three from the corpus in §2.

---

## 8. Coverage

`-coverpkg=./...` — black-box tests in a `tests/` sub-package report 0% for the
package under test otherwise, which is a measurement artefact.

```bash
go test ./... -race -coverpkg=./... -coverprofile=cover.out
```
