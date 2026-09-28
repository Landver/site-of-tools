# Cipher Tools (`cipher.corpberry.com`)

JWT, hashes, HMAC, password hashing, encryption, keys, certificates, TOTP,
random values and byte encodings: one subdomain, switched by sub-nav, in the
shape of [`linktools`](../../linktools/docs/README.md).

**The crypto runs in the visitor's browser.** The same Go package that answers
the JSON API is compiled to WebAssembly and run in a Web Worker, so nothing
pasted into a page leaves the tab. That was the owner's decision, and the
reasons are in [`02` §Decision](02-build-plan.md#decision-where-the-crypto-runs).

## Read in this order

| Doc | What it settles |
|---|---|
| [`00-landscape.md`](00-landscape.md) | 16 tools surveyed; five findings, the first being that trusted tools run client-side |
| [`01-feature-inventory.md`](01-feature-inventory.md) | The menu grouped C1–C11, what ships and what was cut and why |
| [`02-build-plan.md`](02-build-plan.md) | wasm architecture, build artifacts, pages, floor order |
| [`03-correctness-traps.md`](03-correctness-traps.md) | The traps each page must get right; one test each |

## Status

| Floor | Pages | State |
|---|---|---|
| 1 | Foundation + JWT (`/`) | built |
| 2 | Hash, HMAC, Encode | — |
| 3 | Password, Random | — |
| 4 | Keys, Certificates | — |
| 5 | TOTP, Encrypt, Identify | — |

## Adding a page

1. A domain file registering its op(s) in `init()` via `register(Op{...})`: pure
   Go only, since it is also compiled to wasm.
2. A template file: the page shell (`cipher/<page>`) and result fragment(s).
   Fragments read `.Result` only; the page shell also reads `.Form`, `.Op`, `.Error`.
3. A `pages` entry in `handler.go`, plus a link in `templates/nav.html`.
4. Tests in `tests/`. `render_test.go` already checks the new op's fragment exists.

`make wasm` rebuilds the engine; `make dev` does it on every Go change.
