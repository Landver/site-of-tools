# calcbe.com — Query String Parser

**Driven 2026-09-25.** `https://calcbe.com/en/tools/query-string-parser/`

The strongest parser in the corpus, and the one that closes most of the gaps the
plan's first draft claimed were open.

## Probe results

12 pairs found. The table it renders — note it shows **raw and decoded side by
side**, which is better than what the plan sketched:

| # | Decoded key | Decoded value | Raw value |
|---|---|---|---|
| 2 | `subdistrictIds` | `6,7,8,9,10,11` | `6%2C7%2C8%2C9%2C10%2C11` |
| 5 | `id` | `1` | `1` |
| 6 | `id` | `2` | `2` |
| 7 | `debug` | *(empty)* | *(empty)* |
| 8 | `q` | `a+b` | `a+b` |
| 9 | `x` | `%20` | `%2520` |
| 10 | `bad` | `%zz` | `%zz` |
| 12 | `t` | `YWJjK2RlZg==` | `YWJjK2RlZg%3D%3D` |

Three warnings fired, unprompted:

> The input looked like a full URL or path, so only the query string part was parsed.
> At least one key appears more than once. Keep the row order if duplicates are meaningful.
> **Some key/value pairs contain invalid percent-escape sequences. Those rows stay visible in raw form.**

## Does

- **Order preserved**, with an explicit `#` column.
- **Repeated keys as separate rows**, plus a "Repeated keys: 1" summary count.
- **Catches malformed escapes and says so.** This directly closes a gap the
  plan's first draft claimed. Row 10 keeps `%zz` in raw form rather than
  mangling it.
- **Surfaces the `+` ambiguity as a toggle** — "Treat + as space when decoding",
  default **off**. Also "Sort keys in normalized output", default off.
- Detects source type (raw query vs full URL vs path with query).
- Raw and decoded columns side by side.
- Client-side only, and says so plainly: *"The share URL stores settings only.
  It never includes the URL or query string you paste here."*

## Does not

- **Split the comma list.** Row 2 is one value, fourteen numbers, unreadable.
  The single clearest surviving gap in the category.
- **Decode more than one layer.** `x` stops at `%20`.
- **Parse the fragment.** `#frag=1&token=abc` is dropped entirely; "Pairs: 12"
  excludes it. An OAuth implicit-flow token is invisible.
- Recognise a nested URL, JSON or JWT. `t` is base64 of `abc+def` and is
  reported as an opaque string.
- Offer an API, or let you edit a value and rebuild.

## One inconsistency worth recording

Its table is honest about `%zz`; its **"Copy normalized query" output is not**.
The normalized string it hands you is:

```
…&q=a%2Bb&x=%2520&bad=%25zz&…
```

`%zz` has been silently rewritten to `%25zz` — a different URL from the one
pasted in — and `debug` has become `debug=`. So the copy button quietly repairs
data the table correctly flagged as broken. A tool that warns in one pane and
mutates in the other is a good cautionary example for our own round-trip
feature ([A15](../01-feature-inventory.md)): **the rebuild must round-trip what
was actually there, or say it can't.**

## For us

Closes: ordered output, repeats as rows, malformed-escape detection,
`+`-ambiguity surfacing. Those are no longer differentiators and the plan should
stop claiming them.

Leaves open: list splitting, layered decoding, fragment parsing, value typing,
JSON API, round-trip edit.
