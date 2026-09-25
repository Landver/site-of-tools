# jsonutilities.com — Query String Parser

**Driven 2026-09-25.** `https://www.jsonutilities.com/query-string-parser`

Three views of one parse — a table, a JSON object, and a key/value card list.
Live, no submit button.

## Probe results

12 parameters found. Table (abridged):

| # | Key | Value |
|---|---|---|
| 2 | `subdistrictIds` | `6,7,8,9,10,11` |
| 5 | `id` | `1` |
| 6 | `id` | `2` |
| 7 | `debug` | *(empty)* |
| 8 | `q` | **`a b`** |
| 9 | `x` | `%20` |
| 10 | `bad` | `%zz` |
| 12 | `t` | `YWJjK2RlZg==` |

JSON output:

```json
{ "cityIdList": "95", "subdistrictIds": "6,7,8,9,10,11", "id": ["1","2"],
  "debug": "", "q": "a b", "x": "%20", "bad": "%zz", "t": "YWJjK2RlZg==" }
```

## The finding that matters

**`q=a+b` decodes to `a b` here and to `a+b` on calcbe.** Same input, same
minute, two hosted parsers, two different answers — and neither says the value
is ambiguous. calcbe at least exposes a toggle; jsonutilities picks the
form-urlencoded reading silently.

This is the single best argument in the corpus for
[A1](../01-feature-inventory.md#a1-query-string-decomposition--the-flagship)'s
rule: when a value contains `+` **and** looks like base64, show both readings
rather than choosing. Here it costs real data — `t` is base64 whose alphabet
includes `+`, and a parser that form-decodes it destroys the payload.

## Does

- Order preserved, `#` column, repeats as separate rows.
- Repeats as a JSON array — **but the JSON view is an object, so it loses the
  order the table just preserved.** Two views of one parse that disagree about
  whether position matters.
- Per-row Copy buttons.
- Documents its own behaviour up front, which is more than most: *"Hash
  fragments are ignored. Keys without `=` (e.g. `?debug`) are shown with an
  empty value."*

## Does not

- Split the comma list.
- Decode more than one layer.
- **Parse the fragment**, and says so.
- Distinguish `?debug` from `?debug=` — documented, but still a real loss: one
  means "flag present", the other "parameter set to empty".
- Warn on `%zz` **at all**. calcbe flags it; this one just prints it.
- Type values, recognise nested payloads, or offer an API. "Copy JSON" is a
  clipboard button, not an endpoint.

## For us

Same conclusion as calcbe, with one addition: **an object is the wrong output
shape for this data.** Our JSON body must be an ordered array of params, not a
map, or we reproduce exactly this bug.
