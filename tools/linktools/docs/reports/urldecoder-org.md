# urldecoder.org

**Driven 2026-09-25.** `https://www.urldecoder.org/` — the bare host 403s, the
`www.` is required.

## What it actually is

**Not a query-string parser.** A textarea-in, textarea-out percent-decoder. No
key/value table, no ordering, no structure of any kind. The plan's first draft
treated it as a competitor to the Inspect page; it competes with
[A14](../01-feature-inventory.md), the encode/decode scratchpad, and nothing else.

Options: a 57-entry source-character-set dropdown, "decode each line
separately", "decode recursively (up to 16 times)", live mode, and a 100 MB file
upload path.

## Probe results

Input, then output with **recursion off**:

```
in   …subdistrictIds=6%2C7%2C8%2C9%2C10%2C11…&q=a+b&x=%2520&bad=%zz&t=YWJjK2RlZg%3D%3D
out  …subdistrictIds=6,7,8,9,10,11…&q=a+b&x=%20&bad=%zz&t=YWJjK2RlZg==
```

With **recursion on**, the only change is `x=%2520` → `x= ` (a literal space).

| Behaviour | Result |
|---|---|
| Structure | None. One flat string |
| `%2C` → `,` | Yes, but not split |
| `+` handling | **Left as a literal `+`.** It decodes generic percent-encoded data, not `application/x-www-form-urlencoded` |
| `%2520` | One layer off by default; both layers with recursion on, as documented |
| `%zz` | **Silently passed through.** No error, no warning, both modes |
| `%3D%3D` → `==` | Correct |
| Fragment | Not treated specially — it is all one string |

## Useful

- **Recursion is a real, documented feature** with a stated cap of 16. The plan's
  ladder should cite this as prior art rather than claiming novelty; what is
  novel is doing it *per parameter, with the rungs shown*.
- The character-set dropdown is a reminder that percent-encoding carries no
  charset. Out of scope for us, but the reason a decoded value can be mojibake.

## Not useful

- Consent wall on arrival: **1,742 advertising partners**, 944 listed under
  "Purposes". A "REJECT ALL" exists but only behind "MORE OPTIONS". The page is
  unusable until it is dismissed.
- Silent `%zz` pass-through is the worst behaviour seen in the corpus: it is the
  one case where the tool cannot be right, and it says nothing.

## For us

Confirms two gaps and closes none: nobody gets structure from this, and the
`+`-as-literal reading here is the **opposite** of jsonutilities' default on the
same input.
