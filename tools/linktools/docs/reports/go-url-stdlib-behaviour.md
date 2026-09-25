# Reference — what Go's `net/url` actually does

**Executed 2026-09-25**, Go 1.26, against the corpus probe URL. Every line below
is program output, not recollection. These are the behaviours the Inspect page
is built on, and five of them are traps.

Probe:

```
https://example.com/a/b/../c?cityIdList=95&subdistrictIds=6%2C7%2C8&id=1&id=2&debug&q=a+b&x=%2520&bad=%zz&t=YWJjK2RlZg%3D%3D#frag=1&token=abc
```

---

## 1. `ParseQuery` returns partial results *alongside* an error

```
ParseQuery err=invalid URL escape "%zz"  len=7
keys=map[cityIdList:[95] debug:[] id:[1 2] q:[a b] subdistrictIds:[6,7,8] t:[YWJjK2RlZg==] x:[%20]]
```

Eight pairs went in, **seven came back, and `bad` is simply absent**. The
offending pair is dropped and an error is returned with the rest of the data
intact.

So `if err != nil { return }` throws away seven good pairs, and
`if err == nil` as a validity check silently loses one. Neither is right.
This is the strongest argument for hand-splitting rather than calling
`ParseQuery` at all — and for keeping it only as a cross-check that compares
**key sets**, never `err`.

Same shape for semicolons:

```
ParseQuery("a=1;b=2&c=3") → err=invalid semicolon separator in query, values=map[c:[3]]
```

Both `a` and `b` vanish. Go has rejected `;` separators since 1.17.

## 2. `QueryUnescape` returns the empty string on a bad escape

```
QueryUnescape("%zz") = "" err=invalid URL escape "%zz"
```

**Not** the original text. Ignore the error and the value becomes empty, which
looks like `?bad=` — a real value, wrongly. The Inspect page must keep the raw
text and set a warning, never take the return value on error.

## 3. `+` decodes differently depending on which function you call

```
QueryUnescape("a+b") = "a b"
PathUnescape("a+b")  = "a+b"
```

This is the ambiguity that [calcbe](calcbe-query-string-parser.md) and
[jsonutilities](jsonutilities-query-string-parser.md) answer differently. The
stdlib offers both readings and makes the caller choose — correctly. Using
`QueryUnescape` on a path segment renders `/a+b/` as `/a b/`.

## 4. `ParseRequestURI` is not the stricter parser it looks like

```
"javascript:alert(1)"           Parse(host="",err=nil)          ParseRequestURI(host="",err=nil)
"https://paypal.com@evil.tld/"  Parse(host="evil.tld",err=nil)  ParseRequestURI(host="evil.tld",err=nil)
"example.com/a"                 Parse(host="",err=nil)          ParseRequestURI(err=invalid URI for request)
"//evil.tld/x"                  Parse(host="evil.tld",err=nil)  ParseRequestURI(host="",err=nil)
```

It adds **no** validation of hostile schemes or userinfo. It differs in exactly
two ways, and both matter:

- It rejects relative references — its one genuine use, the missing-scheme check.
- **It does not split the fragment:**

```
Parse:            RawQuery="…&t=YWJjK2RlZg%3D%3D"  Fragment="frag=1&token=abc"
ParseRequestURI:  RawQuery="…&t=YWJjK2RlZg%3D%3D#frag=1&token=abc"  Fragment=""
```

So a "run both and report the disagreement" check fires on **every URL
containing a `#`**. Strip the fragment before comparing, or the feature is
noise.

**The protocol-relative trap:** `//evil.tld/x` gives `host=evil.tld` from
`Parse` and `host=""` with **no error** from `ParseRequestURI`. A redirect walk
that resolves `Location` with the wrong one treats an off-host redirect as a
same-host path. Directly relevant to
[06 §2](../06-security-and-abuse.md#the-manual-redirect-walk) rule 1.

## 5. `path.Clean` is wrong for URLs, three separate ways

```
path.Clean("")           = "."          // should stay empty
path.Clean("/a/b/")      = "/a/b"       // trailing slash dropped
path.Clean("/a/b/..")    = "/a"         // RFC 3986 §5.2.4 gives "/a/"
path.Clean("/a/b/../c")  = "/a/c"       // correct
```

And the one that corrupts data:

```
url.Parse("https://x.com/a%2Fb/c")
  → Path         = "/a/b/c"      // %2F already decoded to a real slash
    EscapedPath  = "/a%2Fb/c"
  → path.Clean(Path) = "/a/b/c"  // two segments became three
```

`u.Path` is **already percent-decoded**, so an encoded slash inside a segment is
indistinguishable from a separator by the time you reach it. Resolve dot
segments over `u.EscapedPath()` with a hand-rolled `remove_dot_segments`, and
`PathUnescape` each segment only for display.

## Summary for implementers

| Trap | Rule |
|---|---|
| `ParseQuery` drops bad pairs and still errors | Hand-split; compare key sets, never `err` |
| `QueryUnescape` returns `""` on error | Keep the raw text, set a warning |
| `+` means space only in queries | `QueryUnescape` for query, `PathUnescape` for path |
| `ParseRequestURI` keeps `#` in `RawQuery` | Strip the fragment before any comparison |
| `//host/x` parses host-less with no error | Resolve `Location` with `Parse`, not `ParseRequestURI` |
| `u.Path` has `%2F` already decoded | Work on `EscapedPath()`; never `path.Clean` a URL |

Every one of these has a case in
[07 §2](../07-testing.md#2-the-url-corpus).
