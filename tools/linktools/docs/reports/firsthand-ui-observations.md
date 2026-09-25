# Cross-cutting — UI patterns from driving all five tools

Not about any one product. What the category has converged on, what it gets
wrong, and which habits are worth copying. Same role as
[`dnstools`' report of the same name](../../../dnstools/docs/reports/firsthand-ui-observations.md).

---

## Converged on, and we should match

**One input box, no mode selector.** Every parser accepts a full URL, a bare
query string, or a path-with-query and works it out. calcbe goes further and
*tells you* which it decided: *"The input looked like a full URL or path, so
only the query string part was parsed."* Detect and announce; never ask.

**Live results, no submit button.** jsonutilities parses on keystroke. calcbe
and urldecoder.org have buttons and feel slower for it. htmx gives us the
middle position cheaply — `hx-trigger="keyup changed delay:300ms"` — and our
GET-shaped form keeps the shareable URL that pure-JS tools can't offer.

**Multiple views of one parse.** jsonutilities renders a table, a JSON object
and a card list from the same parse. Cheap with templates, and different people
want different shapes.

**Per-row copy buttons.** Both parsers have them. Copying one value out of a
table is the actual job about a third of the time.

**Worked examples as one-click loaders.** "Load raw query example" / "Load full
URL example" (calcbe), six labelled example strings (jsonutilities). Costs one
link each and removes the empty-state problem.

---

## Got wrong, consistently

**Ambiguity resolved silently.** The headline finding of the corpus: on the same
input in the same minute, calcbe returns `q=a+b` and jsonutilities returns
`q=a b`. Neither output says the value is ambiguous. calcbe at least has a
toggle; its default is just invisible in the result.

**Warnings in one pane, mutation in another.** calcbe's table correctly flags
`%zz` as a bad escape and keeps it raw — and then its "Copy normalized query"
button silently rewrites it to `%25zz` and turns `debug` into `debug=`. The
honest view and the actionable output disagree. Our
[A15 round-trip](../01-feature-inventory.md#a15-round-trip-edit) must round-trip
what was actually there, or say it cannot.

**Fragments discarded.** Both parsers drop everything after `#`. jsonutilities
documents it; calcbe just reports 12 pairs and moves on. OAuth implicit flow
puts the access token there, which makes this the single most consequential
omission in the category.

**Structure abandoned at depth one.** Every tool decodes one layer and stops. A
value that is a URL, a JSON blob or a JWT is printed as an opaque string, even
by tools that have a JSON formatter on the same site and link to it as a "next
step".

**Ordered table, unordered export.** jsonutilities preserves order in the table
and then emits a JSON *object*, losing it. Our JSON body must be an ordered
array of params.

---

## Worth stealing outright

| From | Pattern |
|---|---|
| [calcbe](calcbe-query-string-parser.md) | **Raw and decoded side by side**, per row. Better than the single-column design the plan sketched |
| calcbe | A summary strip before the table: source type, pair count, repeated-key count |
| calcbe | Naming the input shape it detected, rather than silently coping |
| [httpstatus.io](httpstatus-io.md) | **User-agent personas** (27 of them, incl. Googlebot, Slackbot, GPTBot). One dropdown, one header → [A17](../01-feature-inventory.md#a17-user-agent-persona-on-trace) |
| httpstatus.io | `Ctrl+Enter` to submit |
| [wheregoes](wheregoes-com.md) | **A 🍪 marker on hops that set a cookie.** Makes an invisible side effect visible |
| wheregoes | Not rendering a hostile URL as a live link — theirs pipe-separates the characters |
| wheregoes | Honesty notices printed on every result, unprompted, about bot-blocking and about not vouching for safety |

---

## Deliberately not copying

**Persisted, publicly-addressable results.** wheregoes mints
`wheregoes.com/trace/<id>/` for every run, storing URL, timestamp and user
agent. Convenient, and exactly the traced-URL corpus
[06 §6](../06-security-and-abuse.md#6-never-store-what-was-traced--which-is-not-currently-true)
refuses to build. Our shareable result is the *query* in the URL bar, which
costs us no storage and holds no record of who asked.

**Consent walls.** urldecoder.org fronts 1,742 advertising partners and hides
"REJECT ALL" one level down. It is the clearest single reason a self-hosted
tool has a reason to exist.

**Client-side-only as a privacy claim.** Both parsers make it — calcbe: *"The
share URL stores settings only. It never includes the URL or query string you
paste here."* It is a real property and we are **giving it up** in exchange for
a curl-able API. That trade is defensible
([00 §3](../00-landscape.md#3-whats-actually-unoccupied)) but it is not free,
and the page has to say which trade it made
([06 §5](../06-security-and-abuse.md#5-the-request-log-will-eat-pasted-urls)).

---

## The pattern that matters most

Every tool in this corpus is honest about *something* and silent about
something else. wheregoes warns you it may have been blocked but stores your
trace forever. calcbe flags a bad escape and then quietly rewrites it.
jsonutilities documents that it ignores fragments and then loses ordering in
its own export.

The differentiator available to us is not any single feature. It is being the
one that states its limits **in the place where the limit bites** — the note
next to the value, not in a FAQ at the bottom of the page.
