---
title: "The bug is still there. There's just more code around it now."
description: "I lost my temper at a coding agent for fixing a bug by burying it under four patches, then went looking for research on whether it's a real pattern. It is, it has a name, and most of the advice about it measures worse than nothing."
date: "2026-07-30"
image: "/static/img/patch-on-patch.png"
---

![A git diff titled "fix: stale value returned from cache", showing four stacked patches added and zero lines deleted, with the original buggy line untouched at the bottom](/static/img/patch-on-patch.png)

Last week I asked an agent to fix one bug in a worker that reads from a cache.
What came back was four patches stacked on top of each other like a wedding cake,
and at the bottom, untouched, still breathing, was the line that caused the whole
thing.

Patch one cleared the cache when the entry looked stale. Patch two handled clearing it
racing the writer. Patch three initialised the lock patch two assumed existed. Patch four
gave up after three tries and returned `{"ok": True, "stale": True}`, so the caller would
stop asking.

Forty-one lines added. Zero deleted. All tests green.

I typed something at it that I wouldn't say to a person. Lightly cleaned up,
because my English gets worse in proportion to my blood pressure:

> so you decided to add complexity, add code, add variables, add fucking
> workarounds, add patches. Do you want to cause me harm? Make me suffer? Give
> me more work in the future to support those patches? Maybe do your job and
> write the code properly, from zero, to decrease complexity?

I'm 37. I've known for years that shouting at software fixes nothing. I did it
anyway, at two in the morning, in a repo I write for fun on weekends, which is
the part that annoys me most. Then I went to find out whether I was being unfair.

I was, a bit. But less than I expected.

Two claims are in play and I only get to keep one. The strong one, that AI makes
repositories grow, I can't support, and I'll hand it back later. The narrow one is the
title: around the line that caused this bug there is now more code than there was, and
less chance anyone goes back and makes the four things one thing. A repo can shrink on
net while every bug site quietly gets fatter.

My prompt was also garbage. A stack trace and one sentence, no invariant. Skill issue,
and there's a number on how much of one further down. What kept me reading is that
this isn't a story about one bad prompt.

## The thing has a name

In May a group at ETH Zurich published a benchmark that does something I'd never thought
to do. It gives coding agents 200 tasks where the correct answer is to do nothing. The
bug is already fixed. The code is fine. Go ahead.

Five models across four frameworks changed the code anyway in 35 to 65% of those
cases. Even the best of them touched code it should have left alone about a third of
the time. The paper's diagnosis is the line I'd been looking for since Tuesday:

> our results indicate that LLMs fall prey to an action bias: they choose to act
> even if inaction would be appropriate

That's [Coding Agents Don't Know When to Act](https://arxiv.org/abs/2605.07769).
Hand a model working code and tell it to fix the bug, and half the time it finds
something to do to it, because doing something is what it's for.

IBM then looked at what happens when you let an agent iterate a patch against tests until
they pass, which is the loop most of us run all day. Overfitting got worse. Their figure 1
is my Tuesday: refinement took a real fix and replaced it with a `try`/`except` that
swallows the error and returns a placeholder. Passed the generated test, failed the real
one. Of 22 patches refinement rescued into passing, 14 failed the hidden tests
([IBM](https://arxiv.org/abs/2511.16858)). Offered the code or the test to edit, those
agents went for the code six times out of seven, because the model "believes that the
tests are mostly perfect."

And the direction it diverges isn't random. Of the patches SWE-bench Verified calls
solved, 29.6% behave differently from what the developer wrote, and those "tend to
introduce additional changes rather than omitting necessary changes"
([PatchDiff](https://arxiv.org/abs/2503.15223)).

Fine. I feel seen. The interesting question is why.

## Why it does it

The oracle is "tests pass," not "design improved." This is the whole thing. The
cheapest way to make a failure signal stop is to stop the signal, and nothing in the
loop distinguishes a fix from a well-placed `except`. The IBM result is the proof: the
more you iterate against tests, the more of your fixes become suppressions.

It can see the crash site but not the invariant. One taxonomy of repair failures has a
category for exactly this: everything needed for the fix is in the codebase, and none
of it is visible from the method body the model was handed. From inside a 40-line
window, adding a guard is the only move the model can actually see.

Action bias, which isn't the same thing. "No change needed" isn't in the action space
the model believes it has, and the fact that this responds so strongly to phrasing
suggests a learned habit rather than a ceiling.

[Armin Ronacher](https://lucumr.pocoo.org/2026/6/23/the-coming-loop/) gets at the
shape of it better than I can, writing about present-day models being "too
defensive, too complex, too local in its reasoning," and then landing the actual
principle: they "add fallbacks instead of making bad states impossible."

That's my complaint, stated properly. The problem was never that it added code.
**You added a defence at a distance from the invariant it was compensating for.** Patch three existed to
serve patch two. None of them knew why patch one was there.

Anthropic's own docs warn that a reviewer agent told to find gaps will find them, and that chasing all of them "leads to
over-engineering: extra abstraction layers, defensive code, and tests for cases that
can't happen." The vendor documented my bug.

## Where I'm wrong

Nobody has measured the thing I actually said. No study separates bug-fix patches from
features and compares net lines added by a model against the human who fixed the same bug.
I went looking three times. Everything above is mechanism and proxy, and one good study
could take it apart.

The aggregate version doesn't survive either, and neither does the number I thought had
killed it. Faros AI has the ratio of lines deleted to lines added up 861% under heavy AI
use, across 22,000 developers. I read that as the end of this post for about an hour. A
ratio moving isn't a codebase shrinking, though: 0.05 to 0.48 is an 861% rise and still
two lines added for every one removed, and Faros won't say which it is. Agent pull
requests are also *smaller* than human ones, across [29,000 of
them](https://arxiv.org/abs/2601.17581), though humans remove more and range wider.

Deletion is fine, then. I aimed my rant at the wrong number. What has stopped happening
is the operation where somebody notices four things are the same thing and makes them
one thing. GitClear puts moved code, their proxy for refactoring, at 21% of changed lines
in 2022 and 3.8% in 2026. And across [15,451 agentic
refactorings](https://arxiv.org/abs/2511.04824), duplication was the stated purpose 1.1%
of the time against 13.7% for humans. Agents refactor. They rename.

The number I want most is GitClear's "error-masking constructs, +47%," their name for
defensive idioms: rescues, null checks, mock guards. I want it badly enough that I should
say the rest out loud. GitClear sells code analytics and the definition sits behind a
registration wall. So I have a number I love, from a vendor, that I can't check. Make of
that what I did.

Addition isn't the vice, either. A guard is often right, and the repair tools before
LLMs had the opposite bug, deleting whatever made the test fail. None of this is new:
Hacker News has "afraid to delete code" comments going back a decade. What's new is
that it's free, instant, and carries no memory of why. A human's band-aid has a person
attached who remembers. An agent's has a commit message, and it lands in a review
queue that was the first resource AI spent.

## Ranked by whether there's any evidence

Which means the ones I like most are near the bottom. The most useful finding here is
a negative result, so it goes first: giving an agent test-first instructions and
changing nothing else measured *worse* than giving it none at all. Most of what you and
I tell agents, including my own instruction file, is that kind of advice.

**1. Give it a map of what it's about to break.** Hand the agent a plain text file
listing which tests and callers touch the code it's about to change. Regressions fell
by two thirds ([TDAD](https://arxiv.org/abs/2603.17973)). Small study, two open-weight
models, and still the best-designed thing I found, which tells you plenty. Its
conclusion is the one I'd tape above my monitor: surfacing contextual information beats
prescribing procedural workflows. Most of us are prescribing.

**2. Say out loud that "nothing needs to change" is an allowed answer.** Cheapest
thing on this list and I had never done it. Every prompt any of us writes starts
from *fix this*, which quietly forbids the correct answer to a fair share of
tickets. Telling the model abstaining is legitimate moved one from 60.5% to 88.5%. So
write the permission down: `If the code is already correct, say so and stop.`

The lever has an ugly other end, which I should report since I'm leaning on it. Where
a previous agent's fix was genuinely wrong, that same framing pushed two models into
returning empty patches most of the time. So it moves the bias rather than removing
it.

**3. Put the rules you care about in a hook.** Anthropic's docs draw the line: CLAUDE.md
instructions are advisory, hooks are deterministic. And a git hook stops *me* before the
push, which is where the real teeth are, because the agent isn't the only one here who
reaches for a quiet `except` at midnight. My pre-push hook already runs `go vet` and `go
test`. The rule I care about is four more lines:

```sh
if git diff origin/master...HEAD -U0 | grep -nE '^\+.*(except:[[:space:]]*$|_ = err)'; then
  echo "new silent swallow. name the error or fix the invariant." >&2
  exit 1
fi
```

Crude, false-positive-prone, and `--no-verify` exists for when it's wrong. It has
still caught more than the paragraph in my markdown file ever did, because the
markdown file asks and this one refuses.

**4. Harden the oracle.** If a weak test suite is what lets a suppression pass,
strengthen the suite instead of nagging the model. Mutation testing is the
mechanically correct answer and it's no longer academic: Meta runs an LLM-driven
version in production, where engineers kept 73% of the generated tests. Their mutants
targeted privacy faults, not band-aid patches, so the transfer to my problem is my
argument and not their measurement. Still, a guard that swallows an error will survive
a weak suite and die to a mutant.

**5. Read the plan. You aren't going to read the diff.** Dex Horthy's version is the
one everybody quotes and it holds: he can't read 2,000 lines of Go a day, he can read
200 lines of a plan. Neither can I, and the plan is where the invariant gets named or
doesn't. Mixed evidence though, because a bad plan measures worse than no plan at all. The model
follows it off the cliff.

**6. After two failed corrections, throw the session away.** The one piece of vendor
advice with a mechanism under it: if refinement loops are what convert real fixes
into swallowing `try`/`except`, then the loop is the hazard. I've never once
regretted doing this and I still forget.

**7. Measure your own repo.** GitClear says churn rose. [A causal study of 151 Java
repos](https://arxiv.org/abs/2606.13298) says it fell, while finding lines of code up
12.8% and smells flat. Faros says the deleted-to-added ratio is up 861%. All three
define churn differently, so stop arguing about their numbers and generate your own:

```sh
git log --first-parent HEAD --numstat --date=short --after=2025-01-01 \
  --pretty=format:'--%h--%ad--%aN' \
| awk -F'\t' '
  /^--/ { split($0, h, "--"); m = substr(h[3], 1, 7); next }
  NF==3 && $1 != "-" { a[m]+=$1; d[m]+=$2 }
  END { for (k in a) printf "%s  +%-7d -%-7d  net %+d\n", k, a[k], d[k], a[k]-d[k] }
' | sort
```

One line per month, added, deleted, net. Leave rename detection on, because I got that
wrong first: `--no-renames` counts every file move as a whole delete plus a whole add,
which pumps both columns and hides what you're looking for.

**8. Schedule a deletion pass.** No evidence, just arithmetic. A standing pass whose
only permitted output is removal, no features in the same commit. You can now pay a
consultancy ten thousand a week to send three senior engineers in to delete things, so
somebody has already turned this bullet into a pricing model.

## The rule I wrote anyway

Weakest tier, and I'll say so. Bloated instruction files get ignored, and vendors
already ship this instruction: Anthropic's own phrasing is "address the root cause,
don't suppress the error." It ships in the docs and I still got four patches. I wrote
mine anyway, six bullets, in the file I've just told you gets ignored. I hear it.

> **NO PATCHES, rewrite what produces the bug** (peer of DRY/KISS/YAGNI). Never
> fix a bug by layering a compensating mechanism over it. A fix that is visibly
> bolted on is not done.
>
> - Before writing any code, state what gets **deleted**. "Nothing deleted, net
>   lines added" means the design is wrong. Rethink it first.
> - Ask why the buggy code exists at all. Removing a component beats correcting
>   it.
> - Ask which component owns the truth being corrupted and fix it there. One
>   owner, one write. Don't repair downstream what an upstream line got wrong.
> - Stop if: a flag exists only to undo prior behaviour, a write exists only to
>   repair earlier state, or plumbing is threaded through call sites just to
>   reach the correction.
> - Report size honestly. Never frame growth as cleanup.

The first bullet is the one that earns its place. "State what gets deleted" is the only
line in there a model can't satisfy by adding something.

## The absurd part

What gets me isn't the patches.

I've got a model that can read a paper, find the flaw in my reasoning, and write better
Go than I did at 30. I asked it to fix a cache bug and it built four layers of defence
around a line it never questioned. Then I swore at it, and it said
"You're absolutely right," which is what it says whether I am or not, and then it did
the correct thing, which was to ask whether the cache should exist at all.

The capability was in there the whole time. What was missing was permission to delete
something, and what granted it was a 37-year-old man losing his composure at two in the
morning.

The patches aren't new either. I've seen that exact shape in a PHP file from 2009,
written by a contractor who is probably a director somewhere now. Retry, sleep, swallow,
return true. The difference is that took a week and cost money, and I got it in nine
seconds from something that had just explained Go's memory model better than the book
did.

Twenty years of tooling, and the highest-leverage debugging technique available to
me is still: get annoyed enough to ask why the code exists.

The essay about code bloat wanted to be five thousand words. Nothing deleted, net
lines added means the design is wrong. Applies to prose.
