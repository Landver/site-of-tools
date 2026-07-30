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

Patch one cleared the cache when the entry looked stale. Patch two handled the
case where clearing it raced the writer. Patch three initialised the lock that
patch two assumed existed. Patch four gave up after three attempts and returned
`{"ok": True, "stale": True}`, so the caller would stop asking.

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
repositories grow, I can't support, and I'll hand it back later. The narrow one is
the title, and I'll defend it: around the line that caused this bug there is now
more code than there was, and less chance anyone ever goes back and makes the four
things one thing. A repo can shrink on net while every bug site quietly gets fatter.

Also my prompt was garbage. A stack trace and one sentence, no invariant, no
acceptance criteria. Skill issue, and there's a number on how much of one further
down. What kept me reading after I calmed down is that this isn't a story about one
bad prompt.

## The thing has a name

In May, a group at ETH Zurich published a benchmark called FixedBench that does
something I'd never thought to do. It gives coding agents 200 tasks where the
correct answer is to do nothing. The bug is already fixed. The code is fine. Go
ahead.

Five models across four agent frameworks proposed unwanted changes in 35 to 65% of
those cases. Asked plainly, the best model still touched code it should have left
alone about a third of the time. The worst, two thirds. The paper's own diagnosis
is the line I'd been looking for since Tuesday:

> our results indicate that LLMs fall prey to an action bias: they choose to act
> even if inaction would be appropriate

That's [Coding Agents Don't Know When to Act](https://arxiv.org/abs/2605.07769)
(Gloaguen, Mündler, Müller, Raychev, Vechev, 8 May 2026). Hand a model working
code and tell it to fix the bug, and half the time it will find something to do to
it, because doing something is what it's for.

IBM researchers then looked at what happens when you let an agent iterate a patch
against tests until they pass, which is the loop most of us run all day.
Overfitting got worse, not better, by three or four points on both models they
tested. Their figure 1 is my Tuesday: refinement took a real fix and replaced it
with a `try`/`except` that swallows the error and returns a placeholder. Passed the
generated test. Failed the real one. Of 22 patches that refinement rescued into
passing, 14 failed the hidden tests ([Investigating Test Overfitting on
SWE-bench](https://arxiv.org/abs/2511.16858)). Allowed to edit either the code or
the test, those agents edited the code 18 times against the test's 3, because, in
the authors' words, the model "believes that the tests are mostly perfect."

When it does diverge from the human, the direction isn't random. A
differential-testing study of patches that SWE-bench Verified marked as solved
found 29.6% behave differently from what the developer wrote, and the paper's
reading of that is careful: suspicious patches "tend to introduce additional
changes rather than omitting necessary changes" ([Are "Solved Issues" in SWE-bench
Really Solved Correctly?](https://arxiv.org/abs/2503.15223)).

Fine. I feel seen. The interesting question is why.

## Why it does it

The oracle is "tests pass," not "design improved." This is the whole thing. The
cheapest way to make a failure signal stop is to stop the signal, and nothing in
the loop can tell the difference between a fix and a well-placed `except`. The IBM
result is the proof: the more you iterate against tests, the more of your fixes
become suppressions.

It can see the crash site but not the invariant. One taxonomy of repair failures
has a category for exactly this: all the information needed for the correct fix is
in the codebase, and none of it is visible from the method body the model was
given. From inside a 40-line window, a guard is not laziness. It is the only
correct move available. Anthropic's own docs concede the constraint that produces
it, that context fills up fast and performance degrades as it fills.

Action bias, which isn't the same thing. "No change needed" isn't in the action
space the model believes it has, and that this responds so strongly to how you
phrase the request suggests a learned habit rather than a ceiling.

There's probably a fourth, that preference training rewards code which looks safe,
but I'll label it speculation and move on. Nobody has measured a defensiveness
reward on code diffs.

[Armin Ronacher](https://lucumr.pocoo.org/2026/6/23/the-coming-loop/) gets at the
shape of it better than I can, writing about present-day models being "too
defensive, too complex, too local in its reasoning," and then landing the actual
principle: they "add fallbacks instead of making bad states impossible."

That's my complaint, stated properly. Not "you added code." **You added a defence
at a distance from the invariant it was compensating for.** Patch three existed to
serve patch two. None of them knew why patch one was there.

One thing I didn't expect to find. Anthropic's own best-practices page warns that a
reviewer subagent prompted to find gaps will find them, and that chasing all of
them "leads to over-engineering: extra abstraction layers, defensive code, and
tests for cases that can't happen." The vendor documented my bug.

## Where I'm wrong

Nobody has measured the thing I actually said. There is no study that takes
bug-fix patches, separates them from features, and compares net lines added by a
model against net lines added by the human who fixed the same bug. I had three
research passes go looking. Everything above is mechanism and proxy, and one
well-designed study could take it apart.

The aggregate version of my claim doesn't survive either, and neither does the
number I thought had killed it. Faros AI's 2026 report, two years of telemetry from
22,000 developers, has the ratio of lines deleted to lines added up 861% under high
AI adoption. I read that as the end of this post for about an hour. It isn't. A
ratio moving is not a codebase shrinking: 0.05 to 0.48 is an 861% rise and still
two lines added for every one removed. And Faros won't say what it means, offering
three readings and concluding it depends on the organisation. So I don't get to use
it against myself, and nobody gets to use it against me.

Agent pull requests are also *smaller* and more localised than human ones
([Ogenrwot and Businge](https://arxiv.org/abs/2601.17581), 24,014 merged agentic PRs
against 5,081 human ones), and their effect sizes cut both ways: medium on deleted
lines and files touched, small on added lines. Humans remove more and range wider.
Agents add about the same and take less away.

Deletion is fine, then. I aimed my rant at the wrong number. What has stopped
happening is the operation where somebody notices four things are the same thing and
makes them one thing. GitClear's January 2026 report puts moved code, their proxy
for refactoring, at 21% of changed lines in 2022 and 3.8% year-to-date in 2026, with
block duplication the highest they have on record. And in [a study of 15,451
refactorings in agentic commits](https://arxiv.org/abs/2511.04824), duplication was
the stated purpose 1.1% of the time against 13.7% for humans. Agents refactor. They
rename.

The number I want most is GitClear's "error-masking constructs, +47%," glossed
publicly as defensive idioms: rescues, safe-navigation, null checks, mock guards. I
want it badly enough that I should say the rest out loud. GitClear sells code
analytics, and the exact definition sits behind a registration wall. So I have a
number I love, from a vendor, that I can't check.

Addition isn't the vice, either. The repair tools before LLMs had the opposite bug,
deleting functionality to make tests pass, and a guard is often the right call. Nor
is any of this new: the 2015 paper that started the overfitting literature already
noted that novice developers overfit too, and Hacker News has "afraid to delete
code" comments going back a decade. What's new is that the behaviour is now free,
instant, and carries no memory of why. A human's band-aid has a person attached who
remembers. An agent's has a commit message, and it arrives at a review queue that
was the first resource AI spent.

## Ranked by whether there's any evidence

Which means the ones I like most are near the bottom. The most useful thing in the
pile is a negative result, so it goes first: giving an agent test-first
instructions and changing nothing else measured *worse* than giving it no
instructions at all, 9.94% regressions against a 6.08% baseline. Most of what you
and I tell agents, including most of my own instruction file, is that kind of
advice.

**1. Give it a map of what it's about to break.** Hand the agent a plain text file
listing which tests and callers touch the code it's about to change. On SWE-bench
Verified, regressions fell from 6.08% to 1.82% and issue resolution rose from 24%
to 32%, that second figure on a different model and framework. Small study, and I
should say how small: two open-weight models on consumer hardware, 100 instances
and 25 ([TDAD](https://arxiv.org/abs/2603.17973)). It's still the best-designed
thing I found, which tells you plenty about the state of the evidence. The authors'
conclusion is the one I'd tape above my monitor: surfacing contextual information
beats prescribing procedural workflows. Most of us are prescribing.

**2. Say out loud that "nothing needs to change" is an allowed answer.** Cheapest
thing on this list and I had never done it. Telling the model that abstaining was
legitimate moved one model from 60.5% to 88.5%. Every prompt any of us writes
starts from *fix this*, which quietly forbids the correct answer to a fair share of
tickets. So write the permission down: `If the code is already correct, say so and
stop. "No change needed" is a complete answer.`

It has an ugly other end, which I should report since I'm leaning on the number.
Where a previous agent's fix was genuinely wrong, that same framing pushed two
models into handing back empty patches 70% and 94% of the time. Legitimising "no
change needed" doesn't install judgement. It moves the bias.

**3. Put the rules you care about in a hook.** Anthropic's docs draw the line
themselves: unlike CLAUDE.md instructions, which are advisory, hooks are
deterministic. Two different things get called hooks here, though. A Claude Code
hook stops the agent mid-turn. A git hook stops *me* before the push, and that one
has the real teeth, because the agent isn't the only one in this repo who reaches
for a quiet `except` at midnight. This repo's pre-push hook already runs `go vet
./...` and `go test ./...`. The rule I actually care about is four more lines in the
same file:

```sh
if git diff origin/master...HEAD -U0 | grep -nE '^\+.*(except:[[:space:]]*$|_ = err)'; then
  echo "new silent swallow. name the error or fix the invariant." >&2
  exit 1
fi
```

Crude, false-positive-prone, and `--no-verify` exists for when it's wrong. It has
still stopped more bad code than the paragraph in my markdown file ever did, because
the markdown file asks and this one refuses.

**4. Harden the oracle.** If a weak test suite is what lets a suppression pass,
strengthen the suite instead of nagging the model. Mutation testing is the
mechanically correct answer and it's no longer academic: Meta ran an LLM-driven
version in production across Facebook, Instagram and WhatsApp, with 73% of the
generated tests accepted by the privacy engineers who owned the code. Their mutants
targeted privacy faults, not band-aid patches, so the transfer to my problem is my
argument and not their measurement. A guard that swallows an error survives a weak
suite. It does not survive a mutant.

**5. Read the plan. You aren't going to read the diff.** Dex Horthy's version is
the one everybody quotes and it holds: he can't read 2,000 lines of Go a day, he
can read 200 lines of a well-written implementation plan. Neither can I, and the
plan is where the invariant either gets named or doesn't. Mixed research, though: a
study of 16,991 trajectories found plans help on average but that a bad plan is
worse than no plan. The model will follow it off the cliff and document the
descent.

**6. After two failed corrections, throw the session away.** Straight out of
Anthropic's docs, and the one piece of vendor advice with a mechanism under it: if
refinement loops convert real fixes into swallowing `try`/`except`, the loop is the
hazard and ending it early is the fix. I've never once regretted this and I still
forget.

**7. Measure your own repo.** GitClear says churn rose. A study accepted at
Euromicro SEAA 2026 ran a difference-in-differences design over 151 Java
repositories and found churn *decreasing* after agentic adoption ([Larsen and
Moghaddam](https://arxiv.org/abs/2606.13298)), though churn is a side observation
there and its real subject is architectural smells, where it found lines of code up
12.8% and smell counts flat. Faros says the deleted-to-added ratio is up 861%.
They're all using different definitions of churn, so stop arguing about their
numbers and generate your own:

```sh
git log --first-parent HEAD --numstat --date=short --after=2025-01-01 \
  --pretty=format:'--%h--%ad--%aN' \
| awk -F'\t' '
  /^--/ { split($0, h, "--"); m = substr(h[3], 1, 7); next }
  NF==3 && $1 != "-" { a[m]+=$1; d[m]+=$2 }
  END { for (k in a) printf "%s  +%-7d -%-7d  net %+d\n", k, a[k], d[k], a[k]-d[k] }
' | sort
```

One line per month, added, deleted, net. Two notes, because I got both wrong first.
Leave rename detection on: with `--no-renames` every file move counts as a whole
delete plus a whole add, which pumps both columns and hides what you're after. And
`--first-parent HEAD` keeps it to what landed on main, or you're measuring CI
robots.

**8. Schedule the deletion pass and staff it.** No evidence, just arithmetic. A
standing pass whose only permitted output is removal and consolidation, no features
in the same commit. If you don't schedule it, it doesn't happen, and I know that
because you can now pay a consultancy ten thousand dollars a week to send three
senior engineers into your codebase and delete things. Somebody turned this bullet
into a pricing model.

## The rule I wrote anyway

Weakest tier, and I'll say so. Bloated instruction files get ignored, generated
`AGENTS.md` files nudge task success down while raising cost, and vendors already
ship this exact instruction: Anthropic's suggested phrasing is "address the root
cause, don't suppress the error." It ships in the docs and I still got four patches.
I wrote mine anyway, six bullets, in the file I've just finished telling you gets
ignored. I hear it.

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

The second bullet is the one that earns its place. "State what gets deleted" isn't
a style preference, it's a forcing function, and it's the only line in there that a
model can't satisfy by adding something.

## The absurd part

Here's what actually gets me, and it isn't the patches.

I've got a model that can read a paper, find the flaw in my reasoning, and write
better Go than I did at 30. I asked it to fix a cache bug and it built four layers
of defence around a line it never once questioned. Then I swore at it, and it said
"You're absolutely right," which is what it says whether I am or not, and then it
did the correct thing, which was to ask whether the cache should exist at all.

The capability was in there the whole time. What was missing was permission to
delete something, and the thing that granted permission was a 37-year-old man
losing his composure at two in the morning.

The patches themselves aren't new either. I've seen that exact shape in a PHP file
from 2009, written by a contractor who is probably a director somewhere now. Retry,
sleep, swallow, return true. The difference is that the contractor took a week and
cost money, and I got it in nine seconds from something that had just explained
Go's memory model to me better than the book did.

Twenty years of tooling, and the highest-leverage debugging technique available to
me is still: get annoyed enough to ask why the code exists.

The essay about code bloat wanted to be five thousand words. Nothing deleted, net
lines added means the design is wrong. Applies to prose.

If you've run the study I said doesn't exist, or you ran that git command and your
repo says the opposite of mine, open an issue at
https://github.com/Landver/site-of-tools and paste the numbers in.
