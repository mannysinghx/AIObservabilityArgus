# 16 — The Six New Ideas, Explained Simply

This is a plain-English companion to
[docs/15 — Platform Evolution Proposals](15-platform-evolution-proposals.md),
written for anyone reading it without a technical background. No jargon, no
acronyms, no code. If you want the engineering detail behind any of these,
doc 15 has it — this page just explains **what each idea is, why it would
help, and what it would look like in real life.**

None of these six ideas have been built yet. This document is a proposal —
something to react to and decide on, not something that already exists.

---

## First, a 30-second refresher on what Argus does today

Argus watches AI applications (chatbots, AI agents, anything built on top of
a language model) for two kinds of trouble:

1. **Is someone attacking it right now?** — like a security camera that
   watches everything the AI reads and does, and raises an alarm if it looks
   like someone tricked it into doing something bad (leaking private data,
   for example).
2. **Was it built safely in the first place?** — like a home inspector who
   checks the wiring and locks *before* anything goes wrong, rather than
   waiting for a break-in.

The six ideas below all make one of those two jobs smarter, faster, or less
dependent on a person remembering to do something manually.

---

## Idea 1: Let Argus attack the app itself, on purpose, to find holes before real attackers do

**The problem, in plain terms.** Argus already has a "home inspector" report
that lists an app's weak points — for example, "this part of the app trusts
information from outside without double-checking it." But right now, nobody
actually *tests* whether that weak point can really be used to cause harm.
The report just sits there.

**The idea.** Use that same inspector's report to automatically generate
realistic fake attacks aimed at exactly the weak points it found, and try
them against the app in a safe test environment — the way a bank might hire
someone to try to break into its own vault using the building's actual
blueprints, instead of just testing "can you pick a random lock somewhere."

**A simple analogy.** Imagine a home inspector doesn't just hand you a list
saying "your back door lock looks weak" — they also try the door themselves,
right then, so you find out for certain whether it actually opens, instead of
guessing.

**Why it matters.** Generic security tests try the same handful of tricks
against every app, whether or not those tricks apply. Because this idea
starts from *this specific app's* actual blueprint, the fake attacks it
generates are aimed at real weak spots — which means fewer wasted tests and
a much better answer to "did fixing that problem actually work?"

**Guardrails built in.** This would only ever run against an app the customer
specifically marks as a safe testing target — never against a live app
without asking first.

---

## Idea 2: Let different companies quietly warn each other about attacks they've each seen

**The problem, in plain terms.** Right now, if Company A gets attacked with a
poisoned document or a tricky prompt, and later Company B gets hit with the
exact same trick, Company B has no way of knowing anyone else has seen it
before. Every company starts from zero.

**The idea.** Let companies *optionally* share a "fingerprint" of confirmed
attacks with each other — not the actual document or prompt (which could
contain private information), just a scrambled code that proves "this exact
thing was seen before and confirmed to be an attack." If your app runs into
something that matches a fingerprint another company already flagged, you get
warned immediately instead of having to figure it out yourself.

**A simple analogy.** Think of neighborhood watch: neighbors don't share each
other's house keys or floor plans, but if one house spots a suspicious car,
they can tell the street "watch out for this car" without revealing anything
private about their own home.

**Why it matters.** Attacks that work once often get reused elsewhere — the
same poisoned webpage, the same trick prompt copied around the internet.
Right now, every company fighting that has to discover it independently. This
lets the whole group of Argus users get smarter together, the more of them
there are.

**Guardrails built in.** This is entirely **opt-in** — nothing is shared
unless a company explicitly turns it on. What's shared is a scrambled code
that can't be reversed back into the original content, and never includes
which company reported it. This is the one idea in this document that needs
a real decision (and likely a written policy) before any of it gets built.

---

## Idea 3: Let the security system say "wait for a person's approval" instead of just "allow" or "block"

**The problem, in plain terms.** Argus has a feature today that can step in
and block an obviously bad message before it reaches the AI model — like a
bouncer checking IDs at the door. But that bouncer only ever looks at *one
person at a time*, with no memory of what happened five minutes ago in the
same conversation. It can't say "this conversation has been acting
suspicious for a while now — let's pause before it does anything risky."

**The idea.** Give the system a short memory of how suspicious a conversation
has been *overall*, and let it pause — not block, just pause — a risky action
(like "send an email" or "delete a record") for a human to quickly approve,
if that conversation's overall behavior has been building up red flags.

**A simple analogy.** A single suspicious transaction on your credit card
might not trigger anything. But if your card is used for five odd purchases
in ten minutes, your bank might hold the sixth one and text you to confirm it
was really you — not decline it outright, just check first.

**Why it matters.** The riskiest actions an AI agent can take are usually the
ones with real-world consequences — sending money, sending an email, deleting
something. This gives a way to add a "let a human double-check this one" step
specifically for those moments, based on the whole conversation's behavior,
not just the last message.

**Guardrails built in.** This would be optional and would need to fail safely
— if the approval system itself is ever slow or unavailable, the app keeps
working normally rather than getting stuck waiting forever.

---

## Idea 4: Automatically plant "tripwires" everywhere instead of relying on someone to remember to do it

**The problem, in plain terms.** Argus already has one of the most reliable
tricks in security: planting a unique, secret marker somewhere it should
never leave from (like a hidden tag), so that if it ever shows up somewhere
it shouldn't — in an AI's response, for example — that's essentially proof
something went wrong. There's no need to "guess" whether it's an attack. The
catch: right now, a person has to remember to plant each one by hand, one at
a time.

**The idea.** Two parts. First, automatically plant these tripwires across an
app's documents and knowledge sources as they come in, instead of waiting for
someone to do it manually. Second, show a simple coverage report — like "62%
of your documents currently have a tripwire in them" — so it's obvious where
the gaps are.

**A simple analogy.** It's the difference between a single motion-sensor
light you remember to install by the back door, versus a home security
system that automatically adds a sensor to every new window as it's put in,
plus a dashboard showing you exactly which windows still don't have one.

**Why it matters.** This is the platform's single most trustworthy alarm —
when it goes off, it's essentially never a false alarm. Making it automatic
instead of manual means it actually gets used everywhere it should be, not
just in the few places someone remembered to set it up.

**Guardrails built in.** Because this involves writing something into a
customer's own documents (not just Argus's own records), the automatic
version would require clear, explicit permission first, and would offer a
"preview what this would do" mode before ever doing it for real.

---

## Idea 5: Turn a security score into "here's exactly what's actually at risk"

**The problem, in plain terms.** Right now, when Argus finds a weakness, it
gives it a score, like "risk: 78 out of 100, high." That's useful to a
security expert, but if you show that number to a manager, an executive, or
an auditor, it doesn't really tell them anything concrete. "78 out of 100" —
so what happens if it's actually exploited?

**The idea.** Instead of stopping at a number, trace *what that weakness
actually connects to* — using the same map of the application Argus already
builds — and show it in plain terms: "if someone got in through this specific
weak spot, here's what they could reach: the customer information database
(2 steps away), and the tool that sends emails (3 steps away)."

**A simple analogy.** It's the difference between a smoke detector that just
says "risk level: high" versus a fire evacuation map that shows you exactly
which rooms would fill with smoke first if a fire started in the kitchen.
Both are useful, but only one tells you what to actually worry about.

**Why it matters.** This turns a security finding into something a
non-technical decision-maker can immediately understand and act on, and it's
exactly the kind of concrete detail that shows up well in a report for
auditors, insurers, or company leadership.

**Guardrails built in.** This idea deliberately does **not** try to put a
dollar figure on the risk (like "$4 million at risk") unless a customer
provides their own numbers for that — inventing a dollar amount out of thin
air would be misleading, and this platform is built around never presenting
made-up precision as fact.

---

## Idea 6: Let people ask questions about their security data in plain English

**The problem, in plain terms.** Argus stores a huge amount of detailed
information — every conversation, every finding, every alert. But today, the
only way to explore it is through a fixed set of dashboard screens. If you
want to ask an unusual question — like "show me every conversation where a
risky action happened right after one of our tripwires almost went off" —
there's currently no way to just ask that.

**The idea.** Add a search box where someone can type a plain-English
question, and have the system figure out how to answer it from the existing
data — similar to asking a smart librarian a question instead of having to
know exactly which shelf and card-catalog code to look under yourself.

**A simple analogy.** It's the difference between only being able to use a
library's five pre-made "recommended books" lists, versus being able to ask
a librarian "do you have anything about castles from the 1400s in France" and
having them go find it for you.

**Why it matters.** The security team's most important questions are often
the ones nobody thought to build a dashboard screen for in advance. This
makes the platform's data actually explorable, not just viewable.

**Guardrails built in.** This is the idea with the most careful design
requirement: the system would **never** be allowed to freely rewrite and run
arbitrary database commands based on what someone typed, because that would
be a real security risk in its own right for a *security* product. Instead,
plain-English questions would only ever be translated into a small, fixed set
of safe, pre-approved question types — similar to how a librarian can only
pull books that are actually in the library's catalog, not go improvise
something unrelated.

---

## Quick summary table

| # | In one line | Think of it as... |
|---|---|---|
| 1 | Test the app with realistic fake attacks aimed at its real weak points | A safety inspector who also tries the door, not just points at it |
| 2 | Let companies quietly warn each other about confirmed attacks | Neighborhood watch, without sharing anyone's house keys |
| 3 | Pause a risky action for human approval if a conversation looks suspicious overall | A bank holding one odd transaction after several others in a row |
| 4 | Automatically plant tripwires everywhere, and show what's still uncovered | A security system that wires every new window automatically |
| 5 | Show what's actually reachable from a weak spot, not just a risk number | A fire evacuation map instead of a "risk: high" label |
| 6 | Ask security questions in plain English instead of using fixed dashboards | Asking a librarian instead of hunting the shelves yourself |

## What happens next

These are proposals, not decisions. A few of them (especially Idea 2 and part
of Idea 4) need an explicit yes/no decision about sharing or writing data
before any of them could move forward — see the "Decisions needed" section at
the end of [docs/15](15-platform-evolution-proposals.md) for exactly what
those decisions are.
