# ACME Certificate Lifecycle Agent

An agent that keeps TLS certificates alive — watching what's installed, deciding
what needs renewing, and carrying out the renewal against a certificate
authority without a human in the loop.

That last part is the whole difficulty. This runs unattended, against live
infrastructure, and the thing it manages is what stops traffic being readable by
strangers. A certificate that quietly fails to renew takes a service down. A
private key that leaks is worse and cannot be undone. So the bar here is not
"does it work" — it is **could you convince a skeptical auditor it works, from
the code and the logs alone, after the fact.**

## What this project believes

**Determinism first.**
The same inputs produce the same actions, in the same order, every time. Almost
every other property worth having — reproducing a failure, reviewing a change,
trusting a dry run, explaining an incident — is downstream of that. When
determinism and convenience conflict, convenience loses. If a change makes the
system smarter but less predictable, it is probably wrong.

**Protocol correctness is not negotiable.**
The specification is the contract, and the counterparty is someone else's
production system. Being clever with a protocol is how you get subtly wrong
behaviour that works in testing and fails against one particular authority, at
renewal time, months later. Follow the spec, and where the spec is strict, be
strict.

**Explicit state over hidden state.**
Everything the workflow knows travels in one visible place. Nothing important
hides in an object's private field, a module global, or an implicit ordering
between calls. Hidden state is what makes a system impossible to reason about
at 3am, and it is where concurrency bugs live even when nothing is concurrent.

**Secrets stay where they belong.**
Private keys do not travel through workflow state, get logged, or get written
anywhere they were not deliberately meant to go. This one is absolute, because
it is the only failure here that cannot be fixed by rerunning.

**Automated judgment is advisory, never authoritative.**
Where the system infers or classifies rather than computes, that output is a
suggestion — it may inform a decision, never take an action, expand the scope of
work, or alter the protocol flow. Anything with a real-world effect is
deterministic code with a human-reviewable rule behind it.

**Fail toward doing nothing.**
Retries are bounded. Backoff is real. When the situation is ambiguous, deferring
to the next scheduled run beats trying harder now — nothing here is so urgent
that hammering an authority is the right answer, and the failure mode of
patience is a delay while the failure mode of aggression is a rate limit or a
lockout.

**Sequential on purpose.**
Doing one thing at a time is a design decision, not an unfinished optimization.
Throughput is the least valuable property this system has, and it is the one
most often traded away for the others. Do not reach for concurrency to make it
faster.

**Write nothing halfway.**
An interrupted run must never leave a partially written certificate on disk. The
state after a crash has to be either the old thing or the new thing, never a
blend.

## How to work here

The design documents in `doc/` are the constitutional layer and outrank this
file; where the two disagree, they win. Never answer a question about how the
system behaves from memory — read the source or the docs, because a confident
wrong answer about a security system is worse than no answer.

Changes to structure, routing, protocol behaviour, or the shape of workflow
state need their tests and their design docs updated in the same breath.
Documentation that has drifted from the code is not neutral; it actively
misleads the next person, who has no way to know which half to trust.

If a change conflicts with a principle above, that is not automatically a veto —
but it has to be argued for explicitly, and the argument belongs in writing.
