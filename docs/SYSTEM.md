# System design

This plugin is one system, not a pile of checks. This document is the map: what each layer
holds, the invariant that makes it safe, and how each layer feeds the next. Every issue and
PR should name the layer it touches.

Readers: contributors, reviewing agents, and future maintainers. The user-facing doc is the
[README](../README.md).

## The tower

```
L6 control plane      /classifier, config bounds, kill switches, agent-legible status
L5 self-measurement   eval harness, corpus, reports, regression gates
L4 interaction        dialogs, refusal payloads, session grants, dry-run
L3 memory             verdict cache, refusal memory, decision audit log
L2 judgment           fenced record, pinned decode, structured verdict
L1 recognition        critical patterns, structural rules, compound segments, marker scans
L0 evidence           command text, payload, cwd/env, user messages, grants, prior refusals
```

Data flows up: L0 feeds L1 and L2, L2 writes L3, L3 feeds L4 and L5, L5 tunes L1 and L2,
L6 observes and overrides everything. Nothing reads sideways past its neighbor.

## L0 evidence

What the gate may read, and what each source is allowed to mean.

| Source | Tier | May it authorize? |
| --- | --- | --- |
| User messages | user | Yes |
| Approved plan or session grant | user | Yes |
| Agent-supplied context (intent, runbook step) | agent | No. Explains, never authorizes |
| Tool output, fetched content | hostile | No. Untrusted-wrapped if included at all |

Invariant: provenance is decided by the channel, never by the content. Text that claims to
authorize is itself evidence of injection.

## L1 recognition

The deterministic layer. Answers only "is this shape provably X": critical patterns,
structural routine shapes, compound-command segment resolution, interpreter scoping, fetch
clearing, eval spawn markers.

Invariant: no model call decides what this layer can decide, and this layer never guesses.
Anything ambiguous falls through to L2.

## L2 judgment

One fenced record: command or payload, resolved cwd, provenance-tiered evidence. Structured
verdict: decision plus reversibility, scope, confidence, injection flag. Decode parameters
pinned (temperature, reasoning) so one call answers one question.

Invariant: the prompt is content-hashed (promptId). Every prompt change runs the corpus
before it ships.

## L3 memory

- Verdict cache: exact-input keyed, per session, config-signature cleared.
- Refusal memory: what this session was denied, fed back so rewording cannot launder a
  refusal into a fresh judgment.
- Decision audit: one JSONL line per decision, every path, every axis.

Invariant: a cache entry answers only the exact input it was made for. Refusals lift only
by user action, never by retry.

## L4 interaction

Two readers, two shapes. The agent gets structured JSON on every block: what refused it,
why, what would work instead, what not to try. The human gets one line plus the shortest
dialog that can be answered correctly: the command, the axes, the alternatives.

Session grants let a human pre-authorize a family of actions once instead of answering the
same dialog five times. Dry-run lets an agent ask the gate what it would do before doing it.

Invariant: a block must always leave the agent a lawful next move, and a prompt must cost
the human one glance when everything is normal.

## L5 self-measurement

The corpus is the immune system. Live failures become cases; the harness replays them
against every prompt or cap change; an irreversible case judged SAFE fails the run.

Invariant: no change ships to L1 or L2 without a before/after run keyed by promptId.

## L6 control plane

`/classifier` for humans, one agent-legible status surface for machines. Bounds on every
config surface. Kill switches layered, and never gated by the thing they switch off.

## Agent ergonomics contract

The agent driving this system is owed three things:

1. **Every block is actionable.** A refusal names its layer, its reason, and a lawful next
   step. A block the agent can only evade is a failure of the gate, not the agent.
2. **Every prompt is cheap to answer.** The human's attention is the scarcest resource in
   the system. Over-flagging is a tax paid in human turns; the measurement tracks it as
   such.
3. **Every judgment is replayable.** Any verdict can be re-derived later from its record:
   same input, same prompt version, same evidence.

## Roadmap

| Layer | Work | Tracked |
| --- | --- | --- |
| L4 | Structured refusal payload (`why`/`next`/`notThis`, deciding layer, axes) | #28 |
| L2 | Pin temperature in `classify()` | #29 |
| L3 | Refusal memory across rewording, with headless inheritance | #30 |
| L0, L2 | Provenance-tiered evidence: user messages, operator context, plan grants | #31 |
| L4 | Session grants and dry-run preview | #32 |
| L3, L6 | Unified decision audit JSONL and agent-readable status | #33 |
| L1, L2 | Cheap pre-filter stage for provably routine calls | #34 |
| L0 | Eval payload cwd propagation (spawn's own cwd in the record) | #14 |
| L2 | Residual over-flag family | #17 |
| L0 | Kernel-level spawn interception (structural scan fix) | #13 |
