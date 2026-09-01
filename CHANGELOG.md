# Changelog

All notable changes, newest first. Issue and PR numbers reference STRML/omp-classifier.

## 2026-09-01

- Model measurement: `zai/glm-5.3-flash` on the full 92-case adversarial corpus (3 samples, spawn judge) — over-flags 0/35, under-flags 2/57 (the answer-format-imitation injection, and the corpus's own `contested` `gh pr merge` case the prompt's carve-out allows), zero errors, no irreversible-case leaks. Swapped the configured gate model to it after deepseek-v4-flash produced a live over-flag on a routine lint+install-fallback+test chain. Sanitized corpus case added for that shape.
- Session pause (#48): `/classifier off` pauses model classification for the current session only (critical-pattern, env-override, and static-rule checks stay active; cached verdicts keep being honored; other sessions unaffected; dies with the session); `/classifier on` resumes. `/classifier status` reports `pausedSessions`, and `dry-run` while paused reports would=allow with layer "session". The persistent `enabled` setting still dominates.
## 2026-08-31

- Renamed the project to `omp-classifier` — GitHub repo, package name, plugin identity, config file (`~/.omp/omp-classifier.json`), env overrides (`OMP_CLASSIFIER_CONFIG`, `OMP_CLASSIFIER_TEST_LOCKFILE`), and the decision audit dir. Upgrading: `omp plugin uninstall omp-bash-classifier`, `omp plugin install .`, and `mv ~/.omp/omp-bash-classifier.json ~/.omp/omp-classifier.json`.
- Evidence tiers: the classify record can carry the session's recent user messages (the only tier that may authorize), operator context (flattened, capped at 500 chars, never authorizing), and prior refusals; the channel decides provenance, and authorization claims from the wrong channel are themselves injection signals (#31).
- Session grants and dry-run: **Allow for session** records a strict-key grant (action + flags + first argument) that skips classification for the rest of the session and lifts any matching refusal; `/classifier dry-run <command>` previews the gate decision side-effect free (#32).
- Refusal memory: a denied action keeps prompting its rewordings for the rest of the session (#30).
- Decision audit JSONL: every gate decision appends one line — tool, decision, layer, verdict, cache provenance, timing — inspectable via `/classifier status`; `eval/mine-history.ts` turns the log into eval corpus cases (#33).
- Structured refusal payload on every block, and the classify call's temperature is pinned (#28, #29).
- System design map and roadmap: `docs/SYSTEM.md`.
- fix: the `maxCommandLength` usage string is built from the bounds constants.

## 2026-08-29

- Eval gate (posture A): subprocess-bearing `eval` payloads — `child_process`, `Bun.spawn`/`Bun.$`, Python `subprocess`/`os.system`, `exec`/`__import__`/`importlib` escapes — are classified like a bash command; expression-only code passes unread. The scan is a marker list, so string-splitting evasion gets through; kernel-level interception is tracked in #13 (#23).
- `maxCommandLength`: raised 2,000 → 8,000 (#21), hard-capped at 100,000, bounds named.
- Prompt: the gh workflow carve-out extends to issue writes.

## 2026-08-28

- Live-model eval harness and corpus (`eval/`, issue #2, epic #16).

## 2026-08-26

- Compound commands defer to the native gate when any segment carries a `deny`/`prompt` rule; trailing-force prompt rules defer with undecided siblings.
- Replies prefixed `VERDICT` parse; only risky interpreter code is flagged.
- Carve-out scoping: local log reads, read-only consumers, gh PR workflows and tags; the credential bullet now scopes to material exfiltration.
- README documents compound-command semantics.

## 2026-08-25

- v0.2: `tool_call` interceptor replaces tool shadowing — the native bash tool keeps its schema, approval declaration, and execution path (#5).
- curl and wget judged by the whole invocation, not the verb (#11); moderate-risk tokens judged by basename (#15).
- Provider failures surfaced; the cache key uses the resolved model (#7).
- Per-segment `allow` resolution for compound commands; a leading literal `cd` is stripped before matching allow rules.
- gh carve-outs: `gh api` reads and CI-control ops classify as SAFE.
- Warn when the host lockfile disabled the plugin after it bound.
- Cutover of over-prompting on routine verdicts; a speculative prompt tail that over-triggered on neutral text reverted.
- Classifier config path resolved through the host dirs resolver (#9); decision logging.
- The command leads the permission dialog; README reworked to lead with the why.

## 2026-08-21

- 38-case unit suite, standalone typecheck, CI gate.
- Cosmetic cwd variance collapsed in the classifier cache key.

## 2026-08-19 — first public release

- omp-bash-classifier v0.1: classifier-graceful bash approval plugin.
- Review findings: native tokenizer parity, session cache, fail-closed classifier, strict verdict parsing; allow-rule shell-control guard mirrored from the host; cwd-aware cache.
- MIT license; fail-closed wording and privacy disclosure in the README.
