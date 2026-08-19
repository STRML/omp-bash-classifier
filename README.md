# omp-bash-classifier

Classifier-graceful bash approval for OMP. Mirrors the Claude Code / Codex `auto` mode behavior: trivial commands auto-run, dangerous commands block, ambiguous commands prompt. Inspired by upstream OMP PR [#6263](https://github.com/can1357/oh-my-pi) ("approve-for-me approval mode with LLM reviewer", P3-rejected) and [#8683](https://github.com/can1357/oh-my-pi), incorporating every fix from the #6263 review.

## What it does

Shadows the builtin `bash` tool via the documented OMP extension re-registration surface (`registerTool` with the same name + `ctx.invokeTool` delegation). Execution **always** flows through native bash, so `CRITICAL_BASH_PATTERNS` (`rm -rf /`, `sudo rm`, fork bombs, `curl|sh`, disk/device writes, `kill -9 1`, `nc -e`) and the static config rules stay authoritative regardless of what the classifier says.

| Command state | approval() (sync) | execute() (model) | Result |
|---|---|---|---|
| Critical pattern hit | deny | — | blocked |
| Static config deny | deny | — | blocked |
| Static config allow | allow | — | native bash |
| No rule / prompt rule | pass | model judges | SAFE → native · UNSAFE → block · UNSURE → confirm / fail-closed |

A per-session cache (`SAFE`/`UNSAFE`) remembers verdicts; cleared on every session event so no state crosses sessions (the #6263 P3 fix).

## Safety model

1. The model **never** overrides a static `deny` or critical pattern — the sync `approval()` gate runs first, independent of the model.
2. The model **never** runs a command directly — all execution is `ctx.invokeTool` → native bash. Critical patterns live there and cannot be bypassed by classifier output.
3. Fail-closed: classifier `UNSURE` with no UI, or model timeout/error → command blocked, never silently run.
4. Session-scoped cache only. No process-global state.
5. On a plugin/model *plumbing* failure, execution falls back to native bash — which is exactly today's static-gate behavior. The classifier is additive; losing it reverts to baseline, it cannot weaken the static safety net.

## Install

```bash
cd ~/git && omp plugin install ./omp-bash-classifier
```

This symlinks the directory into `~/.omp/plugins/node_modules/omp-bash-classifier` and writes `omp-plugins.lock.json`. No build step, no npm deps. Then start a new OMP session (config/plugins load at session start).

## Uninstall

```bash
omp plugin uninstall omp-bash-classifier
```

or remove the symlink and the `omp-plugins.lock.json` entry by hand.

## Model used

The current session model (`ctx.model`) via `@oh-my-pi/pi-ai` `completeSimple`, single-turn, reasoning disabled, 20s bound, key resolved from `ctx.modelRegistry.resolver`. On any model failure it falls back to native bash (baseline behavior).

## Configuration

No plugin config. It reads the existing `bash.patterns` (from `@oh-my-pi/pi-coding-agent` `settings`) and `CRITICAL_BASH_PATTERNS` from the fork, so your current guardrails keep working — the classifier only adds judgment for commands no static rule decides.

## Risks

- **Model misevaluation**: bounded by critical patterns + native delegation (never runs directly) + fail-closed on uncertainty.
- **Latency**: one model call per non-allow bash command (cached per session). Uses reasoning-disabled single turn, cheap.
- **Shadowing regression**: if the plugin is broken, all bash is affected. Mitigated by fail-open-to-native on any plugin error — the static gate is never weakened.

## Files

- `index.ts` — the plugin (single file: registerTool bash, sync approval, async execute, onSession cache).
- `package.json` — manifest (`omp.extensions: ["./index.ts"]`, no deps).
- `tsconfig.json` — typecheck against the fork (`~/git/forks/omp`), `extends` its base.