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

In non-`yolo` approval modes (`always-ask`/`write`), the host's own approval gate runs first and may prompt before the classifier path executes. Classification happens after any host approval the active mode requires.

A per-session cache (`SAFE`/`UNSAFE`), keyed by session id, working directory, and command, remembers verdicts. Cache state never crosses sessions or directories (the #6263 P3 fix).

## Safety model

1. The model **never** overrides a static `deny` or critical pattern — the sync `approval()` gate runs first, independent of the model.
2. The model **never** runs a command directly — all execution is `ctx.invokeTool` → native bash. Critical patterns live there and cannot be bypassed by classifier output.
3. Fail-closed everywhere: classifier `UNSURE` with no UI, model timeout/error, malformed verdict, and unexpected plugin errors all block the command. A command the classifier could not judge is never run.
4. Session-scoped cache only, keyed by session. No process-global command state.
5. Static-gate fidelity: the plugin uses the same shell tokenizer as native bash approval (`tokenizeShellSegments`) and mirrors the native allow-rule shell-control guard (`hasBashApprovalShellControl`), so `allow` rules never ride a compound line (`git status; rm -rf x` cannot pass an `allow: git *`) and `deny`/`prompt` rules see identical segmentation to the builtin. This matters because `ctx.invokeTool` delegates to native execution without re-running native approval — the plugin's static gate must mirror the native one exactly.

## Install

```bash
git clone https://github.com/STRML/omp-bash-classifier.git
cd omp-bash-classifier && omp plugin install .
```

This symlinks the directory into `~/.omp/plugins/node_modules/omp-bash-classifier` and writes `omp-plugins.lock.json`. No build step, no npm deps. Then start a new OMP session (config/plugins load at session start).

## Uninstall

```bash
omp plugin uninstall omp-bash-classifier
```

or remove the symlink and the `omp-plugins.lock.json` entry by hand.

## Model used

The current session model (`ctx.model`) via `@oh-my-pi/pi-ai` `completeSimple`, single-turn, reasoning disabled, 20s timeout (combined with the caller's abort signal), key resolved from `ctx.modelRegistry.resolver`. Classifier calls are sent only for commands no static rule decides; the cache avoids repeat calls for the same command in the same working directory within a session.

## Configuration

No plugin config. It reads the existing `bash.patterns` (from `@oh-my-pi/pi-coding-agent` `settings`) and imports `CRITICAL_BASH_PATTERNS` from `@oh-my-pi/pi-coding-agent/tools/bash`, so your current guardrails keep working — the classifier only adds judgment for commands no static rule decides.

## Risks

- **Command privacy**: commands that static rules do not allow are sent, up to 2,000 characters, to the configured model provider for classification. Command text can contain private paths, proprietary code snippets, inline environment assignments, or secrets in flags, so those values may leave your machine. The provider's logging, retention, and privacy policies apply. The session cache only avoids repeat requests after the first classification.
- **Model misevaluation**: bounded by critical patterns + native delegation (never runs directly) + fail-closed on uncertainty and on classifier errors.
- **Latency**: one model call per non-allow bash command (cached per session). Uses reasoning-disabled single turn, cheap.
- **Shadowing regression**: if the plugin is broken, non-allow commands fail closed (blocked) rather than executing. Static allow/deny rules and critical patterns are unaffected; to disable entirely, uninstall the plugin.

## Files

- `index.ts` — the plugin (single file: registerTool bash, sync approval, async execute, onSession cache).
- `package.json` — manifest (`omp.extensions: ["./index.ts"]`, no deps).
- `LICENSE` — MIT.