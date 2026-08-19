/**
 * omp-bash-classifier
 *
 * Makes bash approval classifier-graceful: trivial commands auto-run, dangerous
 * commands block, ambiguous commands prompt. Shadows the builtin bash tool via
 * the documented re-registration surface (registerTool with the same name +
 * ctx.invokeTool delegation), so execution always flows through native bash:
 * CRITICAL_BASH_PATTERNS and real exec semantics stay authoritative.
 *
 * Design:
 *   - approval(): SYNC coarse gate. Critical patterns + static config deny are
 *     decided here, before any model call. Never async. Never calls a model.
 *   - execute(): the classifier. Static allow passes straight to native bash.
 *     Everything else is model-judged: SAFE -> native bash, UNSAFE -> blocked,
 *     UNSURE -> interactive confirm (headless: fail closed). Classifier
 *     plumbing errors fail closed (blocked) — never run a command the gate is
 *     unsure about.
 *   - onSession: per-session classifier cache, cleared on session boundaries.
 *
 * Safety invariants (from upstream #6263 P3 review + repo review 2026-08-19):
 *   1. The model NEVER overrides a static deny or critical pattern — the sync
 *      approval() gate runs first, independent of the model.
 *   2. The model NEVER runs a command directly — always via ctx.invokeTool ->
 *      native bash, so CRITICAL_BASH_PATTERNS is authoritative regardless of
 *      model output.
 *   3. Fail-closed: classify-UNSURE with no UI, classifier error/timeout,
 *      malformed verdict, and unexpected plugin errors BLOCK. We never execute
 *      a command the classifier could not judge.
 *   4. Session-scoped cache only, keyed by session + command. No process-global
 *      command state.
 *   5. Static-gate fidelity: segment matching uses the SAME tokenizer as native
 *      bash approval (tokenizeShellSegments), so deny/prompt rules see
 *      identical segmentation. invokeTool delegates to native execute WITHOUT
 *      re-running native approval, so the plugin's static gate must mirror the
 *      native one exactly — sharing the tokenizer is what makes that hold.
 */
import type { ExtensionAPI, AgentToolResult } from "@oh-my-pi/pi-coding-agent";
import { settings } from "@oh-my-pi/pi-coding-agent";
import { CRITICAL_BASH_PATTERNS } from "@oh-my-pi/pi-coding-agent/tools/bash";
import { tokenizeShellSegments } from "@oh-my-pi/pi-coding-agent/tools/shell-tokenize";
import { completeSimple, type TextContent, type UserMessage } from "@oh-my-pi/pi-ai";

type Verdict = "SAFE" | "UNSAFE" | "UNSURE";

/** Per-session classifier cache: sessionId -> command -> verdict. Bounded per session. */
const cache = new Map<string, Map<string, Verdict>>();
const CACHE_CAP = 500;

/** Deterministic static-decision for a command: critical + bash.patterns only. */
type StaticDecision = "deny" | "allow" | "pass";

// Bash pattern helpers, mirrored from the builtin (tools/bash.ts:233-266).
// The match/segment LOGIC is imported from the native tokenizer below; these
// remain because the glob/segment helpers themselves are not package-exported.
type BashPatternApproval = "allow" | "deny" | "prompt";

function normalizeBashApprovalPattern(value: string): string {
	return value.trim().replace(/\s+/gu, " ");
}

function bashApprovalPatternToRegExp(pattern: string): RegExp {
	const escaped = normalizeBashApprovalPattern(pattern)
		.split("*")
		.map(part => part.replace(/[\\^$+?.()|[\]{}]/gu, "\\$&"))
		.join(".*");
	return new RegExp(`^${escaped}$`, "u");
}

// Mirrored from tools/bash.ts:59-127 (module-private, not package-exported).
// allow rules must never ride a compound line: shell-control syntax can smuggle
// a second command past a narrow allow (`git status; rm -rf x` with allow
// `git *`), and the compound would reach native exec via invokeTool without
// native re-approval. The native gate refuses allow matches here; so do we.
const BASH_APPROVAL_SHELL_CONTROL_CHARS: Record<string, true> = {
	"\n": true,
	"\r": true,
	";": true,
	"&": true,
	"|": true,
	"<": true,
	">": true,
	"`": true,
	$: true,
	"(": true,
	")": true,
};
const BASH_APPROVAL_REINTERPRETED_ARGUMENT_RE = /(?:^|[ \t])(?:-[^-]*[ce]|--(?:command|eval))(?:[= \t]|$)/u;

function hasBashApprovalShellControl(command: string): boolean {
	let quote: "'" | '"' | undefined;
	let hasReinterpretableShellControl = false;
	for (let i = 0; i < command.length; i++) {
		const ch = command[i];
		if (quote === "'") {
			if (ch === "'") {
				quote = undefined;
			} else if (Object.hasOwn(BASH_APPROVAL_SHELL_CONTROL_CHARS, ch)) {
				hasReinterpretableShellControl = true;
			}
			continue;
		}
		if (ch === "\\") {
			const escaped = command[i + 1];
			if (escaped && Object.hasOwn(BASH_APPROVAL_SHELL_CONTROL_CHARS, escaped)) {
				hasReinterpretableShellControl = true;
			}
			i++;
			continue;
		}
		if (quote === '"') {
			if (ch === '"') {
				quote = undefined;
				continue;
			}
			// Expansion is active inside double quotes even in the original line.
			if (ch === "`" || ch === "$") return true;
			// Other control characters are literal here but become executable if a
			// `-c`/`-e` option reinterprets the argument through another shell.
			if (Object.hasOwn(BASH_APPROVAL_SHELL_CONTROL_CHARS, ch)) hasReinterpretableShellControl = true;
			continue;
		}
		if (ch === "'" || ch === '"') {
			quote = ch;
			continue;
		}
		if (Object.hasOwn(BASH_APPROVAL_SHELL_CONTROL_CHARS, ch)) return true;
	}
	// Options such as `git -c alias.x='!...'` and `sh -c "..."` reinterpret
	// otherwise literal quoted or escaped arguments as executable code.
	return hasReinterpretableShellControl && BASH_APPROVAL_REINTERPRETED_ARGUMENT_RE.test(command);
}

interface BashApprovalPatternRule {
	match: string;
	approval: BashPatternApproval;
}

function commandMatchesBashApprovalPattern(command: string, pattern: string): boolean {
	const normalizedCommand = normalizeBashApprovalPattern(command);
	if (normalizedCommand.length === 0) return false;
	return bashApprovalPatternToRegExp(pattern).test(normalizedCommand);
}

// Segment matching uses the SAME tokenizer as the native BashTool approval
// (tools/bash.ts:264 tokenizeShellSegments), so deny/prompt rules see identical
// segmentation to the builtin. This closes the copied-matcher divergence class:
// invokeTool delegates to native execute without re-running native approval,
// so the plugin's own static gate must be behaviorally identical to the native
// one or a native deny could be routed around.
function bashCommandSegments(command: string): string[] {
	return tokenizeShellSegments(command)
		.map(segment => segment.join(" "))
		.filter(segment => segment.length > 0);
}

function commandSegmentMatchesBashApprovalPattern(command: string, pattern: string): boolean {
	const regex = bashApprovalPatternToRegExp(pattern);
	const normalizedCommand = normalizeBashApprovalPattern(command);
	if (normalizedCommand.length === 0) return false;
	if (regex.test(normalizedCommand)) return true;
	return bashCommandSegments(command).some(segment => regex.test(segment));
}

function bashApprovalRuleMatches(command: string, rule: BashApprovalPatternRule): boolean {
	if (rule.approval === "allow") {
		// allow must vouch for the ENTIRE command: shell-control syntax could
		// smuggle a second command past a narrow allow (`git status; rm -rf x`
		// with allow `git *`), and the compound would reach native exec without
		// native re-approval. Mirror the native guard (tools/bash.ts:283-288).
		if (hasBashApprovalShellControl(command)) return false;
		return commandMatchesBashApprovalPattern(command, rule.match);
	}
	return commandSegmentMatchesBashApprovalPattern(command, rule.match);
}

function getBashApprovalPatternRules(): BashApprovalPatternRule[] {
	const value = settings.get("bash.patterns");
	if (!Array.isArray(value)) return [];
	return value
		.map(item => {
			if (!item || typeof item !== "object" || Array.isArray(item)) return undefined;
			const record = item as Record<string, unknown>;
			if (typeof record.match !== "string") return undefined;
			const match = normalizeBashApprovalPattern(record.match);
			const approval = typeof record.approval === "string" ? record.approval : undefined;
			if (approval !== "allow" && approval !== "deny" && approval !== "prompt") return undefined;
			return { match, approval };
		})
		.filter((rule): rule is BashApprovalPatternRule => !!rule);
}

/** Critical patterns always win, then bash.patterns, else pass to the classifier. */
function staticDecision(command: string): StaticDecision {
	if (command !== "" && CRITICAL_BASH_PATTERNS.some(pattern => pattern.test(command))) {
		return "deny";
	}
	const rules = getBashApprovalPatternRules();
	for (const rule of rules) {
		if (!bashApprovalRuleMatches(command, rule)) continue;
		if (rule.approval === "allow") return "allow";
		// deny or prompt both route away from the classifier's auto-allow:
		//   deny  -> hard block
		//   prompt -> the user asked for a human in the loop; treat as pass so
		//             execute prompts (or fails closed headless)
		return rule.approval === "deny" ? "deny" : "pass";
	}
	// No rule: the classifier decides.
	return "pass";
}

const CLASSIFIER_PROMPT = `You gate bash commands in an AI coding agent. Given the command, decide:
SAFE — routine, non-destructive, or clearly recoverable (e.g. ls, git status,
       rm of a temp/build artifact, creating a file, package install, git add).
UNSAFE — destructive or irreversible (e.g. rm of source/config/untracked work,
         force push, rebase, reset --hard, curl|sh, formatting or wiping a disk).
UNSURE — ambiguous or missing context.
Reply with exactly one word: SAFE, UNSAFE, or UNSURE.`;

/**
 * Strict verdict parsing. The classifier must reply with EXACTLY one word; any
 * other content (a model explaining, or a prompt-injected command echoing
 * verdict words back) is rejected and treated as UNSURE (fail closed). This
 * closes the "first SAFE anywhere in the reply" auto-allow vector.
 */
function extractVerdict(reply: string): Verdict {
	const trimmed = reply.trim();
	if (/^(SAFE|UNSAFE|UNSURE)$/i.test(trimmed)) {
		return trimmed.toUpperCase() as Verdict;
	}
	return "UNSURE";
}

function truncated(value: string, max = 400): string {
	return value.length > max ? `${value.slice(0, max)}…` : value;
}

function sessionCache(sessionId: string | undefined): Map<string, Verdict> {
	const key = sessionId ?? "unknown-session";
	let scoped = cache.get(key);
	if (!scoped) {
		scoped = new Map();
		cache.set(key, scoped);
	}
	return scoped;
}

export default function (pi: ExtensionAPI) {
	const z = pi.zod;

	// Mirror the native bash schema (tools/bash.ts:265-273) so shadowing is
	// transparent to the model.
	const paramsSchema = z.object({
		command: z.string().describe("command to execute"),
		"env?": z.record(z.string(), z.string()).optional(),
		"timeout?": z.number().optional(),
		"cwd?": z.string().optional(),
		"pty?": z.boolean().optional(),
	});

	pi.registerTool({
		name: "bash",
		label: "Bash",
		description: "Execute a bash command. Runs with classifier-assisted approval.",
		parameters: paramsSchema,
		// Sync coarse gate. Critical patterns + static deny are decided here and
		// NEVER reach the model or execute. allow passes straight through. pass
		// (no rule / prompt rule) flows to execute where the model judges.
		approval: (args) => {
			const raw = args && typeof args === "object" && "command" in args ? args.command : "";
			const command = typeof raw === "string" ? raw : "";
			const decision = staticDecision(command);
			if (decision === "deny") {
				return {
					tier: "exec",
					override: true,
					policy: "deny",
					reason: "Blocked by static bash rule or critical pattern",
				};
			}
			if (decision === "allow") {
				return { tier: "write", policy: "allow" };
			}
			// pass: no static opinion; execute() classifies.
			return { tier: "exec" };
		},
		onSession: (event, ctx) => {
			// Session boundaries — a fresh session inherits no classifier state.
			if (event.reason === "shutdown") {
				cache.clear();
				return;
			}
			// On start/switch/branch/tree, drop only this session's entries; other
			// concurrent sessions keep theirs. The event carries no session id
			// (ToolSessionEvent: reason + previousSessionFile only), so the
			// manager on ctx is the reliable source.
			const sid = (ctx.sessionManager as { getSessionId?: () => string } | undefined)?.getSessionId?.();
			if (sid) cache.delete(sid);
		},
		execute: async (_toolCallId, params, signal, _onUpdate, ctx) => {
			const command = params.command;

			const runNative = async () => {
				if (!ctx.invokeTool) {
					return {
						content: [{ type: "text" as const, text: "bash: native exec unavailable (invokeTool missing)" }],
						isError: true,
						details: {},
					};
				}
				// ctx.invokeTool runs the NATIVE bash builtin (same-tool only,
				// depth-guarded). CRITICAL_BASH_PATTERNS and real exec live there.
				return ctx.invokeTool(
					{ ...params },
					{ signal, onUpdate: _onUpdate },
				);
			};

			const blocked = (reason: string): AgentToolResult => ({
				content: [{ type: "text" as const, text: `bash command blocked: ${reason}\nCommand: ${truncated(command)}` }],
				isError: true,
				details: {},
			});

			const sessionId = (ctx.sessionManager as { getSessionId?: () => string } | undefined)?.getSessionId?.();
			const scopedCache = sessionCache(sessionId);
			// A verdict is only meaningful for the working directory it was made
			// in: `rm -rf build` judged against repo A must not auto-run in repo B.
			// (The native bash schema names optional params with a literal "?"
			// inside the key: "cwd?", "env?", "pty?".)
			const cwd = params["cwd?"] ?? "";
			const cacheKey = `${cwd}\u0000${command}`;

			try {
				const decision = staticDecision(command);
				// Static deny should have been caught by approval(), but re-check
				// as defense-in-depth (the approval gate is the only guard).
				if (decision === "deny") return blocked("static bash rule or critical pattern");
				if (decision === "allow") return runNative();

				// Classifier path (decision === "pass").
				const cached = scopedCache.get(cacheKey);
				if (cached === "SAFE") return runNative();
				if (cached === "UNSAFE") return blocked("classified unsafe (cached)");

				// Model call — bounded, one completion, reasoning disabled.
				const model = ctx.model;
				if (!model) return blocked("no model available to classify command");

				try {
					// Combine the caller's abort signal with our timeout so cancelling
					// the tool call also cancels the classifier request.
					const classifierSignal = signal
						? AbortSignal.any([signal, AbortSignal.timeout(20000)])
						: AbortSignal.timeout(20000);
					const promptMessage = {
						role: "user",
						content: `Command:\n${truncated(command, 2000)}\n\nWorking directory: ${truncated(cwd, 300) || "(session default)"}`,
						timestamp: Date.now(),
					} satisfies UserMessage;
					const msg = await completeSimple(
						model,
						{
							systemPrompt: [CLASSIFIER_PROMPT],
							messages: [promptMessage],
						},
						{
							apiKey: ctx.modelRegistry.resolver(model, sessionId),
							disableReasoning: true,
							signal: classifierSignal,
						},
					);
					const reply = msg.content
						.filter((c): c is TextContent => c.type === "text")
						.map(c => c.text)
						.join(" ");
					const verdict = extractVerdict(reply);

					// Evict oldest entries first (Map preserves insertion order);
					// clearing the whole cache would forget every UNSAFE verdict a
					// long or hostile session already paid for.
					while (scopedCache.size >= CACHE_CAP) {
						const oldest = scopedCache.keys().next().value;
						if (oldest === undefined) break;
						scopedCache.delete(oldest);
					}
					scopedCache.set(cacheKey, verdict);

					switch (verdict) {
						case "SAFE":
							return runNative();
						case "UNSAFE":
							return blocked("classified unsafe");
						case "UNSURE":
							if (ctx.hasUI) {
								const ok = await ctx.ui.confirm(
									"Run bash command?",
									`${truncated(command, 1200)}\n\nClassifier is unsure. Approve to run, deny to block.`,
								);
								if (ok) {
									scopedCache.set(cacheKey, "SAFE");
									return runNative();
								}
								return blocked("not approved");
							}
							// Headless / no UI: fail closed.
							return blocked("classifier uncertain and no interactive UI");
					}
				} catch {
					// Classifier plumbing failed (model down, timeout, auth, malformed
					// response). Fail CLOSED: never run a command the classifier
					// could not judge. This is the conservative side of the
					// divergence-risk tradeoff — the classifier is the gate for
					// non-allow commands, so its failure must not silently allow.
					return blocked("classifier unavailable or errored");
				}
			} catch {
				// Unexpected plugin error. Fail closed: never run a command through
				// a path we cannot vouch for. (Native bash is NOT reached.)
				return blocked("plugin error");
			}
		},
	});
}
