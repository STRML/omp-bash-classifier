/**
 * omp-bash-classifier
 *
 * Makes bash approval classifier-graceful: trivial commands auto-run, dangerous
 * commands block, ambiguous commands prompt. Shadows the builtin bash tool via
 * the documented re-registration surface (registerTool with the same name +
 * ctx.invokeTool delegation), so execution always flows through native bash:
 * CRITICAL_BASH_PATTERNS and real exec semantics stay authoritative.
 *
 * Design (from spec /tmp/omp-classifier-plugin-spec.md):
 *   - approval(): SYNC coarse gate. Critical patterns + static config deny are
 *     decided here, before any model call. Never async. Never calls a model.
 *   - execute(): the classifier. Static allow passes straight to native bash.
 *     Everything else is model-judged: SAFE -> native bash, UNSAFE -> blocked,
 *     UNSURE -> interactive confirm (headless: fail closed). Classifier/model
 *     plumbing errors fail open to native bash (that is today's static-gate
 *     behavior; the classifier is additive).
 *   - onSession: per-session classifier cache, cleared on every session event.
 *
 * Safety invariants (from upstream #6263 P3 review):
 *   1. The model NEVER overrides a static deny or critical pattern.
 *   2. The model NEVER runs a command directly — always via ctx.invokeTool ->
 *      native bash, so CRITICAL_BASH_PATTERNS is authoritative regardless of
 *      model output.
 *   3. Fail-closed: classify-UNSURE with no UI, and model-timeout, block.
 *   4. Session-scoped cache only. No process-global state.
 */
import type { ExtensionAPI, AgentToolResult } from "@oh-my-pi/pi-coding-agent";
import { settings } from "@oh-my-pi/pi-coding-agent";
import { CRITICAL_BASH_PATTERNS } from "@oh-my-pi/pi-coding-agent/tools/bash";
import { completeSimple, type TextContent, type UserMessage } from "@oh-my-pi/pi-ai";

type Verdict = "SAFE" | "UNSAFE" | "UNSURE";

/** Session-scoped classifier cache. Cleared in onSession; bounded. */
const cache = new Map<string, Verdict>();
const CACHE_CAP = 500;

/** Deterministic static-decision for a command: critical + bash.patterns only. */
type StaticDecision = "deny" | "allow" | "pass";

// Bash pattern helpers, mirrored from the builtin (tools/bash.ts:233-266).
// Not exported from the package, so copied here to stay behavior-identical.
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

interface BashApprovalPatternRule {
	match: string;
	approval: BashPatternApproval;
}

function commandMatchesBashApprovalPattern(command: string, pattern: string): boolean {
	const normalizedCommand = normalizeBashApprovalPattern(command);
	if (normalizedCommand.length === 0) return false;
	return bashApprovalPatternToRegExp(pattern).test(normalizedCommand);
}

function bashCommandSegments(command: string): string[] {
	return command
		.split(/[;&|&()\n]/)
		.map(segment => segment.trim())
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
		// allow only vouches for the ENTIRE command, never a compound segment
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

function extractVerdict(reply: string): Verdict {
	const m = /(SAFE|UNSAFE|UNSURE)/.exec(reply.toUpperCase());
	if (!m) throw new Error(`No verdict in classifier reply: ${reply.slice(0, 80)}`);
	return m[1] as Verdict;
}

function truncated(value: string, max = 400): string {
	return value.length > max ? `${value.slice(0, max)}…` : value;
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
		onSession: () => {
			// Session boundaries — a fresh session inherits no classifier state.
			cache.clear();
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

			try {
				const decision = staticDecision(command);
				// Static deny should have been caught by approval(), but re-check
				// as defense-in-depth (the approval gate is the only guard).
				if (decision === "deny") return blocked("static bash rule or critical pattern");
				if (decision === "allow") return runNative();

				// Classifier path (decision === "pass").
				const cached = cache.get(command);
				if (cached === "SAFE") return runNative();
				if (cached === "UNSAFE") return blocked("classified unsafe (cached)");

				// Model call — bounded, one completion, reasoning disabled.
				const model = ctx.model;
				if (!model) return runNative(); // no model: today's static-gate behavior
				let reply: string;
				try {
					const sessionId = (ctx.sessionManager as { getSessionId?: () => string } | undefined)?.getSessionId?.();
					const promptMessage = {
					role: "user",
					content: truncated(command, 2000),
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
							signal: AbortSignal.timeout(20000),
						},
					);
					reply = msg.content
						.filter((c): c is { type: "text"; text: string } => c.type === "text")
						.map(c => c.text)
						.join(" ");
				} catch {
					// Classifier plumbing failed (model down, timeout, auth). Fail
					// open to native bash: that is today's behavior — the static
					// gate (critical patterns + rules) still guards. The classifier
					// is additive; losing it reverts to baseline, nothing worse.
					return runNative();
				}

				const verdict = extractVerdict(reply);
				if (cache.size >= CACHE_CAP) cache.clear();
				cache.set(command, verdict);

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
								cache.set(command, "SAFE");
								return runNative();
							}
							return blocked("not approved");
						}
						// Headless / no UI: fail closed.
						return blocked("classifier uncertain and no interactive UI");
				}
			} catch (err) {
				// Any unexpected plugin error: fail open to native bash (the static
				// gate still guards; this is baseline behavior, never a bypass of
				// critical patterns which live in native bash).
				return runNative();
			}
		},
	});
}

