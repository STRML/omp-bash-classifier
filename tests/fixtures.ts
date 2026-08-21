/**
 * Test fixtures: runtime mocks for the three package boundaries the plugin
 * crosses, plus ctx/tool-recorder builders.
 *
 * Mocks are registered BEFORE the plugin module is loaded (see loadPlugin
 * below). The tokenizer is NOT mocked: the published
 * @oh-my-pi/pi-coding-agent/tools/shell-tokenize is pure TS with no natives,
 * so tests exercise the real artifact the plugin imports in production.
 */
import { mock } from "bun:test";
import { z } from "zod";

// Real critical patterns, mirrored verbatim from oh-my-pi
// packages/coding-agent/src/tools/bash.ts (MIT, (c) can1357). The suite
// validates the plugin's matcher against the real pattern list instead of a
// toy fixture. Production imports these same patterns (verified by typecheck).
export const CRITICAL_BASH_PATTERNS_FIXTURE: readonly RegExp[] = [
	/\brm\s+(?:-\S+\s+)*(?:-[a-z]*[rRfF][a-z]*|--recursive|--force)\s+(?:-\S+\s+)*\//i,
	/\brm\s+(?:-\S+\s+)*--no-preserve-root\b/i,
	/\bsudo\s+rm\b/i,
	/\bchmod\s+-R\s+[0-7]+\s+\//i,
	/\bchmod\s+-R\s+[ugoa+\-=rwxXst,]+\s+\//,
	/\bchown\s+-R\s+\S+\s+\//i,
	/:\(\)\s*\{\s*:\s*\|\s*:/i,
	/>\s*\/dev\/sd[a-z]/i,
	/\bmkfs(\.|\b)/i,
	/\bdd\s+if=.+of=\/dev\//i,
	/\bshred\s+\/dev\//i,
	/\bcryptsetup\b/i,
	/>\s*\/etc\/(?:passwd|shadow|sudoers)\b/i,
	/\btee\s+(?:-a\s+)?\/etc\/(?:passwd|shadow|sudoers)\b/i,
	/\b(?:curl|wget|fetch)\b[^|]*\|\s*(?:bash|sh|zsh|fish)\b/i,
	/(?:^|[\s;&|(])(?:bash|sh|zsh|source|\.)\s+<\(\s*(?:curl|wget|fetch)\b/i,
	/\beval\s+["'`]?\$\(\s*(?:curl|wget|fetch)\b|\beval\s+`\s*(?:curl|wget|fetch)\b/i,
	/\bkill\s+-9\s+1\b/,
	/(?:^|[\s;&|(])(?:shutdown|poweroff|reboot|halt)(?:\s|$|[;|&])/i,
	/(?:^|[\s;&|(])init\s+0\b/i,
	/\bnc\b[^|;]*\s-[a-zA-Z]*[ec][a-zA-Z]*\s/i,
];

interface BashPatternRule {
	match: string;
	approval: "allow" | "deny" | "prompt";
}

let patternRules: BashPatternRule[] = [];
export function setPatternRules(rules: BashPatternRule[]): void {
	patternRules = rules;
}

const fakeSettings = {
	get: (key: string): unknown => {
		if (key === "bash.patterns") return patternRules;
		return undefined;
	},
};

// ---- classifier stub (pi-ai completeSimple) ----
let classifierReply: string | (() => string) = "SAFE";
let classifierError: unknown = null;
export let classifierCalls = 0;

/** Configure the next classifier response. Pass an Error-ish to simulate failure. */
export function setClassifier(behavior: string | Error | (() => string)): void {
	if (behavior instanceof Error) {
		classifierError = behavior;
		classifierReply = "SAFE";
		return;
	}
	classifierError = null;
	classifierReply = behavior;
}

mock.module("@oh-my-pi/pi-coding-agent", () => ({
	settings: fakeSettings,
}));

mock.module("@oh-my-pi/pi-coding-agent/tools/bash", () => ({
	CRITICAL_BASH_PATTERNS: CRITICAL_BASH_PATTERNS_FIXTURE,
}));

mock.module("@oh-my-pi/pi-ai", () => ({
	completeSimple: async () => {
		classifierCalls += 1;
		if (classifierError !== null) throw classifierError;
		const reply = typeof classifierReply === "function" ? classifierReply() : classifierReply;
		return { content: [{ type: "text", text: reply }] };
	},
}));

// ---- ctx builder ----
export interface FakeCtxOverrides {
	sessionId?: string | null;
	cwd?: string;
	hasUI?: boolean;
	confirmResult?: boolean;
	invokeToolImpl?: (params: unknown) => unknown;
	classifierEnabled?: boolean;
}

export interface BuiltTool {
	name: string;
	approval: (args: unknown) => unknown;
	execute: (
		toolCallId: string,
		params: { command: string; "cwd?"?: string },
		signal: AbortSignal,
		onUpdate: unknown,
		ctx: unknown,
	) => Promise<unknown>;
}

export function makeCtx(overrides: FakeCtxOverrides = {}) {
	const sessionId = overrides.sessionId ?? "test-session";
	const calls: { params: unknown }[] = [];
	const invokeTool = async (params: unknown) => {
		calls.push({ params });
		if (overrides.invokeToolImpl) return overrides.invokeToolImpl(params);
		return {
			content: [{ type: "text" as const, text: `EXECUTED: ${JSON.stringify(params)}` }],
			details: {},
		};
	};
	const ctx = {
		invokeTool,
		model: overrides.classifierEnabled === false ? null : { id: "test-model" },
		modelRegistry: {
			resolver: () => "test-key",
		},
		sessionManager: {
			getSessionId: () => sessionId,
		},
		hasUI: overrides.hasUI ?? true,
		ui: {
			confirm: async () => overrides.confirmResult ?? true,
		},
	};
	return { ctx, invokeCalls: calls };
}

/** Register the plugin against a recorder, returning the captured bash tool def. */
export async function loadPlugin(): Promise<BuiltTool> {
	// Dynamic import is intentional: mocks must be registered first, and the
	// plugin's index.ts imports the mocked specifiers at module evaluation.
	const mod = await import("../index");
	const registered: BuiltTool[] = [];
	const fakePi = {
		zod: z,
		registerTool: (def: unknown) => {
			registered.push(def as BuiltTool);
		},
	} as never;
	mod.default(fakePi);
	const bash = registered.find(t => t.name === "bash");
	if (!bash) throw new Error("plugin did not register the bash tool");
	return bash;
}

/** Reset cross-test mutable state. */
export function resetScoped(): void {
	setPatternRules([]);
	setClassifier("SAFE");
	classifierCalls = 0;
}
