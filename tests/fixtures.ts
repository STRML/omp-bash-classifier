/**
 * Test fixtures for the tool_call interceptor plugin surface.
 *
 * The plugin takes its settings from the pi argument (`pi.pi.settings`) and
 * completes classifications through `completeSimple` — both are injectable
 * here without touching the real modules, so the ONLY stub is the pi-ai model
 * boundary; every static-gate helper (criticals, tokenizer, cwd resolution,
 * leading-cd extraction) runs the real published implementation.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { mock } from "bun:test";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";

export type Verdict = "SAFE" | "UNSAFE" | "UNSURE";

export interface CapturedModelCall {
	model: unknown;
	request: {
		systemPrompt: string[];
		messages: { content: string }[];
	};
	options: { apiKey: unknown; disableReasoning: boolean; signal: unknown };
}

export const modelCalls: CapturedModelCall[] = [];
export let classifierReply = "SAFE";
export function setClassifierReply(value: string): void {
	classifierReply = value;
}
export function setClassifierThrows(value: boolean): void {
	classifierThrows = value;
}
/** Make the stubbed completion slower than the configurable timeout (abort tests). */
export function setClassifierDelay(ms: number): void {
	classifierDelayMs = ms;
}
let classifierThrows = false;
let classifierDelayMs = 5;

// The published 17.3.8 pi-ai/coding-agent pair is not mutually coherent: 30
// names coding-agent imports are absent from the pi-ai barrel (computed via
// tools/diff-exports.ts). The live OMP binary bundles a coherent pair; the npm
// pair explodes on these names. The mock fakes the whole surface; the test
// boundary is completeSimple, everything else is inert.
const missingExportStub = () => undefined;
const typeMarkerStub = "type-only-inert";
mock.module("@oh-my-pi/pi-ai", () => ({
	ANTHROPIC_OAUTH_GRANT_TTL_MS: 1000 * 60 * 60 * 24 * 30,
	AnthropicAuthConfig: typeMarkerStub,
	AnthropicSystemBlock: typeMarkerStub,
	Api: typeMarkerStub,
	ApiKey: typeMarkerStub,
	ApiKeyResolver: typeMarkerStub,
	AssistantMessage: typeMarkerStub,
	AssistantMessageEvent: typeMarkerStub,
	AssistantMessageEventStream: typeMarkerStub,
	AssistantRetryRecovery: typeMarkerStub,
	AssistantRetryRecoveryKind: typeMarkerStub,
	AuthCredential: typeMarkerStub,
	AuthCredentialSnapshotEntry: typeMarkerStub,
	AuthCredentialStore: typeMarkerStub,
	AuthStorage: typeMarkerStub,
	CodexCompactionContext: typeMarkerStub,
	CompletionProbe: typeMarkerStub,
	CompletionProbeInput: typeMarkerStub,
	ComputerSafetyCheck: typeMarkerStub,
	Context: typeMarkerStub,
	CredentialCompletionResult: typeMarkerStub,
	CredentialDisabledEvent: typeMarkerStub,
	CursorExecHandlers: typeMarkerStub,
	CursorMcpCall: typeMarkerStub,
	CursorMcpResource: typeMarkerStub,
	CursorMcpResourceContent: typeMarkerStub,
	CursorShellStreamCallbacks: typeMarkerStub,
	CursorTodoSnapshot: typeMarkerStub,
	DeveloperMessage: typeMarkerStub,
	DisabledCredentialSummary: typeMarkerStub,
	Effort: typeMarkerStub,
	EventStream: class {},
	FetchImpl: typeMarkerStub,
	ImageContent: typeMarkerStub,
	KnownProvider: typeMarkerStub,
	Message: typeMarkerStub,
	MessageAttribution: typeMarkerStub,
	Model: typeMarkerStub,
	ModelSpec: typeMarkerStub,
	ModelUsageHealth: typeMarkerStub,
	OAuthAccess: typeMarkerStub,
	OAuthAccessResolution: typeMarkerStub,
	OAuthAccountIdentity: typeMarkerStub,
	OAuthAccountSummary: typeMarkerStub,
	OAuthCredential: typeMarkerStub,
	OAuthProvider: typeMarkerStub,
	OAuthProviderInfo: typeMarkerStub,
	OpenAIResponsesHistoryPayload: typeMarkerStub,
	PASTE_CODE_LOGIN_PROVIDERS: [],
	PROVIDER_REGISTRY: typeMarkerStub,
	REMOTE_REFRESH_SENTINEL: "inert-sentinel",
	ProviderDetails: typeMarkerStub,
	ProviderPayload: typeMarkerStub,
	ProviderResponseMetadata: typeMarkerStub,
	ProviderSessionState: typeMarkerStub,
	RawSseEvent: typeMarkerStub,
	ResetCreditAccountStatus: typeMarkerStub,
	ResetCreditRedeemOutcome: typeMarkerStub,
	ResetCreditTarget: typeMarkerStub,
	ServiceTier: typeMarkerStub,
	ServiceTierByFamily: typeMarkerStub,
	SqliteAuthCredentialStore: class {},
	ServiceTierFamily: typeMarkerStub,
	SimpleStreamOptions: typeMarkerStub,
	Static: typeMarkerStub,
	StoredAuthCredential: typeMarkerStub,
	THINKING_EFFORTS: [],
	TSchema: typeMarkerStub,
	TextContent: typeMarkerStub,
	ThinkingContent: typeMarkerStub,
	Tool: typeMarkerStub,
	ToolCall: typeMarkerStub,
	ToolChoice: typeMarkerStub,
	ToolExample: typeMarkerStub,
	ToolResultMessage: typeMarkerStub,
	Usage: typeMarkerStub,
	UsageHistoryEntry: typeMarkerStub,
	UsageLimit: typeMarkerStub,
	UsageReport: typeMarkerStub,
	UsageResetCreditDetail: typeMarkerStub,
	UsageUnit: typeMarkerStub,
	UserMessage: typeMarkerStub,
	buildAnthropicAuthConfig: missingExportStub,
	buildAnthropicSearchHeaders: missingExportStub,
	buildAnthropicSystemBlocks: missingExportStub,
	buildAnthropicUrl: missingExportStub,
	calculateRateLimitBackoffMs: missingExportStub,
	clearAnthropicFastModeFallback: missingExportStub,
	coerceServiceTierByFamily: missingExportStub,
	deriveClaudeDeviceId: missingExportStub,
	getEnvApiKey: missingExportStub,
	getOAuthProviders: missingExportStub,
	getOpenRouterHeaders: missingExportStub,
	getProviderDetails: missingExportStub,
	isAnthropicFastModeFallbackDisabled: missingExportStub,
	isApiKeyResolver: missingExportStub,
	isAuthRetryableError: missingExportStub,
	isDefinitiveOAuthFailure: missingExportStub,
	isSqliteBusyError: missingExportStub,
	isUsageLimitOutcome: missingExportStub,
	jsonSchemaToTypeScript: missingExportStub,
	listProvidersWithEnvKey: missingExportStub,
	parseRateLimitReason: missingExportStub,
	realizesPriorityServiceTier: missingExportStub,
	resolveAnthropicMetadataUserId: missingExportStub,
	resolveApiKeyOnce: missingExportStub,
	resolveModelServiceTier: missingExportStub,
	resolveUsedFraction: missingExportStub,
	retryTransientCompletion: missingExportStub,
	seedApiKeyResolver: missingExportStub,
	shouldSendServiceTier: missingExportStub,
	serviceTierFamily: typeMarkerStub,
	streamSimple: missingExportStub,
	stripSchemaDescriptions: missingExportStub,
	stripClaudeToolPrefix: missingExportStub,
	toolWireSchema: typeMarkerStub,
	validateToolArguments: missingExportStub,
	validateToolCall: missingExportStub,
	withAuth: missingExportStub,
	withOAuthAccess: missingExportStub,
	wrapFetchForCch: missingExportStub,
	completeSimple: async (model: unknown, request: unknown, options: unknown) => {
		if (classifierThrows) throw new Error("model call failed");
		const signal = (options as { signal?: AbortSignal } | undefined)?.signal;
		await new Promise<void>((resolve, reject) => {
			if (signal?.aborted) {
				reject(new Error("aborted before completion"));
				return;
			}
			signal?.addEventListener("abort", () => reject(new Error("aborted before completion")));
			setTimeout(resolve, classifierDelayMs);
		});
		modelCalls.push({
			model,
			request: request as CapturedModelCall["request"],
			options: options as CapturedModelCall["options"],
		});
		return { content: [{ type: "text", text: classifierReply }] };
	},
}));

type Handler = (event: unknown, ctx: ExtensionContext) => unknown;
const handlers = new Map<string, Handler>();

/** Load the plugin with a fake pi; returns a fire() bound to it. */
export async function loadPlugin(settings: Record<string, unknown>): Promise<void> {
	handlers.clear();
	modelCalls.length = 0;
	classifierThrows = false;
	const mod = await import("../index.ts");
	mod.default({
		pi: { settings },
		on: (event: string, handler: Handler) => {
			handlers.set(event, handler);
		},
		registerCommand: () => {},
		logger: {
			warn: (message: string) => {
				loggerWarnings.push(message);
			},
			error: () => {},
		},
	} as unknown as ExtensionAPI);
}

/** Captured `pi.logger.warn` messages. The headless notice path writes here
 *  rather than to ctx.ui, so without this it cannot be asserted at all. */
export const loggerWarnings: string[] = [];

export function resetLoggerWarnings(): void {
	loggerWarnings.length = 0;
}

export async function fire(event: string, payload: unknown, ctx: ExtensionContext): Promise<unknown> {
	const handler = handlers.get(event);
	if (!handler) throw new Error(`no handler registered for "${event}"`);
	return await handler(payload, ctx);
}

export function makeEvent(command: string, input: Record<string, unknown> = {}): { toolName: string; input: Record<string, unknown> } {
	return { toolName: "bash", input: { command, ...input } };
}

export interface CtxOptions {
	sessionId?: string;
	cwd?: string;
	hasUI?: boolean;
	confirmResult?: boolean;
	tinyModel?: unknown;
	model?: unknown;
}

export function makeCtx(options: CtxOptions = {}): ExtensionContext {
	const confirmCalls: string[][] = [];
	const notifyCalls: string[][] = [];
	const ctx = {
		cwd: options.cwd ?? "/workspace",
		sessionManager: { getSessionId: () => options.sessionId ?? "session-1" },
		hasUI: options.hasUI ?? false,
		ui: {
			confirm: async (title: string, message: string) => {
				confirmCalls.push([title, message]);
				return options.confirmResult ?? false;
			},
			notify: (message: string, type = "info") => {
				notifyCalls.push([message, type]);
			},
		},
		// Mirrors the host resolver contract: an empty selector is the caller's
		// fallback model; `@tiny` is the tiny role (also the fallback model in
		// tests); any other selector resolves by name; `undefined` when the
		// selector names no available model (like model-resolver.ts).
		models: {
			resolve: (selector: string | undefined) => {
				const s = selector?.trim();
				if (!s || s === "@tiny") return options.tinyModel;
				return { id: s };
			},
		},
		// "model" in options distinguishes an explicit undefined (no model)
		// from an absent option (default test model).
		model: "model" in options ? options.model : { id: "test-model" },
		modelRegistry: { resolver: () => undefined },
	} as unknown as ExtensionContext;
	Object.defineProperty(ctx, "confirmCalls", { value: confirmCalls });
	Object.defineProperty(ctx, "notifyCalls", { value: notifyCalls });
	return ctx;
}

export function confirmCalls(ctx: ExtensionContext): string[][] {
	return (ctx as unknown as { confirmCalls: string[][] }).confirmCalls;
}

export function notifyCalls(ctx: ExtensionContext): string[][] {
	return (ctx as unknown as { notifyCalls: string[][] }).notifyCalls;
}

export function makeSettings(patterns: unknown[], bashPolicy?: string): Record<string, unknown> {
	const store: Record<string, unknown> = {
		"bash.patterns": patterns,
		"tools.approval": bashPolicy ? { bash: bashPolicy } : {},
	};
	// The plugin reads host settings through settings.get(key), like the real
	// Settings singleton.
	return { get: (key: string): unknown => store[key] };
}

let testConfigPath: string | undefined;

// The plugin's config path must NEVER resolve to the real homedir file during
// tests: machine state (a live /classifier edit) would silently flip defaults
// and fail the suite. Force the env override before the plugin first reads it.
process.env.OMP_BASH_CLASSIFIER_CONFIG = useTempConfigFile();

let testLockPath: string | undefined;

// Same reasoning as the config file above, and it bites harder: the real
// lockfile records whether the developer running the suite has the plugin
// disabled, so without this the stale-disable notice fires (or does not) based
// on machine state. Default to a path that does not exist, which reads as
// "not disabled".
process.env.OMP_BASH_CLASSIFIER_TEST_LOCKFILE = lockfilePathForTests();

function lockfilePathForTests(): string {
	if (!testLockPath) {
		// PID alone collides across reruns, and the file outlives the process, so
		// the next run inheriting it would believe the plugin is disabled — the
		// machine-state dependence this indirection exists to remove.
		const suffix = Math.random().toString(36).slice(2, 10);
		testLockPath = path.join(os.tmpdir(), `omp-classifier-test-lock-${process.pid}-${suffix}.json`);
	}
	return testLockPath;
}

/** Write a host lockfile the plugin will read. */
export function writeLockfile(raw: Record<string, unknown>): void {
	fs.writeFileSync(lockfilePathForTests(), JSON.stringify(raw));
}

// The file outlives the process, so a rerun could inherit a lockfile saying the
// plugin is disabled. The random suffix above makes that collision unlikely; this
// makes it impossible.
process.on("exit", () => {
	try {
		if (testLockPath) fs.unlinkSync(testLockPath);
	} catch {
		// already gone
	}
});

/** Remove the host lockfile, so the plugin sees no lockfile at all. */
export function removeLockfile(): void {
	try {
		fs.unlinkSync(lockfilePathForTests());
	} catch {
		// absent is fine
	}
}

/** Point the plugin's config file at a fresh temp path (per test file). */
export function useTempConfigFile(): string {
	if (!testConfigPath) {
		testConfigPath = path.join(os.tmpdir(), `omp-classifier-test-${process.pid}.json`);
	}
	process.env.OMP_BASH_CLASSIFIER_CONFIG = testConfigPath;
	return testConfigPath;
}

export function writeConfigFile(raw: Record<string, unknown>): void {
	const target = useTempConfigFile();
	fs.writeFileSync(target, JSON.stringify(raw));
}

export function removeConfigFile(): void {
	// Point at a fresh per-process temp path instead of deleting the env var:
	// with the var unset the plugin falls back to the real homedir file, and
	// machine state must never leak into the suite.
	if (testConfigPath) {
		try {
			fs.unlinkSync(testConfigPath);
		} catch {
			// absent is fine
		}
	}
	testConfigPath = undefined;
	process.env.OMP_BASH_CLASSIFIER_CONFIG = useTempConfigFile();
}

/** Render an interceptor result: undefined means "let the host decide/run". */
export function resultText(result: unknown): string {
	if (result === undefined) return "ALLOWED";
	if (typeof result === "object" && result !== null && "reason" in result) {
		return String((result as { reason: unknown }).reason);
	}
	return String(result);
}
