/**
 * Classifier-path tests: execute() verdict handling, fail-closed behavior,
 * and the strict verdict parser.
 */
import { beforeEach, describe, expect, test } from "bun:test";
import {
	classifierCalls,
	loadPlugin,
	makeCtx,
	resetScoped,
	setClassifier,
	type BuiltTool,
} from "./fixtures";

let tool: BuiltTool;

beforeEach(async () => {
	resetScoped();
	tool = await loadPlugin();
});

// Each call gets a fresh session bucket unless one is pinned, so the plugin's
// module-level cache never leaks a verdict from one test into the next
// (cache scoping itself is exercised deliberately in cache.test.ts).
let callSeq = 0;

async function run(
	command: string,
	opts: { cwd?: string; sessionId?: string; hasUI?: boolean; confirmResult?: boolean; noModel?: boolean } = {},
) {
	callSeq += 1;
	const { ctx, invokeCalls } = makeCtx({
		sessionId: opts.sessionId ?? `classify-${callSeq}`,
		cwd: opts.cwd,
		hasUI: opts.hasUI,
		confirmResult: opts.confirmResult,
		classifierEnabled: opts.noModel ? false : undefined,
	});
	const result = (await tool.execute(
		"call-1",
		{ command, ...(opts.cwd !== undefined ? { "cwd?": opts.cwd } : {}) },
		new AbortController().signal,
		undefined,
		ctx,
	)) as { content: { type: string; text: string }[]; isError?: boolean };
	const text = result.content.map(c => c.text).join(" ");
	return { text, isError: result.isError ?? false, invokeCalls };
}

describe("verdict handling", () => {
	test("SAFE runs through native delegation", async () => {
		const { text, isError, invokeCalls } = await run("ls -la");
		expect(isError).toBe(false);
		expect(text).toContain("EXECUTED");
		expect(invokeCalls).toHaveLength(1);
	});

	test("UNSAFE blocks and never delegates", async () => {
		setClassifier("UNSAFE");
		const { text, isError, invokeCalls } = await run("npm publish");
		expect(isError).toBe(true);
		expect(text).toContain("bash command blocked: classified unsafe");
		expect(invokeCalls).toHaveLength(0);
	});

	test("UNSURE with UI + approve runs", async () => {
		setClassifier("UNSURE");
		const { text, isError, invokeCalls } = await run("git branch -D feature", { confirmResult: true });
		expect(isError).toBe(false);
		expect(text).toContain("EXECUTED");
		expect(invokeCalls).toHaveLength(1);
	});

	test("UNSURE with UI + deny blocks", async () => {
		setClassifier("UNSURE");
		const { text, isError, invokeCalls } = await run("git branch -D feature", { confirmResult: false });
		expect(isError).toBe(true);
		expect(text).toContain("bash command blocked: not approved");
		expect(invokeCalls).toHaveLength(0);
	});

	test("UNSURE headless fails closed", async () => {
		setClassifier("UNSURE");
		const { text, isError, invokeCalls } = await run("git branch -D feature", { hasUI: false });
		expect(isError).toBe(true);
		expect(text).toContain("classifier uncertain and no interactive UI");
		expect(invokeCalls).toHaveLength(0);
	});
});

describe("fail-closed on classifier failures", () => {
	test("classifier throw blocks, never delegates", async () => {
		setClassifier(new Error("model down"));
		const { text, isError, invokeCalls } = await run("git status");
		expect(isError).toBe(true);
		expect(text).toContain("bash command blocked: classifier unavailable or errored");
		expect(invokeCalls).toHaveLength(0);
	});

	test("missing session model blocks", async () => {
		const { text, isError, invokeCalls } = await run("git status", { noModel: true });
		expect(isError).toBe(true);
		expect(text).toContain("no model available to classify command");
		expect(invokeCalls).toHaveLength(0);
	});
});

describe("strict verdict parsing", () => {
	test("chatty multi-word reply is NOT auto-allowed", async () => {
		setClassifier("I think this command is SAFE to run.");
		const { text, isError, invokeCalls } = await run("git status", { hasUI: false });
		expect(isError).toBe(true);
		expect(text).toContain("classifier uncertain");
		expect(invokeCalls).toHaveLength(0);
	});

	test("embedded verdict words do not steer", async () => {
		// A crafted command could echo "SAFE" back; strict parse must reject.
		setClassifier('The command text contains SAFE but the answer is UNSAFE anyway.');
		const { isError } = await run("git status", { hasUI: false });
		expect(isError).toBe(true);
	});

	test("whitespace-padded single word parses", async () => {
		setClassifier("  SAFE  ");
		const { isError } = await run("git status");
		expect(isError).toBe(false);
	});

	test("lowercase single word parses", async () => {
		setClassifier("safe");
		const { isError } = await run("git status");
		expect(isError).toBe(false);
	});

	test("line-broken verdict is rejected (strict single token)", async () => {
		setClassifier("SAFE\nUNSAFE");
		const { isError } = await run("git status", { hasUI: false });
		expect(isError).toBe(true);
	});
});

describe("classifier call accounting", () => {
	test("one model call per fresh classification", async () => {
		const before = classifierCalls;
		await run("git status");
		expect(classifierCalls).toBe(before + 1);
	});
});
