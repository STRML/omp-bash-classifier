/**
 * Cache tests: verdicts are keyed by session + cwd + command, hit on repeat,
 * and never cross sessions or working directories.
 *
 * NOTE: the plugin module is loaded once per test FILE (bun isolates files),
 * so all cases here use distinct session ids / cwds / commands to stay
 * independent.
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

async function run(
	sessionId: string,
	cwd: string | undefined,
	command: string,
	confirmResult: boolean | undefined = undefined,
) {
	const { ctx, invokeCalls } = makeCtx({ sessionId, cwd, ...(confirmResult !== undefined ? { confirmResult } : {}) });
	const result = (await tool.execute(
		"call-1",
		{ command, ...(cwd !== undefined ? { "cwd?": cwd } : {}) },
		new AbortController().signal,
		undefined,
		ctx,
	)) as { content: { type: string; text: string }[]; isError?: boolean };
	const text = result.content.map(c => c.text).join(" ");
	return { text, isError: result.isError ?? false, invokeCalls };
}

describe("cache keying", () => {
	test("identical session+cwd+command classifies once, reuses verdict", async () => {
		setClassifier("SAFE");
		await run("cache-session", "/repo/a", "git status --short");
		const callsAfterFirst = classifierCalls;
		await run("cache-session", "/repo/a", "git status --short");
		expect(classifierCalls).toBe(callsAfterFirst); // cache hit: no second model call
	});

	test("same command in a different cwd reclassifies", async () => {
		setClassifier("SAFE");
		await run("cache-session", "/repo/a", "npm test");
		const callsAfterFirst = classifierCalls;
		await run("cache-session", "/repo/b", "npm test");
		expect(classifierCalls).toBe(callsAfterFirst + 1);
	});

	test("same command in a different session reclassifies", async () => {
		setClassifier("SAFE");
		await run("session-a", "/repo", "npm test");
		const callsAfterFirst = classifierCalls;
		await run("session-b", "/repo", "npm test");
		expect(classifierCalls).toBe(callsAfterFirst + 1);
	});

	test("cached UNSAFE blocks without reclassification", async () => {
		setClassifier("UNSAFE");
		await run("cache-session", "/repo", "npm publish");
		const callsAfterFirst = classifierCalls;
		const second = await run("cache-session", "/repo", "npm publish");
		expect(classifierCalls).toBe(callsAfterFirst);
		expect(second.text).toContain("classified unsafe (cached)");
		expect(second.invokeCalls).toHaveLength(0);
	});

	test("cached SAFE after interactive UNSURE approval", async () => {
		// First pass: classifier UNSURE, user approves -> SAFE cached.
		setClassifier("UNSURE");
		const first = await run("cache-session", "/repo", "git branch -D tmp", true);
		expect(first.isError).toBe(false);
		const callsAfterFirst = classifierCalls;
		// Second pass: verdict must come from cache.
		const second = await run("cache-session", "/repo", "git branch -D tmp");
		expect(classifierCalls).toBe(callsAfterFirst);
		expect(second.isError).toBe(false);
	});

	test("cwd-absent and cwd-empty are the same key", async () => {
		setClassifier("SAFE");
		await run("cache-session", undefined, "ls -la");
		const callsAfterFirst = classifierCalls;
		await run("cache-session", "", "ls -la");
		expect(classifierCalls).toBe(callsAfterFirst);
	});
});
