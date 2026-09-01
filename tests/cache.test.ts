/**
 * Cache tests: verdicts are keyed per session by the full execution identity —
 * native-resolved cwd, canonical env, pty, timeout, async, and command — and a
 * session boundary drops only that session's entries.
 */
import { beforeEach, describe, expect, test } from "bun:test";
import {
	fire,
	loadPlugin,
	makeCtx,
	makeEvent,
	makeSettings,
	modelCalls,
	resultText,
	selectCalls,
	setClassifierReply,
} from "./fixtures";

beforeEach(async () => {
	await loadPlugin(makeSettings([]));
	setClassifierReply("UNSAFE"); // default: every classification blocks, so cache hits are visible as blocked-without-model
});

let seq = 0;

const gate = async (command: string, opts: { sessionId?: string; cwd?: string; input?: Record<string, unknown>; hasUI?: boolean } = {}) => {
	seq += 1;
	const ctx = makeCtx({ sessionId: opts.sessionId ?? `cache-${seq}`, cwd: opts.cwd, hasUI: opts.hasUI ?? false });
	const result = await fire("tool_call", makeEvent(command, opts.input ?? {}), ctx);
	return { text: resultText(result), modelCalls: modelCalls.length, selects: selectCalls(ctx).length };
};

describe("identical execution identity is judged once", () => {
	test("same session, cwd, and command: one model call, second run cached", async () => {
		const first = await gate("npm publish", { cwd: "/repo", sessionId: "shared-session" });
		expect(first.text).toContain("classified unsafe");
		expect(first.modelCalls).toBe(1);

		const second = await gate("npm publish", { cwd: "/repo", sessionId: "shared-session" });
		expect(second.text).toContain("classified unsafe"); // blocked again (UNSAFE cached)
		expect(second.modelCalls).toBe(1); // no second model call
	});
	test("cached SAFE runs without a second model call or prompt", async () => {
		setClassifierReply("SAFE");
		const ctx = makeCtx({ sessionId: "cache-session", hasUI: true });
		await fire("tool_call", makeEvent("git status", { cwd: "/repo" }), ctx);
		expect(modelCalls.length).toBe(1);

		await fire("tool_call", makeEvent("git status", { cwd: "/repo" }), makeCtx({ sessionId: "cache-session", hasUI: true }));
		expect(modelCalls.length).toBe(1);
		expect(selectCalls(ctx).length).toBe(0);
	});
});

describe("resolved model is part of the identity", () => {
	test("a session whose classifier model changes reclassifies", async () => {
		// Same session + command + cwd; the @tiny role resolves differently.
		const a = makeCtx({ sessionId: "model-shift", cwd: "/repo", tinyModel: { id: "tiny-a" } });
		const b = makeCtx({ sessionId: "model-shift", cwd: "/repo", tinyModel: { id: "tiny-b" } });
		await fire("tool_call", makeEvent("npm publish"), a);
		expect(modelCalls.length).toBe(1);
		await fire("tool_call", makeEvent("npm publish"), b);
		expect(modelCalls.length).toBe(2);
		expect((modelCalls[1].model as { id: string }).id).toBe("tiny-b");
	});

	test("changing a backup candidate invalidates a verdict cached under the same primary", async () => {
		let tinyRole: string[] = ["tiny-a", "tiny-b"];
		await loadPlugin({
			get: (key: string): unknown => {
				if (key === "bash.patterns") return [];
				if (key === "tools.approval") return {};
				if (key === "modelRoles") return { tiny: tinyRole };
				return undefined;
			},
		});
		setClassifierReply("SAFE");
		const context = () =>
			makeCtx({
				sessionId: "backup-shift",
				cwd: "/repo",
				tinyModel: { id: "tiny-a" },
			});

		await fire("tool_call", makeEvent("git status"), context());
		expect(modelCalls.length).toBe(1);
		tinyRole = ["tiny-a", "tiny-c"];
		await fire("tool_call", makeEvent("git status"), context());
		expect(modelCalls.length).toBe(2);
	});
});


describe("every execution-affecting input is part of the identity", () => {
	test("cwd change reclassifies", async () => {
		await gate("make build", { cwd: "/repo/a" });
		const second = await gate("make build", { cwd: "/repo/b" });
		expect(second.modelCalls).toBe(2);
	});

	test("env override commands prompt and never classify (no cache entry)", async () => {
		// Environment overrides are decided by a permission request before any
		// classifier path — env values can select the program that runs — so
		// they never reach the cache at all.
		const first = await gate("make build", { cwd: "/repo", input: { env: { A: "1", B: "2" } } });
		expect(first.text).toContain("environment override");
		expect(first.modelCalls).toBe(0);
		const second = await gate("make build", { cwd: "/repo", input: { env: { B: "2", A: "1" } } });
		expect(second.modelCalls).toBe(0);
	});

	test("pty, timeout, and async each change the identity", async () => {
		await gate("make build", { cwd: "/repo" });
		const pty = await gate("make build", { cwd: "/repo", input: { pty: true } });
		expect(pty.modelCalls).toBe(2);
		const timeout = await gate("make build", { cwd: "/repo", input: { timeout: 42 } });
		expect(timeout.modelCalls).toBe(3);
		const asyncFlag = await gate("make build", { cwd: "/repo", input: { async: true } });
		expect(asyncFlag.modelCalls).toBe(4);
	});

	test("session change reclassifies", async () => {
		await gate("make build", { cwd: "/repo" });
		const other = await gate("make build", { cwd: "/repo", sessionId: "other-session" });
		expect(other.modelCalls).toBe(2);
	});
});

describe("cwd resolution", () => {
	test("leading 'cd' without a cwd param resolves into the key", async () => {
		const first = await gate("cd /tmp/x && make build", { sessionId: "cd-session" });
		expect(first.text).toContain("classified unsafe");
		expect(first.modelCalls).toBe(1);
		// Identical command again: same resolved cwd, cached.
		const second = await gate("cd /tmp/x && make build", { sessionId: "cd-session" });
		expect(second.modelCalls).toBe(1);
	});

	test("relative cwd resolves against the session cwd in the key", async () => {
		const ctx = makeCtx({ sessionId: "cache-session", cwd: "/workspace" });
		await fire("tool_call", makeEvent("make build", { cwd: "subdir" }), ctx);
		expect(modelCalls.length).toBe(1);
		// An explicit absolute path to the same dir is the same identity.
		await fire("tool_call", makeEvent("make build", { cwd: "/workspace/subdir" }), makeCtx({ sessionId: "cache-session", cwd: "/workspace" }));
		expect(modelCalls.length).toBe(1);
	});
});

describe("session boundaries drop only that session's entries", () => {
	for (const event of ["session_start", "session_before_switch", "session_switch", "session_shutdown"]) {
		test(`${event} clears the current session bucket only`, async () => {
			const keep = `keep-${event}`;
			const drop = `drop-${event}`;
			await gate("make build", { sessionId: keep });
			await gate("make build", { sessionId: drop });
			expect(modelCalls.length).toBe(2);

			// Boundary in the dropped session: its bucket is cleared.
			await fire(event, {}, makeCtx({ sessionId: drop }));
			await gate("make build", { sessionId: drop });
			expect(modelCalls.length).toBe(3); // reclassified

			// The other session's verdict survives.
			await gate("make build", { sessionId: keep });
			expect(modelCalls.length).toBe(3);
		});
	}
});
