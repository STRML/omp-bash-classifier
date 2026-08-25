/**
 * The stale-disable notice. `omp plugin disable` rewrites the host lockfile,
 * but OMP binds interceptors at session start and never unbinds them, so the
 * plugin keeps classifying in a session that was already running. It cannot
 * honor the flag itself (a project-scope lockfile may legitimately re-enable a
 * plugin the user-scope one disables), so it says so once per session.
 */
import { beforeEach, describe, expect, test } from "bun:test";
import {
	fire,
	loadPlugin,
	makeCtx,
	makeEvent,
	makeSettings,
	notifyCalls,
	removeConfigFile,
	removeLockfile,
	resultText,
	setClassifierDelay,
	writeLockfile,
} from "./fixtures";

beforeEach(async () => {
	removeConfigFile();
	removeLockfile();
	setClassifierDelay(5);
	await loadPlugin(makeSettings([]));
});

const DISABLED = { plugins: { "omp-bash-classifier": { version: "0.2.0", enabled: false } } };
const ENABLED = { plugins: { "omp-bash-classifier": { version: "0.2.0", enabled: true } } };

describe("notice fires when the lockfile disabled us after we bound", () => {
	test("warns once, naming both ways out", async () => {
		writeLockfile(DISABLED);
		const ctx = makeCtx({ sessionId: "stale-1", hasUI: true });
		await fire("tool_call", makeEvent("git status"), ctx);

		const calls = notifyCalls(ctx);
		expect(calls).toHaveLength(1);
		const [message, level] = calls[0];
		expect(level).toBe("warning");
		expect(message).toContain("omp-bash-classifier");
		expect(message).toContain("Restart OMP");
		expect(message).toContain("/classifier enabled false");
	});

	test("second command in the same session does not warn again", async () => {
		writeLockfile(DISABLED);
		const ctx = makeCtx({ sessionId: "stale-2", hasUI: true });
		await fire("tool_call", makeEvent("git status"), ctx);
		await fire("tool_call", makeEvent("ls -la"), ctx);
		expect(notifyCalls(ctx)).toHaveLength(1);
	});

	test("a different session gets its own warning", async () => {
		writeLockfile(DISABLED);
		const first = makeCtx({ sessionId: "stale-3a", hasUI: true });
		const second = makeCtx({ sessionId: "stale-3b", hasUI: true });
		await fire("tool_call", makeEvent("git status"), first);
		await fire("tool_call", makeEvent("git status"), second);
		expect(notifyCalls(first)).toHaveLength(1);
		expect(notifyCalls(second)).toHaveLength(1);
	});

	test("headless logs instead of notifying, and still only once", async () => {
		writeLockfile(DISABLED);
		const ctx = makeCtx({ sessionId: "stale-headless", hasUI: false });
		await fire("tool_call", makeEvent("git status"), ctx);
		await fire("tool_call", makeEvent("ls -la"), ctx);
		expect(notifyCalls(ctx)).toHaveLength(0);
	});

	test("the notice does not change what the gate decides", async () => {
		writeLockfile(DISABLED);
		const ctx = makeCtx({ sessionId: "stale-4", hasUI: true });
		const result = resultText(await fire("tool_call", makeEvent("git status"), ctx));
		expect(result).toBe("ALLOWED");
	});
});

describe("session boundaries re-arm the notice", () => {
	for (const event of ["session_start", "session_before_switch", "session_switch", "session_shutdown"]) {
		test(`${event} clears the warned flag for that session only`, async () => {
			writeLockfile(DISABLED);
			const warned = `rearm-${event}`;
			const other = `other-${event}`;
			const first = makeCtx({ sessionId: warned, hasUI: true });
			const untouched = makeCtx({ sessionId: other, hasUI: true });
			await fire("tool_call", makeEvent("git status"), first);
			await fire("tool_call", makeEvent("git status"), untouched);
			expect(notifyCalls(first)).toHaveLength(1);

			await fire(event, {}, makeCtx({ sessionId: warned, hasUI: true }));
			const afterBoundary = makeCtx({ sessionId: warned, hasUI: true });
			await fire("tool_call", makeEvent("git status"), afterBoundary);
			expect(notifyCalls(afterBoundary)).toHaveLength(1);

			// The untouched session is still marked as warned.
			const otherAgain = makeCtx({ sessionId: other, hasUI: true });
			await fire("tool_call", makeEvent("git status"), otherAgain);
			expect(notifyCalls(otherAgain)).toHaveLength(0);
		});
	}
});

describe("notice stays silent otherwise", () => {
	test("no lockfile at all", async () => {
		const ctx = makeCtx({ sessionId: "quiet-1", hasUI: true });
		await fire("tool_call", makeEvent("git status"), ctx);
		expect(notifyCalls(ctx)).toHaveLength(0);
	});

	test("lockfile says enabled", async () => {
		writeLockfile(ENABLED);
		const ctx = makeCtx({ sessionId: "quiet-2", hasUI: true });
		await fire("tool_call", makeEvent("git status"), ctx);
		expect(notifyCalls(ctx)).toHaveLength(0);
	});

	test("lockfile has no entry for this plugin", async () => {
		writeLockfile({ plugins: { "some-other-plugin": { enabled: false } } });
		const ctx = makeCtx({ sessionId: "quiet-3", hasUI: true });
		await fire("tool_call", makeEvent("git status"), ctx);
		expect(notifyCalls(ctx)).toHaveLength(0);
	});

	test("malformed lockfile is not a disable signal", async () => {
		for (const raw of ['{"plugins": "nope"}', "{}", "not json at all", '{"plugins":{"omp-bash-classifier":7}}']) {
			removeLockfile();
			const { writeFileSync } = await import("node:fs");
			writeFileSync(process.env.OMP_PLUGINS_LOCK as string, raw);
			const ctx = makeCtx({ sessionId: `quiet-malformed-${raw.length}` });
			await fire("tool_call", makeEvent("git status"), ctx);
			expect(notifyCalls(ctx)).toHaveLength(0);
		}
	});

	test("enabled omitted from the entry is not a disable signal", async () => {
		writeLockfile({ plugins: { "omp-bash-classifier": { version: "0.2.0" } } });
		const ctx = makeCtx({ sessionId: "quiet-4", hasUI: true });
		await fire("tool_call", makeEvent("git status"), ctx);
		expect(notifyCalls(ctx)).toHaveLength(0);
	});
});
