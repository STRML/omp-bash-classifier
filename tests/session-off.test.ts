/**
 * The per-session classifier pause (issue #48): `/classifier off` suspends
 * model classification for exactly one session — the same layer that
 * `config.enabled=false` gates, scoped to that session — and `/classifier on`
 * resumes it. Critical patterns, env overrides, and static rules keep
 * enforcing while paused, and a paused session's cached verdicts stay valid:
 * pausing is not a trust-state change, so a resume serves the cache instead
 * of re-asking the model.
 *
 * Harness conventions as session-grants.test.ts: fresh temp config dir per
 * test, unique session ids per test (the plugin's stores are module-level and
 * the module imports once per file run).
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { buildStatusReport } from "../index";
import {
	fire,
	fireCommand,
	loadPlugin,
	makeCtx,
	makeEvent,
	makeSettings,
	modelCalls,
	notifyCalls,
	refusalOf,
	resultText,
	setClassifierReply,
	writeConfigFile,
} from "./fixtures";

let dir = "";
let seq = 0;

beforeEach(async () => {
	dir = fs.mkdtempSync(path.join(os.tmpdir(), "omp-session-off-"));
	process.env.OMP_CLASSIFIER_CONFIG = path.join(dir, "omp-classifier.json");
	await loadPlugin(makeSettings([]));
	setClassifierReply("UNSAFE | no");
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
});

const nextSession = (): string => `pause-${(seq += 1)}`;

/** Pause (or resume) via the registered command, asserting the toast. */
const runCommand = async (args: string, sessionId: string): Promise<string[][]> => {
	const ctx = makeCtx({ sessionId });
	await fireCommand("classifier", args, ctx);
	return notifyCalls(ctx);
};

const evalEvent = (code: string) => ({ toolName: "eval", input: { code, language: "py" } });

describe("/classifier off (per-session pause)", () => {
	test("off skips classification for that session: no model call, host decides", async () => {
		const sid = nextSession();
		const calls = await runCommand("off", sid);
		expect(calls[calls.length - 1][0]).toContain("paused for this session only");
		expect(calls[calls.length - 1][0]).toContain("/classifier on");
		expect(calls[calls.length - 1][0]).toContain("Critical, env, and static-rule checks stay active");

		// The gate falls through: undefined means "let the host decide/run",
		// and the classifier model never ran.
		const ctx = makeCtx({ sessionId: sid });
		const result = await fire("tool_call", makeEvent("git status"), ctx);
		expect(result).toBeUndefined();
		expect(modelCalls.length).toBe(0);
	});

	test("another session is unaffected and still classifies", async () => {
		const paused = nextSession();
		await runCommand("off", paused);

		const other = nextSession();
		const ctx = makeCtx({ sessionId: other });
		const result = await fire("tool_call", makeEvent(`git branch -D feature-${other}`), ctx);
		expect(resultText(result)).not.toBe("ALLOWED");
		expect(refusalOf(result).layer).toBe("headless");
		expect(modelCalls.length).toBe(1);
	});

	test("on resumes: the same session classifies again", async () => {
		const sid = nextSession();
		await runCommand("off", sid);
		const pausedCtx = makeCtx({ sessionId: sid });
		expect(await fire("tool_call", makeEvent("git status"), pausedCtx)).toBeUndefined();
		expect(modelCalls.length).toBe(0);

		const calls = await runCommand("on", sid);
		expect(calls[calls.length - 1][0]).toContain("resumed");

		const ctx = makeCtx({ sessionId: sid });
		const result = await fire("tool_call", makeEvent("git status"), ctx);
		expect(refusalOf(result).layer).toBe("headless");
		expect(modelCalls.length).toBe(1);
	});

	test("on when not paused: harmless notice, no state change", async () => {
		const sid = nextSession();
		const calls = await runCommand("on", sid);
		expect(calls[calls.length - 1][0]).toContain("not paused");

		// The session never paused, so nothing about the gate changed.
		const ctx = makeCtx({ sessionId: sid });
		const result = await fire("tool_call", makeEvent(`git branch -D feature-${sid}`), ctx);
		expect(refusalOf(result).layer).toBe("headless");
		expect(modelCalls.length).toBe(1);
	});

	test("global enabled=false dominates: on never force-enables, off stays harmless", async () => {
		writeConfigFile({ enabled: false });
		const sid = nextSession();
		// Both commands must be no-ops against the global kill switch.
		await runCommand("on", sid);
		await runCommand("off", sid);
		const ctx = makeCtx({ sessionId: sid });
		const result = await fire("tool_call", makeEvent("make build"), ctx);
		expect(resultText(result)).toBe("ALLOWED");
		expect(modelCalls.length).toBe(0);
	});
});

describe("pause scope and cache", () => {
	test("cached verdicts survive off/on: resume serves the cache, no second model call", async () => {
		const sid = nextSession();
		setClassifierReply("SAFE");
		const first = await fire("tool_call", makeEvent("git status"), makeCtx({ sessionId: sid }));
		expect(resultText(first)).toBe("ALLOWED");
		expect(modelCalls.length).toBe(1);

		// The pause is not a trust-state change: the verdict cached before the
		// pause answers again after the resume.
		await runCommand("off", sid);
		await runCommand("on", sid);
		const second = await fire("tool_call", makeEvent("git status"), makeCtx({ sessionId: sid }));
		expect(resultText(second)).toBe("ALLOWED");
		expect(modelCalls.length).toBe(1);
	});

	test("spawn-bearing eval payload on a paused session falls through", async () => {
		const sid = nextSession();
		await runCommand("off", sid);
		const code = `import subprocess\nsubprocess.run(["ls"])`;
		const ctx = makeCtx({ sessionId: sid });
		const result = await fire("tool_call", evalEvent(code), ctx);
		expect(result).toBeUndefined();
		expect(modelCalls.length).toBe(0);

		// Resuming re-arms the eval gate for the same session.
		await runCommand("on", sid);
		const resumed = makeCtx({ sessionId: sid });
		const evalResult = await fire("tool_call", evalEvent(code), resumed);
		expect(refusalOf(evalResult).tool).toBe("eval");
		expect(refusalOf(evalResult).layer).toBe("headless");
		expect(modelCalls.length).toBe(1);
	});

	test("dry-run while paused reports would allow at the session layer", async () => {
		const sid = nextSession();
		await runCommand("off", sid);
		const ctx = makeCtx({ sessionId: sid });
		await fireCommand("classifier", "dry-run git push --force origin main", ctx);
		const calls = notifyCalls(ctx);
		expect(calls.length).toBeGreaterThan(0);
		const report = JSON.parse(calls[calls.length - 1][0]) as Record<string, unknown>;
		expect(report.would).toBe("allow");
		expect(report.layer).toBe("session");
		expect(report.why).toContain("paused for this session");
	});

	test("a session boundary drops the pause for that session", async () => {
		const sid = nextSession();
		await runCommand("off", sid);
		await fire("session_start", {}, makeCtx({ sessionId: sid }));

		const ctx = makeCtx({ sessionId: sid });
		const result = await fire("tool_call", makeEvent("git status"), ctx);
		expect(refusalOf(result).layer).toBe("headless");
		expect(modelCalls.length).toBe(1);
	});

	test("buildStatusReport lists the paused session, sorted", async () => {
		const a = nextSession();
		const b = nextSession();
		// The plugin module (and its pause set) is shared across this file's
		// tests, so earlier suites may legitimately still hold pauses. Assert
		// membership and sortedness relative to the pre-test snapshot.
		const before = buildStatusReport().pausedSessions;
		expect(before).not.toContain(a);
		expect(before).not.toContain(b);

		await runCommand("off", b);
		await runCommand("off", a);
		const after = buildStatusReport().pausedSessions;
		expect(after.filter(id => id === a || id === b)).toEqual([a, b]);
		expect(after).toEqual([...after].sort());
	});
});
