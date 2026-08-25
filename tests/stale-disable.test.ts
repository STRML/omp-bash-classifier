/**
 * The stale-disable notice. `omp plugin disable` rewrites the host lockfile,
 * but OMP binds interceptors at session start and never unbinds them, so the
 * plugin keeps classifying in a session that was already running. It cannot
 * honor the flag itself (a project-scope lockfile may legitimately re-enable a
 * plugin the user-scope one disables), so it says so once per session.
 */
import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import {
	fire,
	loadPlugin,
	makeCtx,
	makeEvent,
	makeSettings,
	loggerWarnings,
	notifyCalls,
	resetLoggerWarnings,
	removeConfigFile,
	removeLockfile,
	resultText,
	setClassifierDelay,
	writeConfigFile,
	writeLockfile,
} from "./fixtures";

// Bun runs every file in one process and static-gate.test.ts sorts after this
// one, so a lockfile left behind here arms a false pass for whatever anyone
// adds next.
afterAll(() => {
	removeLockfile();
});

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
		expect(message).toContain("restart OMP");
		expect(message).toContain("/classifier enabled false");
		// It reads the user-scope lockfile only, so it states what it read and
		// does not assert that the plugin is off.
		expect(message).toContain("marked disabled");
		expect(message).toContain("project-scope lockfile can re-enable it");
	});

	test("second command in the same session does not warn again", async () => {
		writeLockfile(DISABLED);
		const ctx = makeCtx({ sessionId: "stale-2", hasUI: true });
		await fire("tool_call", makeEvent("git status"), ctx);
		await fire("tool_call", makeEvent("ls -la"), ctx);
		expect(notifyCalls(ctx)).toHaveLength(1);
	});

	test("two concurrent bash calls in one session warn once, not twice", async () => {
		// Non-pty bash is concurrency:"shared" and the agent loop starts shared
		// tasks without awaiting the previous one, so one turn with two bash
		// calls interleaves at the lockfile await. With the has() check ahead of
		// that await, both handlers passed the guard and the session got two
		// toasts.
		writeLockfile(DISABLED);
		const ctx = makeCtx({ sessionId: "race-1", hasUI: true });
		await Promise.all([
			fire("tool_call", makeEvent("git status"), ctx),
			fire("tool_call", makeEvent("ls -la"), ctx),
		]);
		expect(notifyCalls(ctx)).toHaveLength(1);
	});

	test("a throwing notify does not burn the session's one notice", async () => {
		writeLockfile(DISABLED);
		const ctx = makeCtx({ sessionId: "throwing-ui", hasUI: true });
		const ui = (ctx as unknown as { ui: { notify: (m: string, t?: string) => void } }).ui;
		const real = ui.notify;
		let thrown = false;
		ui.notify = () => {
			thrown = true;
			throw new Error("ui gone");
		};
		await fire("tool_call", makeEvent("git status"), ctx);
		expect(thrown).toBe(true);

		// Marking the session warned before delivery meant this second call
		// stayed silent forever.
		ui.notify = real;
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
		resetLoggerWarnings();
		const ctx = makeCtx({ sessionId: "stale-headless", hasUI: false });
		await fire("tool_call", makeEvent("git status"), ctx);
		await fire("tool_call", makeEvent("ls -la"), ctx);
		expect(notifyCalls(ctx)).toHaveLength(0);
		// Assert the branch that actually runs. Without this the test passes
		// even if the logger call is deleted outright.
		expect(loggerWarnings).toHaveLength(1);
		expect(loggerWarnings[0]).toContain("omp-bash-classifier");
		expect(loggerWarnings[0]).toContain("marked disabled");
	});

	test("with a UI it notifies and does NOT log", async () => {
		writeLockfile(DISABLED);
		resetLoggerWarnings();
		const ctx = makeCtx({ sessionId: "stale-ui-only", hasUI: true });
		await fire("tool_call", makeEvent("git status"), ctx);
		expect(notifyCalls(ctx)).toHaveLength(1);
		expect(loggerWarnings).toHaveLength(0);
	});

	test("the notice does not change what the gate decides", async () => {
		writeLockfile(DISABLED);
		const ctx = makeCtx({ sessionId: "stale-4", hasUI: true });
		const result = resultText(await fire("tool_call", makeEvent("git status"), ctx));
		expect(result).toBe("ALLOWED");
	});
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
			writeFileSync(process.env.OMP_BASH_CLASSIFIER_TEST_LOCKFILE as string, raw);
			const ctx = makeCtx({ sessionId: `quiet-malformed-${raw.length}`, hasUI: true });
			await fire("tool_call", makeEvent("git status"), ctx);
			expect(notifyCalls(ctx)).toHaveLength(0);
		}
	});

	test("enabled omitted or falsy IS a disable signal, matching the host", async () => {
		// The loader does `if (runtimeState && !runtimeState.enabled) continue`
		// with no default, so a hand-edited entry missing the key is disabled as
		// far as the host is concerned. Requiring === false was stricter than
		// the thing this notice reports on.
		for (const [label, entry] of [
			["omitted", { version: "0.2.0" }],
			["zero", { version: "0.2.0", enabled: 0 }],
			["null", { version: "0.2.0", enabled: null }],
		] as const) {
			writeLockfile({ plugins: { "omp-bash-classifier": entry } });
			const ctx = makeCtx({ sessionId: `host-parity-${label}`, hasUI: true });
			await fire("tool_call", makeEvent("git status"), ctx);
			expect(notifyCalls(ctx)).toHaveLength(1);
		}
	});
});

describe("a project-scope disable is not silence", () => {
	test("a project lockfile is read, and the notice names it", async () => {
		// MarketplaceManager picks targetScope "project" for a project-only
		// install and writes <projectRoot>/.omp/plugins/omp-plugins.lock.json,
		// which getPluginsLockfile() never returns. Reading only the user scope
		// meant that user got silence.
		const fs = await import("node:fs");
		const os = await import("node:os");
		const path = await import("node:path");
		const root = fs.mkdtempSync(path.join(os.tmpdir(), "omp-proj-"));
		const lock = path.join(root, ".omp", "plugins", "omp-plugins.lock.json");
		fs.mkdirSync(path.dirname(lock), { recursive: true });
		fs.writeFileSync(lock, JSON.stringify(DISABLED));

		const ctx = makeCtx({ sessionId: "project-scope", hasUI: true, cwd: root });
		await fire("tool_call", makeEvent("git status"), ctx);
		expect(notifyCalls(ctx)).toHaveLength(1);
		expect(notifyCalls(ctx)[0][0]).toContain(lock);

		fs.rmSync(root, { recursive: true, force: true });
	});

	test("no project anchor means the user scope answers", async () => {
		writeLockfile(DISABLED);
		const ctx = makeCtx({ sessionId: "user-scope", hasUI: true, cwd: "/" });
		await fire("tool_call", makeEvent("git status"), ctx);
		expect(notifyCalls(ctx)).toHaveLength(1);
		expect(notifyCalls(ctx)[0][0]).toContain(process.env.OMP_BASH_CLASSIFIER_TEST_LOCKFILE as string);
	});
});

describe("the notice defers to the plugin's own kill switch", () => {
	test("still speaks up when classification is off, because gating continues", async () => {
		writeLockfile(DISABLED);
		writeConfigFile({ enabled: false });
		const ctx = makeCtx({ sessionId: "killswitch-1", hasUI: true });
		await fire("tool_call", makeEvent("git status"), ctx);
		// enabled:false turns off model classification only. Critical patterns,
		// env checks and the length bound keep running, so "disabled but still
		// gating" is reachable in this order too and needs the same explanation.
		expect(notifyCalls(ctx)).toHaveLength(1);
		expect(notifyCalls(ctx)[0][0]).toContain("Classification is already off");
		expect(notifyCalls(ctx)[0][0]).not.toContain("/classifier enabled false");
	});

	test("still warns while the classifier is running", async () => {
		writeLockfile(DISABLED);
		writeConfigFile({ enabled: true });
		const ctx = makeCtx({ sessionId: "killswitch-2", hasUI: true });
		await fire("tool_call", makeEvent("git status"), ctx);
		expect(notifyCalls(ctx)).toHaveLength(1);
		expect(notifyCalls(ctx)[0][0]).toContain("/classifier enabled false");
	});
});

describe("once per session means once, across switches", () => {
	test("switching away and back does not re-warn", async () => {
		writeLockfile(DISABLED);
		const session = "switch-stable";
		const first = makeCtx({ sessionId: session, hasUI: true });
		await fire("tool_call", makeEvent("git status"), first);
		expect(notifyCalls(first)).toHaveLength(1);

		// The outgoing session rides session_before_switch; clearing the warned
		// flag there is what used to re-arm the toast on every bounce.
		await fire("session_before_switch", {}, makeCtx({ sessionId: session }));
		await fire("session_switch", {}, makeCtx({ sessionId: session }));

		const back = makeCtx({ sessionId: session, hasUI: true });
		await fire("tool_call", makeEvent("ls -la"), back);
		expect(notifyCalls(back)).toHaveLength(0);
	});

	test("shutdown ends the session, so a later one warns again", async () => {
		writeLockfile(DISABLED);
		const session = "switch-shutdown";
		const first = makeCtx({ sessionId: session, hasUI: true });
		await fire("tool_call", makeEvent("git status"), first);
		expect(notifyCalls(first)).toHaveLength(1);

		await fire("session_shutdown", {}, makeCtx({ sessionId: session }));

		const reborn = makeCtx({ sessionId: session, hasUI: true });
		await fire("tool_call", makeEvent("ls -la"), reborn);
		expect(notifyCalls(reborn)).toHaveLength(1);
	});
});

describe("the mtime cache does not hide a lockfile change", () => {
	test("flipping the lockfile mid-session is picked up", async () => {
		writeLockfile(ENABLED);
		const before = makeCtx({ sessionId: "mtime-1", hasUI: true });
		await fire("tool_call", makeEvent("git status"), before);
		expect(notifyCalls(before)).toHaveLength(0);

		// Distinct mtime: writeLockfile rewrites the file, and the cache keys on
		// stat().mtimeMs rather than on having read it once.
		const { utimesSync } = await import("node:fs");
		writeLockfile(DISABLED);
		const later = new Date(Date.now() + 2000);
		utimesSync(process.env.OMP_BASH_CLASSIFIER_TEST_LOCKFILE as string, later, later);

		const after = makeCtx({ sessionId: "mtime-2", hasUI: true });
		await fire("tool_call", makeEvent("git status"), after);
		expect(notifyCalls(after)).toHaveLength(1);
	});
});
