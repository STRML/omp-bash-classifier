/**
 * Session grants and the /classifier dry-run preview (issue #32).
 *
 * Grants: a user's "Allow for session" answer records a per-session,
 * per-directory authorization that outranks model classification and the
 * refusal memory, but stays below critical patterns, env overrides, and host
 * static rules. Dry-run: /classifier dry-run <command> fires the real gate
 * once with all side effects off and reports the first decision it reaches.
 *
 * Each test points OMP_BASH_CLASSIFIER_CONFIG at a fresh temp dir, so
 * decisions.jsonl and the config file are per-test (same convention as
 * audit-log.test.ts). Fresh sessions per test — the plugin's stores are
 * module-level.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { buildStatusReport, normalizeGrantTarget, type DecisionRecord } from "../index";
import {
	ALLOW_ONCE,
	ALLOW_SESSION,
	DENY,
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
	selectCalls,
	setClassifierReply,
	writeConfigFile,
} from "./fixtures";

let dir = "";
let seq = 0;

const decisionsPath = (): string => path.join(dir, "decisions.jsonl");

const readDecisions = (): DecisionRecord[] =>
	fs
		.readFileSync(decisionsPath(), "utf8")
		.split("\n")
		.filter(line => line.trim() !== "")
		.map(line => JSON.parse(line) as DecisionRecord);

beforeEach(async () => {
	dir = fs.mkdtempSync(path.join(os.tmpdir(), "omp-grants-"));
	process.env.OMP_BASH_CLASSIFIER_CONFIG = path.join(dir, "omp-bash-classifier.json");
	await loadPlugin(makeSettings([]));
	setClassifierReply("UNSAFE | no");
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
});

const nextSession = (): string => `grants-${(seq += 1)}`;

/** Parse the JSON the dry-run command toasted. */
const dryRunReport = async (command: string, sessionId: string, cwd?: string): Promise<Record<string, unknown>> => {
	const ctx = makeCtx({ sessionId, cwd });
	await fireCommand("classifier", `dry-run ${command}`, ctx);
	const calls = notifyCalls(ctx);
	expect(calls.length).toBeGreaterThan(0);
	return JSON.parse(calls[calls.length - 1][0]) as Record<string, unknown>;
};

/** One UNSAFE dialog answered with `answer`, returning the gate result. */
const prompted = async (command: string, answer: string, sessionId: string) => {
	const ctx = makeCtx({ sessionId, hasUI: true, selectResult: answer });
	const result = await fire("tool_call", makeEvent(command), ctx);
	return { ctx, result };
};

describe("session grants", () => {
	test("Allow for session records a grant; the re-fire runs with no dialog and no model call", async () => {
		const sid = nextSession();
		const first = await prompted(`git branch -D feature-${sid}`, ALLOW_SESSION, sid);
		expect(resultText(first.result)).toBe("ALLOWED");
		expect(selectCalls(first.ctx)).toHaveLength(1);
		expect(modelCalls.length).toBe(1);

		// A fresh turn, same session. If the cached UNSAFE verdict answered, it
		// would re-dialog; if the grant answered, the command runs clean. The
		// audit line proves which layer decided.
		const secondCtx = makeCtx({ sessionId: sid, hasUI: true });
		const second = await fire("tool_call", makeEvent(`git branch -D feature-${sid}`), secondCtx);
		expect(second).toBeUndefined();
		expect(selectCalls(secondCtx)).toHaveLength(0);
		expect(modelCalls.length).toBe(1);
		const lines = readDecisions();
		expect(lines[lines.length - 1]).toMatchObject({ decision: "allow", layer: "granted", why: "session grant" });
	});

	test("a grant honors cwd: same command in another directory classifies again", async () => {
		const sid = nextSession();
		await prompted(`git branch -D feature-${sid}`, ALLOW_SESSION, sid);
		expect(modelCalls.length).toBe(1);

		const elsewhere = makeCtx({ sessionId: sid, hasUI: true, cwd: "/elsewhere" });
		const result = await fire("tool_call", makeEvent(`git branch -D feature-${sid}`), elsewhere);
		expect(refusalOf(result).layer).toBe("dialog");
		expect(selectCalls(elsewhere)).toHaveLength(1);
		expect(modelCalls.length).toBe(2);
	});

	test("a grant does not outrank a critical pattern", async () => {
		const sid = nextSession();
		await prompted("rm -rf x", ALLOW_SESSION, sid);

		const ctx = makeCtx({ sessionId: sid, hasUI: true });
		const result = await fire("tool_call", makeEvent("rm -rf /"), ctx);
		expect(refusalOf(result).layer).toBe("dialog");
		expect(selectCalls(ctx)[0][0]).toContain("critical pattern");
		expect(modelCalls.length).toBe(1); // the grant path never classified
	});

	test("Allow once does not grant: the same command prompts again", async () => {
		const sid = nextSession();
		const first = await prompted(`git branch -D feature-${sid}`, ALLOW_ONCE, sid);
		expect(resultText(first.result)).toBe("ALLOWED");

		const secondCtx = makeCtx({ sessionId: sid, hasUI: true });
		const second = await fire("tool_call", makeEvent(`git branch -D feature-${sid}`), secondCtx);
		expect(refusalOf(second).layer).toBe("dialog");
		expect(selectCalls(secondCtx)).toHaveLength(1);
	});

	test("a canceled dialog (undefined) denies, and the audit line says so", async () => {
		const sid = nextSession();
		const ctx = makeCtx({ sessionId: sid, hasUI: true }); // selectResult: undefined
		const result = await fire("tool_call", makeEvent(`git branch -D feature-${sid}`), ctx);
		expect(refusalOf(result).layer).toBe("dialog");
		const lines = readDecisions();
		expect(lines[lines.length - 1].why.startsWith("prompt canceled")).toBe(true);
	});

	test("explicit Deny keeps the old audit why", async () => {
		const sid = nextSession();
		await prompted(`git branch -D feature-${sid}`, DENY, sid);
		const lines = readDecisions();
		expect(lines[lines.length - 1]).toMatchObject({ decision: "block", layer: "dialog" });
		expect(lines[lines.length - 1].why.startsWith("follows verdict")).toBe(true);
	});

	test("a session grant lifts the refusal memory for its target", async () => {
		const sid = nextSession();
		// Refuse the action...
		await prompted("rm -rf x", DENY, sid);
		// ...then approve a REWORDED ask for the session: SAFE-despite-prior
		// raises the dialog, and the answer grants AND lifts.
		setClassifierReply("SAFE | routine");
		const approved = await prompted("rm -rf ./x", ALLOW_SESSION, sid);
		expect(resultText(approved.result)).toBe("ALLOWED");
		// A third spelling with the SAME flags hits the grant BEFORE the
		// classifier: allowed with no model call and no dialog, though a fresh
		// UNSAFE verdict is pending. ("rm -r x" without -f is a different key
		// now and gates again — see the regression test below.)
		setClassifierReply("UNSAFE | would block if asked");
		const thirdCtx = makeCtx({ sessionId: sid, hasUI: true });
		const third = await fire("tool_call", makeEvent("rm -r -f ./x"), thirdCtx);
		expect(third).toBeUndefined();
		expect(selectCalls(thirdCtx)).toHaveLength(0);
		expect(modelCalls.length).toBe(2);
	});

	test("changing the classifier config clears every grant", async () => {
		const sid = nextSession();
		await prompted(`git branch -D feature-${sid}`, ALLOW_SESSION, sid);

		writeConfigFile({ model: "changed-model" });
		const ctx = makeCtx({ sessionId: sid, hasUI: true });
		const result = await fire("tool_call", makeEvent(`git branch -D feature-${sid}`), ctx);
		expect(refusalOf(result).layer).toBe("dialog");
		expect(selectCalls(ctx)).toHaveLength(1);
	});

	test("a session boundary drops the session's grants", async () => {
		const sid = nextSession();
		await prompted(`git branch -D feature-${sid}`, ALLOW_SESSION, sid);

		await fire("session_start", {}, makeCtx({ sessionId: sid }));
		const ctx = makeCtx({ sessionId: sid, hasUI: true });
		const result = await fire("tool_call", makeEvent(`git branch -D feature-${sid}`), ctx);
		expect(refusalOf(result).layer).toBe("dialog");
		expect(selectCalls(ctx)).toHaveLength(1);
	});

	test("grant store caps at 50 per session and drops the oldest", async () => {
		const sid = nextSession();
		for (let i = 0; i <= 50; i += 1) {
			await prompted(`git branch -D grant-cap-${sid}-${i}`, ALLOW_SESSION, sid);
		}
		// The oldest grant (i=0) was evicted: its command gates again...
		const oldestCmd = `git branch -D grant-cap-${sid}-0`;
		const oldestCtx = makeCtx({ sessionId: sid, hasUI: true });
		const oldest = await fire("tool_call", makeEvent(oldestCmd), oldestCtx);
		expect(refusalOf(oldest).layer).toBe("dialog");
		// ...while a recent one (i=50) still runs ungated.
		const recentCmd = `git branch -D grant-cap-${sid}-50`;
		const recentCtx = makeCtx({ sessionId: sid, hasUI: true });
		const recent = await fire("tool_call", makeEvent(recentCmd), recentCtx);
		expect(recent).toBeUndefined();
		expect(selectCalls(recentCtx)).toHaveLength(0);
	});

	test("an eval payload granted from its own dialog holds on re-fire", async () => {
		const sid = nextSession();
		const code = `require("child_process").exec("ls")`;
		const ctx = makeCtx({ sessionId: sid, hasUI: true, selectResult: ALLOW_SESSION });
		await fire("tool_call", { toolName: "eval", input: { code, language: "js" } }, ctx);
		expect(selectCalls(ctx)).toHaveLength(1);
		expect(modelCalls.length).toBe(1);
	});
});

describe("/classifier dry-run", () => {
	test("over-cap command reports would block at the cap and writes no audit line", async () => {
		const sid = nextSession();
		const long = `echo ${"x".repeat(9000)}`;
		// One live decision first, so the log exists and its length is known.
		const live = await fire("tool_call", makeEvent(long), makeCtx({ sessionId: sid }));
		expect(refusalOf(live).layer).toBe("cap");
		expect(readDecisions()).toHaveLength(1);

		const report = await dryRunReport(long, sid);
		expect(report).toMatchObject({ would: "block", layer: "cap" });
		expect(readDecisions()).toHaveLength(1);
	});

	test("a rule-allowed command reports would allow at the rule layer", async () => {
		await loadPlugin(makeSettings([{ match: "git status", approval: "allow" }]));
		const report = await dryRunReport("git status", nextSession());
		expect(report).toMatchObject({ would: "allow", layer: "rule" });
		expect(modelCalls.length).toBe(0);
	});

	test("an undecided command reports would classify and skips the model call", async () => {
		setClassifierReply("SAFE");
		const sid = nextSession();
		const report = await dryRunReport(`git branch -D feature-${sid}`, sid);
		expect(report).toMatchObject({ would: "classify", layer: "classifier" });
		expect(modelCalls.length).toBe(0);
		// No cached verdict was fabricated by the probe: the session's cache
		// exists (the gate allocates it on entry) but holds zero entries.
		expect(buildStatusReport().cacheSizes[sid]).toBe(0);
	});

	test("a granted command reports would allow at the granted layer", async () => {
		const sid = nextSession();
		await prompted(`git branch -D feature-${sid}`, ALLOW_SESSION, sid);

		const report = await dryRunReport(`git branch -D feature-${sid}`, sid);
		expect(report).toMatchObject({ would: "allow", layer: "granted", why: "session grant" });
	});

	test("a cached verdict is followed without a model call, mutating nothing", async () => {
		setClassifierReply("SAFE");
		const sid = nextSession();
		const command = `echo cached-dry-${sid}`;
		await fire("tool_call", makeEvent(command), makeCtx({ sessionId: sid }));
		expect(modelCalls.length).toBe(1);
		expect(buildStatusReport().cacheSizes[sid]).toBe(1);
		const auditLines = readDecisions().length;

		const report = await dryRunReport(command, sid);
		expect(report).toMatchObject({ would: "allow", layer: "cached" });
		expect(modelCalls.length).toBe(1);
		expect(buildStatusReport().cacheSizes[sid]).toBe(1);
		expect(readDecisions()).toHaveLength(auditLines);
	});
});

describe("grant target strictness (gate fix)", () => {
	test("REGRESSION: a plain-push grant does not cover git push --force", async () => {
		const sid = nextSession();
		await prompted("git push origin main", ALLOW_SESSION, sid);
		expect(modelCalls.length).toBe(1);

		// The force variant is a different authorization key: it must gate
		// again (classify + dialog), never ride the plain-push grant.
		const ctx = makeCtx({ sessionId: sid, hasUI: true });
		const result = await fire("tool_call", makeEvent("git push --force origin main"), ctx);
		expect(refusalOf(result).layer).toBe("dialog");
		expect(selectCalls(ctx)).toHaveLength(1);
		expect(modelCalls.length).toBe(2);
	});

	test("a grant on 'pkill -f MyApp' honors the identical command", async () => {
		const sid = nextSession();
		const first = await prompted("pkill -f MyApp", ALLOW_SESSION, sid);
		expect(resultText(first.result)).toBe("ALLOWED");
		expect(selectCalls(first.ctx)[0][1]).toHaveLength(3); // grantable: three options

		const secondCtx = makeCtx({ sessionId: sid, hasUI: true });
		const second = await fire("tool_call", makeEvent("pkill -f MyApp"), secondCtx);
		expect(second).toBeUndefined();
		expect(selectCalls(secondCtx)).toHaveLength(0);
		expect(modelCalls.length).toBe(1);
	});

	test("flags are canonical: -rf covers -r -f but not a bare rm", async () => {
		const sid = nextSession();
		await prompted("rm -rf x", ALLOW_SESSION, sid);
		expect(modelCalls.length).toBe(1);

		// Combined-short vs split shorts: same key, honored without a model call.
		const splitCtx = makeCtx({ sessionId: sid, hasUI: true });
		const split = await fire("tool_call", makeEvent("rm -r -f x"), splitCtx);
		expect(split).toBeUndefined();
		expect(selectCalls(splitCtx)).toHaveLength(0);
		expect(modelCalls.length).toBe(1);

		// Dropping a flag changes the authorization: gates again.
		const bareCtx = makeCtx({ sessionId: sid, hasUI: true });
		const bare = await fire("tool_call", makeEvent("rm x"), bareCtx);
		expect(refusalOf(bare).layer).toBe("dialog");
		expect(selectCalls(bareCtx)).toHaveLength(1);
		expect(modelCalls.length).toBe(2);
	});

	test("a compound command is offered only Allow once / Deny", async () => {
		const sid = nextSession();
		const ctx = makeCtx({ sessionId: sid, hasUI: true });
		const result = await fire("tool_call", makeEvent("git status && git push --force"), ctx);
		expect(refusalOf(result).layer).toBe("dialog");
		expect(selectCalls(ctx)[0][1].map(option => option.label)).toEqual(["Allow once", "Deny"]);
	});

	test("normalizeGrantTarget unit table", () => {
		expect(normalizeGrantTarget("git push origin main")).toBe("git push origin");
		expect(normalizeGrantTarget("git push --force origin main")).toBe("git push --force origin");
		expect(normalizeGrantTarget("GIT   PUSH --Force ORIGIN main")).toBe("git push --force origin");
		expect(normalizeGrantTarget("pkill -f MyApp")).toBe("pkill -f myapp");
		expect(normalizeGrantTarget("rm -rf x")).toBe(normalizeGrantTarget("rm -r -f x"));
		expect(normalizeGrantTarget("rm x")).not.toBe(normalizeGrantTarget("rm -rf x"));
		expect(normalizeGrantTarget("cd /tmp && rm -rf x")).toBe(normalizeGrantTarget("rm -rf x"));
		expect(normalizeGrantTarget("rm -rf ./x")).toBe(normalizeGrantTarget("rm -rf x"));
		expect(normalizeGrantTarget("echo hello")).toBe("echo hello");
		expect(normalizeGrantTarget("git status")).toBe("git status");
		expect(normalizeGrantTarget("")).toBe("");
	});
});
