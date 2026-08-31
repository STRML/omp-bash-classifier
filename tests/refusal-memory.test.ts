/**
 * Refusal memory across rewording (issue #30): a command this session refused
 * (UNSAFE / PARSE_ERROR / human denial / critical / cap) is remembered by
 * normalized target, injected into the next classify record as priorRefusal,
 * and a SAFE that lands anyway on a refused target still prompts. A user
 * approval lifts the memory; the store holds 20 targets per session, oldest
 * dropped.
 *
 * Unique sessions per test — the module-level refusal store outlives a test.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { normalizeRefusalTarget } from "../index";
import type { DecisionRecord } from "../index";
import {
	confirmCalls,
	fire,
	loadPlugin,
	makeCtx,
	makeEvent,
	makeSettings,
	modelCalls,
	setClassifierReply,
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
	dir = fs.mkdtempSync(path.join(os.tmpdir(), "omp-refusal-"));
	process.env.OMP_BASH_CLASSIFIER_CONFIG = path.join(dir, "omp-bash-classifier.json");
	await loadPlugin(makeSettings([]));
	setClassifierReply("SAFE");
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
});

/** Fresh session id per test; the plugin's stores are module-level. */
const nextSession = (): string => `refusal-memory-${(seq += 1)}`;

/** The JSON record line inside the classifier prompt message. */
const recordOf = (callIndex: number): Record<string, unknown> => {
	const content = modelCalls[callIndex].request.messages[0].content;
	const line = content.split("\n").find(candidate => candidate.startsWith("{"));
	return JSON.parse(line ?? "{}") as Record<string, unknown>;
};

describe("normalizeRefusalTarget", () => {
	test("case, whitespace, flags, cd-prefix, git verbs", () => {
		expect(normalizeRefusalTarget("rm -rf x")).toBe("rm x");
		expect(normalizeRefusalTarget("rm -rf ./x")).toBe("rm x");
		expect(normalizeRefusalTarget("RM   -RF\t./X")).toBe("rm x");
		expect(normalizeRefusalTarget("cd /tmp && rm -rf x")).toBe("rm x");
		expect(normalizeRefusalTarget("rm -f x")).toBe("rm x");
		expect(normalizeRefusalTarget("git push --force origin main")).toBe("git push origin");
		expect(normalizeRefusalTarget("git push origin")).toBe("git push origin");
		expect(normalizeRefusalTarget("echo hello")).toBe("echo hello");
		expect(normalizeRefusalTarget("ls -la")).toBe("ls");
		expect(normalizeRefusalTarget("")).toBe("");
	});

	test("rewordings of one action share a target; unlike actions differ", () => {
		expect(normalizeRefusalTarget("rm -rf x")).toBe(normalizeRefusalTarget("rm -f ./x"));
		expect(normalizeRefusalTarget("rm -rf x")).not.toBe(normalizeRefusalTarget("git reset --hard"));
	});
});

describe("refusal memory", () => {
	test("reworded command carries priorRefusal into the classify record", async () => {
		const sid = nextSession();
		setClassifierReply("UNSAFE | deletes files");
		await fire("tool_call", makeEvent("rm -rf x"), makeCtx({ sessionId: sid }));
		expect(modelCalls.length).toBe(1);
		setClassifierReply("UNSAFE | still");
		await fire("tool_call", makeEvent("rm -rf ./x"), makeCtx({ sessionId: sid }));
		expect(modelCalls.length).toBe(2);
		const record = recordOf(1);
		const prior = record.priorRefusal as { target: string; why: string; when: string };
		expect(prior.target).toBe("rm x");
		expect(prior.why).toBe("deletes files");
		expect(new Date(prior.when).getTime()).toBeGreaterThan(0);
		// The first, unrefused classification carries no such field.
		expect(recordOf(0).priorRefusal).toBeUndefined();
	});

	test("a SAFE that lands despite a prior refusal still prompts", async () => {
		const sid = nextSession();
		const ctx = makeCtx({ sessionId: sid, hasUI: true, confirmResult: false });
		setClassifierReply("UNSAFE | not this session");
		await fire("tool_call", makeEvent("echo bye"), ctx);
		// echo is not a moderate-risk token, so without the refusal memory a
		// SAFE here would auto-run; the dialog proves the refusal decided.
		setClassifierReply("SAFE | harmless rewording");
		const result = await fire("tool_call", makeEvent("echo bye again"), ctx);
		expect(confirmCalls(ctx).length).toBe(2);
		const payload = JSON.parse(
			(result as { block: true; reason: string }).reason,
		) as { layer: string };
		expect(payload.layer).toBe("dialog");
		expect(readDecisions().some(line => line.why.startsWith("despite prior refusal"))).toBe(true);
	});

	test("user approval lifts the refusal for the target", async () => {
		const sid = nextSession();
		setClassifierReply("UNSAFE | deletes files");
		await fire("tool_call", makeEvent("rm -rf x"), makeCtx({ sessionId: sid, hasUI: true, confirmResult: false }));
		setClassifierReply("SAFE | routine");
		const approved = await fire(
			"tool_call",
			makeEvent("rm -rf ./x"),
			makeCtx({ sessionId: sid, hasUI: true, confirmResult: true }),
		);
		expect(approved).toBeUndefined();
		// A third rewording of the same action classifies clean: no memory.
		await fire("tool_call", makeEvent("rm -r x"), makeCtx({ sessionId: sid, hasUI: true, confirmResult: true }));
		expect(modelCalls.length).toBe(3);
		expect(recordOf(2).priorRefusal).toBeUndefined();
	});

	test("store caps at 20 per session and drops the oldest", async () => {
		const sid = nextSession();
		setClassifierReply("UNSAFE | no");
		for (let i = 1; i <= 21; i++) {
			await fire(
				"tool_call",
				makeEvent(`rm -rf f${String(i).padStart(2, "0")}`),
				makeCtx({ sessionId: sid }),
			);
		}
		setClassifierReply("UNSAFE | no");
		// Oldest target (rm f01) was evicted: its rewording classifies bare.
		await fire("tool_call", makeEvent("rm -f f01"), makeCtx({ sessionId: sid }));
		expect(recordOf(21).priorRefusal).toBeUndefined();
		// Newest target (rm f21) is still remembered.
		await fire("tool_call", makeEvent("rm -f f21"), makeCtx({ sessionId: sid }));
		const prior = recordOf(22).priorRefusal as { target: string };
		expect(prior.target).toBe("rm f21");
	});
});
