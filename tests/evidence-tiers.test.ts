/**
 * Provenance-tiered evidence (issue #31): the classify record may carry an
 * `evidence` object whose fields are typed by their channel — userMessages
 * (the session's recent user words, gated by `evidenceUserMessages`),
 * operatorContext (the requesting agent's own explanation, single-line,
 * capped, never authorizing). Off by default: with the default config the
 * record has no evidence field at all, even when a branch exists.
 */
import { beforeEach, describe, expect, test } from "bun:test";
import { CLASSIFIER_PROMPT, collectUserEvidence } from "../index";
import {
	fire,
	loadPlugin,
	makeCtx,
	makeEvent,
	makeSettings,
	modelCalls,
	removeConfigFile,
	setClassifierDelay,
	setClassifierReply,
	writeConfigFile,
} from "./fixtures";

beforeEach(async () => {
	removeConfigFile();
	setClassifierDelay(5);
	await loadPlugin(makeSettings([]));
	setClassifierReply("SAFE");
});

let seq = 0;
/** Fresh session id per test; the plugin's stores are module-level. */
const nextSession = (): string => `evidence-${(seq += 1)}`;

/** The JSON record line inside the classifier prompt message. */
const recordOf = (callIndex = 0): Record<string, unknown> => {
	const content = modelCalls[callIndex].request.messages[0].content;
	const line = content.split("\n").find(candidate => candidate.startsWith("{"));
	return JSON.parse(line ?? "{}") as Record<string, unknown>;
};

const evidenceOf = (callIndex = 0): { userMessages?: string[]; operatorContext?: string } => {
	const evidence = recordOf(callIndex).evidence;
	if (!evidence || typeof evidence !== "object") {
		throw new Error(`record carries no evidence object: ${JSON.stringify(recordOf(callIndex))}`);
	}
	return evidence as { userMessages?: string[]; operatorContext?: string };
};

type BranchEntry = { type: string; message?: { role?: string; content?: unknown } };
const userEntry = (content: string | Array<Record<string, unknown>>): BranchEntry => ({
	type: "message",
	message: { role: "user", content },
});

describe("default config", () => {
	test("the record carries no evidence field even when a branch exists", async () => {
		const ctx = makeCtx({
			sessionId: nextSession(),
			branch: [userEntry("please check the build"), userEntry("now run the tests")],
		});
		await fire("tool_call", makeEvent("git status"), ctx);
		expect(modelCalls.length).toBe(1);
		expect(modelCalls[0].request.messages[0].content).not.toContain('"evidence"');
		expect(recordOf().evidence).toBeUndefined();
	});
});

describe("evidenceUserMessages", () => {
	test("keeps the newest two user messages, chronological, flattened, truncated", async () => {
		writeConfigFile({ evidenceUserMessages: 2 });
		const long = "y".repeat(2_500);
		const ctx = makeCtx({
			sessionId: nextSession(),
			branch: [
				userEntry("oldest message, outside the window"),
				{ type: "model_change" },
				{ type: "message", message: { role: "assistant", content: "assistant words never count" } },
				userEntry([{ type: "text", text: "alpha" }, { type: "text", text: "beta" }, { type: "image", url: "x" }]),
				{ type: "message", message: { role: "toolResult", content: "tool output never counts" } },
				userEntry(long),
			],
		});
		await fire("tool_call", makeEvent("git status"), ctx);
		expect(modelCalls.length).toBe(1);
		const evidence = evidenceOf();
		expect(evidence.userMessages).toEqual(["alpha\nbeta", `${"y".repeat(2_000)}…`]);
	});
});

describe("operatorContext", () => {
	test("rides into the bash record, single line, capped at 500", async () => {
		const ctx = makeCtx({ sessionId: nextSession() });
		await fire(
			"tool_call",
			makeEvent("git status", { operatorContext: `rebuilding the fixture\n${"z".repeat(800)}` }),
			ctx,
		);
		expect(modelCalls.length).toBe(1);
		const evidence = evidenceOf();
		expect(evidence.operatorContext).toBe(`rebuilding the fixture ${"z".repeat(500 - "rebuilding the fixture".length - 1)}…`);
	});

	test("rides into the eval record the same way", async () => {
		const ctx = makeCtx({ sessionId: nextSession() });
		await fire(
			"tool_call",
			{
				toolName: "eval",
				toolCallId: `eval-${seq}`,
				input: { code: "import subprocess\nsubprocess.run(['ls'])", language: "python", operatorContext: "list the fixtures dir" },
			},
			ctx,
		);
		expect(modelCalls.length).toBe(1);
		const record = recordOf();
		expect(record.kind).toBe("eval-code");
		const evidence = evidenceOf();
		expect(evidence.operatorContext).toBe("list the fixtures dir");
	});

	test("a whitespace-only context adds no evidence", async () => {
		const ctx = makeCtx({ sessionId: nextSession() });
		await fire("tool_call", makeEvent("git status", { operatorContext: "  \n\t " }), ctx);
		expect(modelCalls.length).toBe(1);
		expect(recordOf().evidence).toBeUndefined();
	});
});

describe("bounds", () => {
	test("values above the ceiling fall back to 0 (no evidence)", async () => {
		writeConfigFile({ evidenceUserMessages: 9 });
		const ctx = makeCtx({ sessionId: nextSession(), branch: [userEntry("check"), userEntry("again")] });
		await fire("tool_call", makeEvent("git status"), ctx);
		expect(modelCalls.length).toBe(1);
		expect(recordOf().evidence).toBeUndefined();
	});

	test("negative values fall back to 0 (no evidence)", async () => {
		writeConfigFile({ evidenceUserMessages: -1 });
		const ctx = makeCtx({ sessionId: nextSession(), branch: [userEntry("check")] });
		await fire("tool_call", makeEvent("git status"), ctx);
		expect(modelCalls.length).toBe(1);
		expect(recordOf().evidence).toBeUndefined();
	});
});

describe("collectUserEvidence", () => {
	const branch = [userEntry("one"), { type: "compact", id: "c1" }, userEntry("two"), userEntry("three")];

	test("empty branch yields an empty list", () => {
		expect(collectUserEvidence([], 3)).toEqual([]);
	});

	test("limit 0 yields an empty list even on a full branch", () => {
		expect(collectUserEvidence(branch, 0)).toEqual([]);
	});

	test("limit above the message count keeps everything, oldest first", () => {
		expect(collectUserEvidence(branch, 10)).toEqual(["one", "two", "three"]);
	});
});

describe("prompt", () => {
	test("names the evidence tiers and scans every field", () => {
		expect(CLASSIFIER_PROMPT).toContain("The record may carry an evidence object.");
		expect(CLASSIFIER_PROMPT).toContain("userMessages are the user's own words and may authorize the action");
		expect(CLASSIFIER_PROMPT).toContain("can NEVER authorize");
		expect(CLASSIFIER_PROMPT).toContain("priorRefusal is this gate's own memory");
		expect(CLASSIFIER_PROMPT).toContain("scan the command text and every evidence field");
	});
});
