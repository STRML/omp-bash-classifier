/**
 * Structured refusal payload (#28): every block reason is machine-readable
 * JSON with classifier/tool/layer/why/next/notThis. These tests pin the
 * payload contract on the block sites a harness sees directly: the length
 * caps (bash and eval) and the critical-pattern gate (which fires even when
 * classification is disabled).
 *
 * Every test runs in a FRESH session (the module-level cache is per-session).
 */
import { beforeEach, describe, expect, test } from "bun:test";
import {
	fire,
	loadPlugin,
	makeCtx,
	makeEvent,
	makeSettings,
	modelCalls,
	refusalOf,
	removeConfigFile,
	resultText,
	setClassifierReply,
	writeConfigFile,
} from "./fixtures";

let seq = 0;

beforeEach(async () => {
	removeConfigFile();
	await loadPlugin(makeSettings([]));
	setClassifierReply("SAFE");
});

const fresh = (opts: Parameters<typeof makeCtx>[0] = {}) => {
	seq += 1;
	return makeCtx({ sessionId: `refusal-${seq}`, ...opts });
};

const gate = async (command: string, ctxOptions: Parameters<typeof makeCtx>[0] = {}, input: Record<string, unknown> = {}) =>
	resultText(await fire("tool_call", makeEvent(command, input), fresh(ctxOptions)));

const gateEval = async (code: string, language = "py") =>
	resultText(await fire("tool_call", { toolName: "eval", input: { code, language } }, fresh()));

describe("refusal payload", () => {
	test("bash cap: layer cap, next names the commit -F remedy", async () => {
		const long = "echo " + "x".repeat(9_000);
		const payload = refusalOf(await gate(long));
		expect(payload.classifier).toBe("blocked");
		expect(payload.tool).toBe("bash");
		expect(payload.layer).toBe("cap");
		expect(payload.why).toContain("exceeds the 8000-character review limit");
		expect(payload.next.length).toBeGreaterThan(0);
		expect(payload.next).toContain("commit -F");
		expect(payload.notThis.length).toBeGreaterThan(0);
		expect(modelCalls.length).toBe(0); // blocked unseen, no model call
	});

	test("critical pattern fires with enabled=false and parses as a payload", async () => {
		writeConfigFile({ enabled: false });
		const payload = refusalOf(await gate("rm -rf /"));
		expect(payload.classifier).toBe("blocked");
		expect(payload.tool).toBe("bash");
		expect(payload.layer).toBe("headless");
		expect(payload.why).toContain("critical pattern");
		expect(payload.next.length).toBeGreaterThan(0);
		expect(modelCalls.length).toBe(0);
	});

	test("eval cap: layer cap, next moves the code into a file", async () => {
		const code = `import subprocess  # ${"x".repeat(9_000)}\nsubprocess.run(["ls"])`;
		const payload = refusalOf(await gateEval(code));
		expect(payload.classifier).toBe("blocked");
		expect(payload.tool).toBe("eval");
		expect(payload.layer).toBe("cap");
		expect(payload.why).toContain("exceeds the 8000-character review limit");
		expect(payload.next.length).toBeGreaterThan(0);
		expect(payload.next).toContain("file");
		expect(modelCalls.length).toBe(0);
	});
});
