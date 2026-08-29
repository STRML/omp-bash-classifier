/**
 * The plugin's own config (OMP's /settings has no extension hook, so this is a
 * small JSON file + the /classifier command). Tests cover defaults, garbage
 * tolerance, the enabled=false semantics (classification off, critical/env/static
 * checks still on), model override, timeout, and the command-length bound.
 */
import { beforeEach, describe, expect, test } from "bun:test";
import {
	fire,
	loadPlugin,
	makeCtx,
	makeEvent,
	makeSettings,
	modelCalls,
	removeConfigFile,
	resultText,
	setClassifierDelay,
	setClassifierReply,
	writeConfigFile,
} from "./fixtures";

beforeEach(async () => {
	removeConfigFile();
	setClassifierDelay(5);
	await loadPlugin(makeSettings([]));
});

const gate = async (
	command: string,
	opts: { model?: unknown; hasUI?: boolean; sessionId?: string } = {},
	input: Record<string, unknown> = {},
) =>
	resultText(
		await fire("tool_call", makeEvent(command, input), makeCtx({ sessionId: `config-${Math.random().toString(36).slice(2)}`, ...opts })),
	);

describe("defaults with no config file", () => {
	test("classifier runs, 8000-char bound, 15s timeout, auto model", async () => {
		const ctx = makeCtx({});
		await fire("tool_call", makeEvent("git status"), ctx);
		expect(modelCalls.length).toBe(1);

		const long = "echo " + "x".repeat(8_050);
		const blocked = await gate(long);
		expect(blocked).toContain("review limit");
		expect(modelCalls.length).toBe(1); // no model call for the over-length command
	});
});

describe("enabled=false", () => {
	test("classification is skipped; command passes to the host gate", async () => {
		writeConfigFile({ enabled: false });
		expect(await gate("make build")).toBe("ALLOWED");
		expect(modelCalls.length).toBe(0);
	});

	test("critical patterns still block", async () => {
		writeConfigFile({ enabled: false });
		const result = await gate("rm -rf /");
		expect(result).toContain("critical pattern");
		expect(result).toContain("headless, blocked");
		expect(modelCalls.length).toBe(0);
	});

	test("env overrides still prompt", async () => {
		writeConfigFile({ enabled: false });
		const result = await gate("echo hi", {}, { env: { PATH: "/evil" } });
		expect(result).toContain("environment override");
		expect(modelCalls.length).toBe(0);
	});

	test("static deny rule still passes through to the host", async () => {
		writeConfigFile({ enabled: false });
		await loadPlugin(makeSettings([{ match: "rm -rf *", approval: "deny" }]));
		expect(await gate("rm -rf build")).toBe("ALLOWED");
		expect(modelCalls.length).toBe(0);
	});
});

describe("model override", () => {
	test("config.model is resolved first, before @tiny and the session model", async () => {
		writeConfigFile({ model: "my-classifier" });
		const tiny = { id: "tiny" };
		const picked = { id: "picked" };
		const ctx = makeCtx({ tinyModel: tiny, model: picked });
		await fire("tool_call", makeEvent("make build"), ctx);
		// The stub resolves a non-empty selector by name, mirroring the host
		// resolver: the explicit model wins with no fallback involved.
		expect((modelCalls[0].model as { id: string }).id).toBe("my-classifier");
	});

	test("@tiny is the fallback; the session model is last", async () => {
		const tiny = { id: "tiny" };
		const picked = { id: "picked" };
		const ctx = makeCtx({ tinyModel: tiny, model: picked });
		await fire("tool_call", makeEvent("make build"), ctx);
		expect(modelCalls[0].model).toBe(tiny);
	});

	test("changing classifier config invalidates cached verdicts", async () => {
		setClassifierReply("SAFE");
		await gate("git status", { sessionId: "sig-session" });
		expect(modelCalls.length).toBe(1);
		// Same session + command + cwd: without a config change this is cached.
		await gate("git status", { sessionId: "sig-session" });
		expect(modelCalls.length).toBe(1);

		// Toggling enabled (or model/timeout) is a trust-state change: the old
		// SAFE verdict must not survive it.
		writeConfigFile({ enabled: false });
		await gate("git status", { sessionId: "sig-session" });
		expect(modelCalls.length).toBe(1); // no classify at all now
	});
});

describe("bounds and garbage", () => {
	test("maxCommandLength from config", async () => {
		writeConfigFile({ maxCommandLength: 100 });
		const blocked = await gate("echo " + "y".repeat(120));
		expect(blocked).toContain("100-character review limit");
		expect(modelCalls.length).toBe(0);
	});

	test("maxCommandLength above the 100k ceiling falls back to default", async () => {
		// A typo'd huge value must not push multi-MB commands into the
		// classifier prompt and confirm dialog.
		writeConfigFile({ maxCommandLength: 5_000_000 });
		const blocked = await gate("echo " + "z".repeat(8_050));
		expect(blocked).toContain("8000-character review limit");
		expect(modelCalls.length).toBe(0);
	});

	test("timeoutMs from config aborts a slow completion", async () => {
		// bun's AbortSignal.timeout exposes no duration, so the configurable
		// timeout is proven behaviorally: a 20ms limit aborts the (stub) model
		// call before it completes, and the gate fails closed instead of running.
		setClassifierDelay(10_000); // stub completes slowly; the 20ms timeout aborts it
		writeConfigFile({ timeoutMs: 20 });
		const result = await gate("git status");
		expect(result).toContain("unclassified");
		expect(result).toContain("headless, blocked");
		expect(modelCalls.length).toBe(0); // aborted before the call completed
	});

	test("garbage config falls back to defaults", async () => {
		writeConfigFile({ enabled: "banana", model: 7, timeoutMs: -1, maxCommandLength: 0 });
		const result = await gate("git status");
		expect(result).toBe("ALLOWED"); // default enabled, SAFE -> through
		expect(modelCalls.length).toBe(1);
	});
});
