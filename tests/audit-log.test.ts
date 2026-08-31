/**
 * Decision audit log (issue #33): one JSONL line per gate decision, written
 * fire-and-forget so a broken log never touches the gate, plus the
 * buildStatusReport tail summary behind `/classifier status`.
 *
 * Each test points OMP_CLASSIFIER_CONFIG at a fresh temp dir, so
 * decisions.jsonl resolves to dirname(override)/decisions.jsonl and can be
 * asserted byte-for-byte. Unique commands + fresh sessions per test, matching
 * the module-level cache conventions in classifier.test.ts.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
	fire,
	ALLOW_ONCE,
	DENY,
	loadPlugin,
	loggerWarnings,
	makeCtx,
	makeEvent,
	makeSettings,
	refusalOf,
	resultText,
	setClassifierReply,
	useTempConfigFile,
} from "./fixtures";
import { buildStatusReport, type DecisionRecord } from "../index";

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
	dir = fs.mkdtempSync(path.join(os.tmpdir(), "omp-audit-"));
	process.env.OMP_CLASSIFIER_CONFIG = path.join(dir, "omp-classifier.json");
	await loadPlugin(makeSettings([]));
	setClassifierReply("SAFE");
});

afterEach(() => {
	// Restore the shared suite config path so later test files never see this
	// dir, then remove it.
	process.env.OMP_CLASSIFIER_CONFIG = useTempConfigFile();
	fs.rmSync(dir, { recursive: true, force: true });
});

describe("decision audit log", () => {
	test("cap block writes one line with layer cap and the right tool", async () => {
		seq += 1;
		const bashResult = resultText(
			await fire("tool_call", makeEvent(`echo ${"x".repeat(9000)}`), makeCtx({ sessionId: `audit-${seq}` })),
		);
		expect(refusalOf(bashResult).layer).toBe("cap");
		let lines = readDecisions();
		expect(lines).toHaveLength(1);
		expect(lines[0]).toMatchObject({ tool: "bash", decision: "block", layer: "cap", verdict: null, cached: 0 });
		expect(lines[0].cmd.length).toBeLessThanOrEqual(121); // truncated(120) + ellipsis
		expect(lines[0].cmd).not.toContain("\n");
		expect(Number.isNaN(Date.parse(lines[0].ts))).toBe(false);

		seq += 1;
		// Spawn-bearing payload: the marker scan must route it to the cap.
		const evalResult = await fire(
			"tool_call",
			{ toolName: "eval", input: { code: `import subprocess\n${"x".repeat(9000)}`, language: "py" } },
			makeCtx({ sessionId: `audit-${seq}` }),
		);
		expect(refusalOf(evalResult).layer).toBe("cap");
		lines = readDecisions();
		expect(lines).toHaveLength(2);
		expect(lines[1]).toMatchObject({ tool: "eval", decision: "block", layer: "cap", verdict: null });
	});

	test("SAFE verdict logs allow, verdict SAFE, cached 0 then cached 1 on repeat", async () => {
		seq += 1;
		const command = `echo audit-safe-${seq}`;
		const ctx = makeCtx({ sessionId: "audit-safe" });
		expect(await fire("tool_call", makeEvent(command), ctx)).toBeUndefined();
		let lines = readDecisions();
		expect(lines).toHaveLength(1);
		expect(lines[0]).toMatchObject({
			tool: "bash",
			decision: "allow",
			layer: "verdict",
			verdict: "SAFE",
			cached: 0,
		});
		expect(lines[0].cmd).toBe(command);

		// Same session + command: the cached judgement answers, provenance flips.
		expect(await fire("tool_call", makeEvent(command), ctx)).toBeUndefined();
		lines = readDecisions();
		expect(lines).toHaveLength(2);
		expect(lines[1]).toMatchObject({ decision: "allow", layer: "cached", verdict: "SAFE", cached: 1 });
	});

	test("unwritable log drops the line and warns once, never breaks the gate", async () => {
		// A FILE where decisions.jsonl's directory must be: mkdir and append
		// both fail on every decision.
		const blocker = path.join(dir, "not-a-dir");
		fs.writeFileSync(blocker, "occupied");
		process.env.OMP_CLASSIFIER_CONFIG = path.join(blocker, "omp-classifier.json");

		seq += 1;
		setClassifierReply("UNSAFE");
		const blocked = resultText(
			await fire("tool_call", makeEvent(`git branch -D audit-broken-${seq}`), makeCtx({ sessionId: `audit-${seq}` })),
		);
		expect(refusalOf(blocked).layer).toBe("headless"); // the gate still decided

		seq += 1;
		setClassifierReply("SAFE");
		expect(
			await fire("tool_call", makeEvent(`echo audit-broken-${seq}`), makeCtx({ sessionId: `audit-${seq}` })),
		).toBeUndefined(); // ...and still allows

		const warnings = loggerWarnings.filter(message => message.includes("decision audit log unwritable"));
		expect(warnings).toHaveLength(1); // warn once, not per decision
		expect(fs.existsSync(path.join(blocker, "decisions.jsonl"))).toBe(false);
	});

	test("buildStatusReport parses a fixture log: counts, last 10, torn line", () => {
		const fixture: DecisionRecord[] = [];
		for (let i = 0; i < 15; i += 1) {
			const block = i % 3 === 0;
			fixture.push({
				ts: new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString(),
				tool: "bash",
				decision: block ? "block" : "allow",
				layer: block ? "headless" : "verdict",
				why: block ? "classified unsafe: fixture" : "fixture",
				cmd: `cmd-${i}`,
				cwd: "/workspace",
				verdict: "SAFE",
				cached: 0,
				ms: i,
			});
		}
		// A torn final line (crash mid-append) must vanish, not throw.
		fs.writeFileSync(decisionsPath(), `${fixture.map(line => JSON.stringify(line)).join("\n")}\n{"ts":"tore`);
		const report = buildStatusReport();
		expect(report.decisions).toEqual({ scanned: 15, allow: 10, block: 5 });
		expect(report.last).toHaveLength(10);
		expect(report.last[0].cmd).toBe("cmd-5");
		expect(report.last[9].cmd).toBe("cmd-14");
		expect(report.config.enabled).toBe(true); // defaults: no config file here
		// The "audit-safe" session from the repeat test cached exactly one verdict.
		expect(report.cacheSizes["audit-safe"]).toBe(1);
	});

	test("dialog paths log the verdict line plus the dialog outcome; approval logs allow", async () => {
		seq += 1;
		setClassifierReply("UNSAFE");
		const deny = makeCtx({ sessionId: `audit-${seq}`, hasUI: true, selectResult: DENY });
		const blocked = resultText(await fire("tool_call", makeEvent(`git branch -D audit-ui-${seq}`), deny));
		expect(refusalOf(blocked).layer).toBe("dialog");
		let lines = readDecisions();
		expect(lines).toHaveLength(2);
		expect(lines[0]).toMatchObject({ decision: "block", layer: "verdict", verdict: "UNSAFE" });
		expect(lines[1]).toMatchObject({ decision: "block", layer: "dialog" });
		expect(lines[1].why.startsWith("follows verdict")).toBe(true);

		seq += 1;
		const approve = makeCtx({ sessionId: `audit-${seq}`, hasUI: true, selectResult: ALLOW_ONCE });
		expect(await fire("tool_call", makeEvent(`git branch -D audit-ui-${seq}`), approve)).toBeUndefined();
		lines = readDecisions();
		expect(lines).toHaveLength(4); // two per decision
		expect(lines[2]).toMatchObject({ decision: "block", layer: "verdict", verdict: "UNSAFE" });
		expect(lines[3]).toMatchObject({ decision: "allow", layer: "dialog", why: "approved by user" });
	});
	test("SAFE + flagged command logs the verdict line, then the outcome line", async () => {
		seq += 1;
		// Plain non-recursive rm: flagged by the moderate-risk scan, not by the
		// builtin critical list, so a SAFE reply still takes the dialog path.
		const blocked = resultText(
			await fire(
				"tool_call",
				makeEvent(`rm /tmp/audit-flag-${seq}`),
				makeCtx({ sessionId: `audit-${seq}` }),
			),
		);
		expect(blocked).toContain("flagged for approval");
		const lines = readDecisions();
		expect(lines).toHaveLength(2);
		expect(lines[0]).toMatchObject({ decision: "block", layer: "verdict", verdict: "SAFE", cached: 0 });
		expect(lines[0].why).toContain("flags: rm");
		expect(lines[1]).toMatchObject({ decision: "block", layer: "headless" });
		expect(lines[1].why.startsWith("follows verdict")).toBe(true);
	});
});
