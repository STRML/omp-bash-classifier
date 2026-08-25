/**
 * Static-gate precedence through the tool_call interceptor. The design goal:
 * critical patterns outrank every bash.patterns rule in every approval mode
 * (native in `yolo` drops the critical `override`, so the plugin must be the
 * check), deny stays with the host, narrow allow is honored without a model
 * call, blanket allow gets classified, and env overrides prompt.
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
	confirmCalls,
	setClassifierReply,
} from "./fixtures";

beforeEach(async () => {
	await loadPlugin(makeSettings([]));
	setClassifierReply("SAFE");
});

let seq = 0;

const gate = async (
	command: string,
	input: Record<string, unknown> = {},
	ctxOptions: Parameters<typeof makeCtx>[0] = {},
) => {
	seq += 1;
	return resultText(
		await fire("tool_call", makeEvent(command, input), makeCtx({ sessionId: `sg-${seq}`, ...ctxOptions })),
	);
};

describe("host-owned decisions pass through untouched", () => {
	test("deny rule is left to the host", async () => {
		await loadPlugin(makeSettings([{ match: "rm -rf *", approval: "deny" }]));
		expect(await gate("rm -rf build")).toBe("ALLOWED");
		expect(modelCalls.length).toBe(0);
	});

	test("deny policy is left to the host", async () => {
		await loadPlugin(makeSettings([], "deny"));
		expect(await gate("echo hi")).toBe("ALLOWED");
	});

	test("prompt rule is left to the host's own prompt", async () => {
		await loadPlugin(makeSettings([{ match: "dd *", approval: "prompt" }]));
		expect(await gate("dd if=x of=y bs=1M count=1")).toBe("ALLOWED");
		expect(modelCalls.length).toBe(0);
	});

	test("non-bash tool calls are untouched", async () => {
		expect(resultText(await fire("tool_call", { toolName: "write", input: {} }, makeCtx()))).toBe("ALLOWED");
	});

	test("empty command passes through", async () => {
		expect(await gate("  ")).toBe("ALLOWED");
	});
});

describe("critical patterns outrank everything", () => {
	test("critical beats a matching allow rule, with no model call", async () => {
		await loadPlugin(makeSettings([{ match: "rm -rf *", approval: "allow" }]));
		const result = await gate("rm -rf /");
		expect(result).toContain("critical pattern");
		expect(result).toContain("headless, blocked");
		expect(modelCalls.length).toBe(0);
	});

	test("critical beats a matching prompt rule", async () => {
		await loadPlugin(makeSettings([{ match: "rm -rf *", approval: "prompt" }]));
		const result = await gate("rm -rf /");
		expect(result).toContain("critical pattern");
		expect(modelCalls.length).toBe(0);
	});

	test("critical in a compound still blocks", async () => {
		const result = await gate("cd /tmp && mkfs.ext4 /dev/fake-disk");
		expect(result).toContain("critical pattern");
		expect(modelCalls.length).toBe(0);
	});

	test("critical with a UI raises a real confirm, not a silent run", async () => {
		const ctx = makeCtx({ hasUI: true, confirmResult: true });
		const result = resultText(await fire("tool_call", makeEvent("mkfs.ext4 /dev/sdb1"), ctx));
		expect(result).toBe("ALLOWED"); // user approved
		expect(confirmCalls(ctx)[0][0]).toContain("critical pattern");
		expect(modelCalls.length).toBe(0);
	});
});

describe("allow rules", () => {
	test("narrow allow is honored without a model call", async () => {
		await loadPlugin(makeSettings([{ match: "git status *", approval: "allow" }]));
		expect(await gate("git status --short")).toBe("ALLOWED");
		expect(modelCalls.length).toBe(0);
	});

	test("narrow allow is honored even for a destructive-looking command", async () => {
		await loadPlugin(makeSettings([{ match: "git status *", approval: "allow" }]));
		expect(await gate("git status thing")).toBe("ALLOWED");
		expect(modelCalls.length).toBe(0);
	});

	test("blanket allow '*' is classified, not auto-approved", async () => {
		await loadPlugin(makeSettings([{ match: "*", approval: "allow" }]));
		expect(await gate("git status --short")).toBe("ALLOWED"); // classifier says SAFE
		expect(modelCalls.length).toBe(1);
	});

	test("'**' and '* *' are blanket too", async () => {
		for (const pattern of ["**", "* *"]) {
			await loadPlugin(makeSettings([{ match: pattern, approval: "allow" }]));
			expect(await gate("make build")).toBe("ALLOWED");
			expect(modelCalls.length).toBe(1);
		}
	});

	test("allow with shell control is not honored: classified instead", async () => {
		await loadPlugin(makeSettings([{ match: "git status *", approval: "allow" }]));
		expect(await gate("git status; echo hi")).toBe("ALLOWED"); // SAFE -> through
		expect(modelCalls.length).toBe(1); // the compound got classified
	});

	test("quoted shell control inside a narrow allow stays honored (native semantics)", async () => {
		await loadPlugin(makeSettings([{ match: "echo *", approval: "allow" }]));
		expect(await gate("echo 'a;b'")).toBe("ALLOWED");
		expect(modelCalls.length).toBe(0);
	});
});

describe("env overrides prompt before any rule exemption", () => {
	test("env override beats a matching narrow allow", async () => {
		await loadPlugin(makeSettings([{ match: "git status *", approval: "allow" }]));
		const result = await gate("git status --short", { env: { PATH: "/evil" } });
		expect(result).toContain("environment override");
		expect(modelCalls.length).toBe(0);
	});

	test("env values are never sent to the classifier", async () => {
		await loadPlugin(makeSettings([{ match: "*", approval: "allow" }]));
		const result = await gate("echo hi", { env: { SECRET: "s3cr3t" } });
		expect(result).toContain("environment override");
		expect(modelCalls.length).toBe(0);
	});
});

describe("command bounds", () => {
	test("commands over 2000 chars are blocked without a model call", async () => {
		const long = "echo " + "x".repeat(2100);
		const result = await gate(long);
		expect(result).toContain("review limit");
		expect(modelCalls.length).toBe(0);
	});

	test("internal-URL cwd is blocked, not misclassified", async () => {
		const result = await gate("ls", { cwd: "local:/tmp/project" });
		expect(result).toContain("cannot resolve an internal-URL cwd");
		expect(modelCalls.length).toBe(0);
	});
});
