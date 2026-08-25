/**
 * Permission-dialog shape. The reason belongs in the body, not the title;
 * everything this process did not author is a verbatim code block; and fields
 * that sit at their default are not printed at all.
 */
import { beforeEach, describe, expect, test } from "bun:test";
import {
	confirmCalls,
	fire,
	loadPlugin,
	makeCtx,
	makeEvent,
	makeSettings,
	removeConfigFile,
	setClassifierDelay,
	setClassifierReply,
} from "./fixtures";

beforeEach(async () => {
	removeConfigFile();
	setClassifierDelay(5);
	await loadPlugin(makeSettings([]));
});

async function prompt(command: string, input: Record<string, unknown> = {}, cwd = "/workspace") {
	setClassifierReply("UNSAFE: Reads local git data and sends to a temp log");
	const ctx = makeCtx({ sessionId: `prompt-${command.length}-${Math.random()}`, hasUI: true, cwd });
	await fire("tool_call", makeEvent(command, input), ctx);
	const calls = confirmCalls(ctx);
	expect(calls).toHaveLength(1);
	return { title: calls[0][0], body: calls[0][1] };
}

describe("title", () => {
	test("carries the headline only, so it does not truncate", async () => {
		const { title } = await prompt("git log --oneline");
		expect(title).toBe("Run bash command? (classified unsafe)");
		expect(title).not.toContain("Reads local git data");
	});

	test("no em dash", async () => {
		const { title } = await prompt("git log -n 5");
		expect(title).not.toContain("—");
	});
});

describe("body", () => {
	test("opens with the command, indented verbatim", async () => {
		const { body } = await prompt("git log --oneline");
		expect(body.startsWith("    git log --oneline")).toBe(true);
	});

	test("markdown in the command cannot escape the code block", async () => {
		const command = "echo '**bold** `tick` <!-- hidden -->'";
		const { body } = await prompt(command);
		for (const line of body.split("\n")) {
			if (line.includes("**bold**")) expect(line.startsWith("    ")).toBe(true);
		}
	});

	test("the classifier reason is indented too, not rendered as live markdown", async () => {
		setClassifierReply("UNSAFE: **danger** <!-- hi -->");
		const ctx = makeCtx({ sessionId: "prompt-reason-md", hasUI: true });
		await fire("tool_call", makeEvent("git log"), ctx);
		const body = confirmCalls(ctx)[0][1];
		const reasonLine = body.split("\n").find(l => l.includes("**danger**"));
		expect(reasonLine?.startsWith("    ")).toBe(true);
	});
});

describe("details are omitted at their defaults", () => {
	test("a plain command prints no Details section at all", async () => {
		const { body } = await prompt("git log --oneline");
		expect(body).not.toContain("Details:");
		expect(body).not.toContain("pty");
		expect(body).not.toContain("async");
		expect(body).not.toContain("env:");
	});

	test("working directory appears only when it differs from the session cwd", async () => {
		const same = await prompt("git log", {}, "/workspace");
		expect(same.body).not.toContain("working directory");

		const different = await prompt("git log", { cwd: "/elsewhere" }, "/workspace");
		expect(different.body).toContain("working directory: /elsewhere");
	});

	test("non-defaults are printed when set", async () => {
		const { body } = await prompt("git log", { timeout: 600, pty: true });
		expect(body).toContain("Details:");
		expect(body).toContain("timeout: 600s");
		expect(body).toContain("pty: true");
	});
});
