/**
 * Permission-dialog shape. The reason belongs in the body, not the title;
 * everything this process did not author is a verbatim code block; and fields
 * that sit at their default are not printed at all.
 */
import { beforeEach, describe, expect, test } from "bun:test";
import {
	confirmCalls,
	dialogText,
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
	return { title: calls[0][0], body: calls[0][1], dialog: dialogText(ctx) };
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
		expect(body.startsWith("\n    git log --oneline")).toBe(true);
	});

	test("a blank line separates the title from the command", async () => {
		// THE invariant. An indented code block cannot interrupt a paragraph in
		// CommonMark, so without a blank line here the command is a lazy
		// continuation of the title and its markdown is rendered, not shown.
		const { dialog } = await prompt("git log --oneline");
		const lines = dialog.split("\n");
		expect(lines[0]).toBe("Run bash command? (classified unsafe)");
		expect(lines[1]).toBe("");
		expect(lines[2]).toBe("    git log --oneline");
	});

	test("an html comment cannot hide the middle of a command", async () => {
		// Verbatim from the review: comments are stripped for the terminal, so a
		// rendered version of this displays `echo " "` and runs the deletion.
		const command = 'echo "<!-- ok" ; rm -rf ~/data ; echo "-->"';
		const { dialog } = await prompt(command);
		const lines = dialog.split("\n");
		expect(lines[1]).toBe("");
		expect(lines[2]).toBe(`    ${command}`);
	});

	test("control characters are escaped, not sent to the terminal", async () => {
		const { dialog } = await prompt("echo \u001b[2J\u001b[Hgotcha");
		expect(dialog).not.toContain("\u001b");
		expect(dialog).toContain("\\x1b[2J");
	});

	test("unicode line separators cannot split the command out of the block", async () => {
		// U+2028 is a line break to the Markdown lexer but not to String.split("\n"),
		// so the half before it vanished from the dialog and the half after
		// rendered live. Reported as: `rm -rf ~/data\u2028git status` displays
		// only `git status`.
		const { dialog } = await prompt("rm -rf ~/data\u2028git status --short");
		expect(dialog).not.toContain("\u2028");
		expect(dialog).toContain("\\u2028");
		const lines = dialog.split("\n");
		expect(lines[1]).toBe("");
		expect(lines[2].startsWith("    rm -rf ~/data")).toBe(true);
		// The destructive half is still on screen.
		expect(lines[2]).toContain("rm -rf ~/data");
	});

	for (const [name, ch] of [["U+0085 NEL", "\u0085"], ["U+2029 paragraph separator", "\u2029"]] as const) {
		test(`${name} is escaped too`, async () => {
			const { dialog } = await prompt(`echo a${ch}rm -rf ~/data`);
			expect(dialog).not.toContain(ch);
			expect(dialog).toContain("rm -rf ~/data");
		});
	}

	test("a bidi override cannot reorder the displayed command", async () => {
		const { dialog } = await prompt("echo \u202Egnuj\u202C");
		expect(dialog).not.toContain("\u202E");
		expect(dialog).toContain("\\u202e");
	});

	test("a bare carriage return cannot overwrite the line", async () => {
		const { dialog } = await prompt("echo safe\rrm -rf ~/data");
		expect(dialog).not.toContain("\r");
		expect(dialog).toContain("\\x0d");
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

	test("a trailing space IS a different directory and must be shown", async () => {
		// Trimming made "/workspace " compare equal to "/workspace", so the dialog
		// implied the command ran in the session cwd when it did not.
		const spaced = await prompt("rm -rf *", { cwd: "/workspace " }, "/workspace");
		expect(spaced.body).toContain("working directory: /workspace ");
	});

	test("a trailing slash is not a different directory", async () => {
		const trailing = await prompt("git log", { cwd: "/workspace/" }, "/workspace");
		expect(trailing.body).not.toContain("working directory");
	});

	test("timeout 0 disables the deadline, so it does not read as 0s", async () => {
		const { body } = await prompt("git log", { timeout: 0 });
		expect(body).toContain("timeout: none (no deadline)");
		expect(body).not.toContain("timeout: 0s");
	});

	test("non-defaults are printed when set", async () => {
		const { body } = await prompt("git log", { timeout: 600, pty: true });
		expect(body).toContain("Details:");
		expect(body).toContain("timeout: 600s");
		expect(body).toContain("pty: true");
	});
});
