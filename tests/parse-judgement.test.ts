import { describe, expect, test } from "bun:test";
import { parseJudgement } from "../index.ts";

describe("parseJudgement", () => {
	test("bare verdict with reason", () => {
		const j = parseJudgement("SAFE — routine read of local files");
		expect(j.verdict).toBe("SAFE");
		expect(j.reason).toContain("routine read");
	});

	test("markdown-emphasized verdict still parses", () => {
		expect(parseJudgement("**SAFE**").verdict).toBe("SAFE");
	});

	test("VERDICT-prefixed replies parse (the PARSE_ERROR class)", () => {
		expect(parseJudgement("VERDICT | SAFE | Reads local logs, no exfiltration").verdict).toBe("SAFE");
		expect(parseJudgement("VERDICT: UNSAFE | deletes untracked work").verdict).toBe("UNSAFE");
		expect(parseJudgement("VERDICT- UNSURE").verdict).toBe("UNSURE");
	});

	test("verdict must stay anchored at reply start", () => {
		// Prose before the token is not a verdict format echo; it fails closed.
		expect(parseJudgement("The verdict is SAFE but actually UNSAFE").verdict).toBe("PARSE_ERROR");
		expect(parseJudgement("I think SAFE here").verdict).toBe("PARSE_ERROR");
		// VERDICT must be the exact label, not any word.
		expect(parseJudgement("The VERDICT | SAFE").verdict).toBe("PARSE_ERROR");
	});

	test("reason is carried from the first line only", () => {
		const j = parseJudgement("UNSAFE | force push\nextra ignored detail");
		expect(j.verdict).toBe("UNSAFE");
		expect(j.reason).not.toContain("extra");
	});
});
