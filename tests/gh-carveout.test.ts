/**
 * Guards the gh/rtk read-pipe carve-outs that live in CLASSIFIER_PROMPT
 * (index.ts:590). The prompt is a template literal: an inner backtick breaks
 * the string (caught by tsc as a syntax error), and a drift in wording silently
 * regresses the live classifier. These tests are the cheap deterministic check;
 * the corpus in eval/classify-corpus.ts is the live-model check (issue #2,
 * epic #16).
 */
import { describe, expect, test } from "bun:test";
import { CLASSIFIER_PROMPT } from "../index";

describe("CLASSIFIER_PROMPT gh/rtk carve-outs", () => {
	test("read-only hosted-API queries (gh read, gh api GET piped to jq/head/tail) are declared SAFE", () => {
		expect(CLASSIFIER_PROMPT).toContain("gh api <endpoint> GET");
		expect(CLASSIFIER_PROMPT).toContain("fetches data, sends nothing local");
	});

	test("gh run rerun/cancel with explicit run id are declared routine and SAFE", () => {
		expect(CLASSIFIER_PROMPT).toContain("gh run rerun and gh run cancel");
		expect(CLASSIFIER_PROMPT).toContain("routine development work and SAFE");
	});

	test("reading a hosted API is explicitly not sending local data", () => {
		expect(CLASSIFIER_PROMPT).toContain("Reading a hosted API is");
		expect(CLASSIFIER_PROMPT).toContain("sending LOCAL");
		expect(CLASSIFIER_PROMPT).toContain("file contents or secrets to a network endpoint");
	});

	test("gh pr merge is NOT carved out (consequential remote action)", () => {
		expect(CLASSIFIER_PROMPT).not.toContain("gh pr merge --auto");
	});
});