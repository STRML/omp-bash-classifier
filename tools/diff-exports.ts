/** One-off tool: names pi-coding-agent imports from the pi-ai barrel that the
 *  published pi-ai barrel does not export. Writes the set to STDOUT. */
import * as fs from "node:fs";
import * as path from "node:path";

const api = (p: string) => `node_modules/@oh-my-pi/${p}/src`;

const walk = (dir: string): string[] =>
	fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry =>
		entry.isDirectory() ? walk(path.join(dir, entry.name)) : [path.join(dir, entry.name)],
	);

const exported = new Set<string>();
const barrel = fs.readFileSync(path.join(api("pi-ai"), "index.ts"), "utf8");
for (const match of barrel.matchAll(/export\s*\*\s*from\s*"\.\/([^"]+)"/g)) {
	let file = path.join(api("pi-ai"), match[1]);
	if (!fs.existsSync(file)) file += ".ts";
	if (fs.statSync(file).isDirectory()) {
		const entries = fs.readdirSync(file).filter(entry => entry.endsWith(".ts"));
		file = path.join(file, entries.includes("index.ts") ? "index.ts" : entries[0]);
	}
	const source = fs.readFileSync(file, "utf8");
	for (const name of source.matchAll(/export\s+(?:declare\s+)?(?:function|const|class|interface|type|enum)\s+([A-Za-z_$][\w$]*)/g)) {
		exported.add(name[1]);
	}
}
for (const match of barrel.matchAll(/export\s*\{([^}]+)\}/g)) {
	for (const name of match[1].split(",")) exported.add(name.trim().replace(/^type\s+/, ""));
}

const imported = new Set<string>();
for (const file of walk(path.join(api("pi-coding-agent")))) {
	const source = fs.readFileSync(file, "utf8");
	for (const match of source.matchAll(/import(?:\s+type)?\s*\{([^}]+)\}\s*from\s*"@oh-my-pi\/pi-ai"/g)) {
		for (const name of match[1].split(",")) {
			// ESM resolves the EXPORTED name; an `as local` alias only renames
			// locally. Strip type markers and aliases to the exported side.
			const cleaned = name.trim().replace(/^type\s+/, "").split(/\s+as\s+/u)[0]?.trim() ?? "";
			if (cleaned && cleaned !== "type") imported.add(cleaned);
		}
	}
}

const missing = [...imported].filter(name => !exported.has(name)).sort();
const allImported = [...imported].sort();
console.log("=== MISSING FROM BARREL ===");
console.log(missing.join("\n"));
console.log("=== ALL IMPORTED NAMES (mock must provide every one) ===");
console.log(allImported.join("\n"));
console.error(`missing=${missing.length} imported=${imported.size} exported=${exported.size}`);
// Paste-ready mock object literal: runtime-value names get stubs, everything
// else (types) gets an inert marker.
const FUNCTION_NAMES = new Set([
	"buildAnthropicAuthConfig", "buildAnthropicSearchHeaders", "buildAnthropicSystemBlocks",
	"buildAnthropicUrl", "calculateRateLimitBackoffMs", "clearAnthropicFastModeFallback",
	"coerceServiceTierByFamily", "completeSimple", "deriveClaudeDeviceId", "getEnvApiKey",
	"getOAuthProviders", "getOpenRouterHeaders", "getProviderDetails",
	"isAnthropicFastModeFallbackDisabled", "isAuthRetryableError", "isDefinitiveOAuthFailure",
	"isSqliteBusyError", "isUsageLimitOutcome", "jsonSchemaToTypeScript",
	"listProvidersWithEnvKey", "parseRateLimitReason", "realizesPriorityServiceTier",
	"resolveAnthropicMetadataUserId", "resolveApiKeyOnce", "resolveModelServiceTier",
	"resolveUsedFraction", "retryTransientCompletion", "seedApiKeyResolver", "streamSimple",
	"stripClaudeToolPrefix", "validateToolArguments", "validateToolCall", "withAuth",
	"withOAuthAccess", "wrapFetchForCch",
]);
const ARRAYS = new Set(["PASTE_CODE_LOGIN_PROVIDERS"]);
const NUMBERS = new Set(["ANTHROPIC_OAUTH_GRANT_TTL_MS"]);
console.log("=== MOCK OBJECT ===");
for (const name of allImported) {
	if (name === "completeSimple") continue;
	if (name === "SqliteAuthCredentialStore") continue;
	let expr: string;
	if (FUNCTION_NAMES.has(name)) expr = "missingExportStub";
	else if (ARRAYS.has(name)) expr = "[]";
	else if (NUMBERS.has(name)) expr = "1000 * 60 * 60 * 24 * 30";
	else expr = "typeMarkerStub";
	console.log(`\t${name}: ${expr},`);
}
