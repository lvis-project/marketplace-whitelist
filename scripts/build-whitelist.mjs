#!/usr/bin/env node
/**
 * build-whitelist.mjs — concatenate per-plugin grant JSON files in
 * `src/grants/*.json` into the canonical `v1/whitelist.json` artifact.
 *
 * Inputs:
 *   --validity-days <N>     Number of days from issuedAt → expiresAt. Default 90.
 *   --issued-at <ISO>       Optional explicit issuedAt. Default: now.
 *
 * Output: writes `v1/whitelist.json` to the repo root. Deterministic
 * top-level key order; per-plugin grants are sorted by plugin id so the
 * resulting body is byte-stable across runs that share the same timestamp.
 */
import { readdirSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const grantsDir = join(repoRoot, "src", "grants");
const outDir = join(repoRoot, "v1");
const outPath = join(outDir, "whitelist.json");

function parseArgs(argv) {
  const out = { validityDays: 90, issuedAt: undefined };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--validity-days") {
      out.validityDays = Number(argv[++i]);
      if (!Number.isFinite(out.validityDays) || out.validityDays <= 0) {
        throw new Error("--validity-days must be a positive number");
      }
    } else if (a === "--issued-at") {
      out.issuedAt = argv[++i];
    }
  }
  return out;
}

const { validityDays, issuedAt: explicitIssuedAt } = parseArgs(process.argv.slice(2));

const issuedAtDate = explicitIssuedAt ? new Date(explicitIssuedAt) : new Date();
if (Number.isNaN(issuedAtDate.getTime())) {
  throw new Error(`invalid --issued-at: ${explicitIssuedAt}`);
}
const expiresAtDate = new Date(issuedAtDate.getTime() + validityDays * 24 * 60 * 60 * 1000);

const grantFiles = readdirSync(grantsDir)
  .filter((name) => name.endsWith(".json"))
  .sort();

const pluginGrants = {};
for (const name of grantFiles) {
  const pluginId = name.replace(/\.json$/, "");
  const grant = JSON.parse(readFileSync(join(grantsDir, name), "utf-8"));
  pluginGrants[pluginId] = grant;
}

const doc = {
  version: 1,
  schemaVersion: 1,
  issuedAt: issuedAtDate.toISOString(),
  expiresAt: expiresAtDate.toISOString(),
  pluginGrants,
};

mkdirSync(outDir, { recursive: true });
writeFileSync(outPath, `${JSON.stringify(doc, null, 2)}\n`, "utf-8");
console.log(`wrote ${outPath}`);
console.log(`  issuedAt=${doc.issuedAt}`);
console.log(`  expiresAt=${doc.expiresAt}`);
console.log(`  plugins=${Object.keys(pluginGrants).join(",")}`);
