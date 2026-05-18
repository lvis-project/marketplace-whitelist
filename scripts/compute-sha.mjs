#!/usr/bin/env node
/**
 * compute-sha.mjs — compute the canonical-JSON sha256 used by Tier-3's
 * `approvedManifestSha256` pin. Mirrors `canonicalJSON` from
 * `src/plugins/whitelist/canonical-json.ts` in the App repo.
 *
 * Usage: node scripts/compute-sha.mjs <path/to/plugin.json> [more...]
 *
 * Why a local copy instead of `import`-ing? This repo is intentionally
 * dependency-free and self-contained — no link to the App worktree at
 * build time, so PR authors can run it from a clean clone.
 */
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

function canonicalJSON(value) {
  if (value === undefined) return "null";
  if (value === null || typeof value !== "object") {
    const s = JSON.stringify(value);
    return s ?? "null";
  }
  if (Array.isArray(value)) {
    const parts = value.map((e) => canonicalJSON(e));
    return `[${parts.join(",")}]`;
  }
  const obj = value;
  const sortedKeys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  const parts = sortedKeys.map((k) => `${JSON.stringify(k)}:${canonicalJSON(obj[k])}`);
  return `{${parts.join(",")}}`;
}

function sha256Of(path) {
  const raw = readFileSync(path, "utf-8");
  const parsed = JSON.parse(raw);
  const canon = canonicalJSON(parsed);
  return createHash("sha256").update(canon, "utf-8").digest("hex");
}

const args = process.argv.slice(2);
if (args.length === 0) {
  console.error("usage: compute-sha.mjs <plugin.json> [more...]");
  process.exit(2);
}
for (const p of args) {
  console.log(`${p}\t${sha256Of(p)}`);
}
