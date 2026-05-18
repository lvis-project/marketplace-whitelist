#!/usr/bin/env node
/**
 * verify-whitelist.mjs — sanity-check `v1/whitelist.json.sig` against
 * `v1/whitelist.json` using the public key supplied by env var. Mirrors
 * the App's `verifyEnvelope` semantics so a local check matches what the
 * client will execute.
 *
 * Inputs:
 *   env WHITELIST_PUBLIC_KEY_BASE64   Raw 32-byte ed25519 public key (base64).
 *   env WHITELIST_KEY_ID              Optional — expected key id. Default "whitelist-v1".
 *
 * Exit codes:
 *   0 — verified ok
 *   1 — verification failed
 *   2 — usage / config error
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, createPublicKey, verify } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const bodyPath = join(repoRoot, "v1", "whitelist.json");
const sigPath = `${bodyPath}.sig`;

const pubBase64 = process.env.WHITELIST_PUBLIC_KEY_BASE64;
if (!pubBase64) {
  console.error(
    "[verify-whitelist] WHITELIST_PUBLIC_KEY_BASE64 must be set (32-byte ed25519 public key, base64).",
  );
  process.exit(2);
}
const expectedKeyId = process.env.WHITELIST_KEY_ID || "whitelist-v1";

const rawPub = Buffer.from(pubBase64, "base64");
if (rawPub.length !== 32) {
  console.error(
    `[verify-whitelist] public key must decode to 32 bytes, got ${rawPub.length}.`,
  );
  process.exit(2);
}
const keyObj = createPublicKey({
  key: { kty: "OKP", crv: "Ed25519", x: rawPub.toString("base64url") },
  format: "jwk",
});

const body = readFileSync(bodyPath);
const envelope = JSON.parse(readFileSync(sigPath, "utf-8"));

if (envelope.version !== 1) {
  console.error(`[verify-whitelist] unsupported envelope version: ${envelope.version}`);
  process.exit(1);
}
const computedSha = createHash("sha256").update(body).digest("hex");
if (envelope.artifact_sha256?.toLowerCase() !== computedSha) {
  console.error(
    `[verify-whitelist] artifact_sha256 mismatch: envelope=${envelope.artifact_sha256} computed=${computedSha}`,
  );
  process.exit(1);
}

let matched = false;
for (const sig of envelope.signatures || []) {
  if (!sig || sig.alg !== "ed25519") continue;
  if (sig.key_id !== expectedKeyId) continue;
  const sigBytes = Buffer.from(sig.sig, "base64");
  if (sigBytes.length !== 64) continue;
  if (verify(null, body, keyObj, sigBytes)) {
    matched = true;
    break;
  }
}

if (!matched) {
  console.error(`[verify-whitelist] no signature verified against expected key_id=${expectedKeyId}`);
  process.exit(1);
}

console.log(`[verify-whitelist] OK`);
console.log(`  key_id=${expectedKeyId}`);
console.log(`  artifact_sha256=${computedSha}`);
console.log(`  issuedAt=${JSON.parse(body.toString("utf-8")).issuedAt}`);
console.log(`  expiresAt=${JSON.parse(body.toString("utf-8")).expiresAt}`);
