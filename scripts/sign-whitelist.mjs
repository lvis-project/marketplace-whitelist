#!/usr/bin/env node
/**
 * sign-whitelist.mjs — produce `v1/whitelist.json.sig` from `v1/whitelist.json`.
 *
 * The signature envelope matches the App's `SignatureEnvelope` contract:
 *
 *   { "version": 1,
 *     "iat": <unix>,
 *     "artifact_sha256": "<hex sha256 of body bytes>",
 *     "signatures": [{
 *       "key_id": "whitelist-v1",
 *       "alg": "ed25519",
 *       "sig": "<base64 ed25519 signature over the RAW body bytes>"
 *     }] }
 *
 * Inputs:
 *   env WHITELIST_PRIVATE_KEY_BASE64   Raw 32-byte ed25519 private key (base64).
 *   env WHITELIST_KEY_ID               Key id string. Default "whitelist-v1".
 *
 * Notes:
 *   - The signature is over the RAW body bytes (matches verifyEnvelope in
 *     `src/plugins/envelope-verifier.ts` — ed25519 signs raw bytes; the
 *     envelope sha256 is an explicit integrity cross-check).
 *   - Private key is consumed via env var only; never written to disk by
 *     this script. CI passes it through a GitHub Actions encrypted secret.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, createPrivateKey, sign } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const bodyPath = join(repoRoot, "v1", "whitelist.json");
const sigPath = `${bodyPath}.sig`;

const privBase64 = process.env.WHITELIST_PRIVATE_KEY_BASE64;
if (!privBase64) {
  console.error(
    "[sign-whitelist] WHITELIST_PRIVATE_KEY_BASE64 must be set (32-byte ed25519 private key, base64).",
  );
  process.exit(2);
}
const keyId = process.env.WHITELIST_KEY_ID || "whitelist-v1";

const rawPriv = Buffer.from(privBase64, "base64");
if (rawPriv.length !== 32) {
  console.error(
    `[sign-whitelist] private key must decode to 32 bytes, got ${rawPriv.length}.`,
  );
  process.exit(2);
}

// Construct a node KeyObject from raw seed via PKCS8 prefix.
// ed25519 PKCS8 SEED prefix: 302e020100300506032b657004220420
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const pkcs8 = Buffer.concat([PKCS8_PREFIX, rawPriv]);
const keyObj = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });

const body = readFileSync(bodyPath);
const sigBytes = sign(null, body, keyObj);
if (sigBytes.length !== 64) {
  console.error(
    `[sign-whitelist] expected 64-byte ed25519 signature, got ${sigBytes.length}.`,
  );
  process.exit(1);
}

const envelope = {
  version: 1,
  iat: Math.floor(Date.now() / 1000),
  artifact_sha256: createHash("sha256").update(body).digest("hex"),
  signatures: [
    { key_id: keyId, alg: "ed25519", sig: sigBytes.toString("base64") },
  ],
};

writeFileSync(sigPath, `${JSON.stringify(envelope, null, 2)}\n`, "utf-8");
console.log(`wrote ${sigPath}`);
console.log(`  key_id=${keyId}`);
console.log(`  artifact_sha256=${envelope.artifact_sha256}`);
