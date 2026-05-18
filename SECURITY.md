# Security & key custody — marketplace-whitelist

## Threat model

The signed whitelist document gates which marketplace plugin may read which
host-owned LLM secret (`llm.apiKey.<vendor>`). The threat model:

- **Adversary A — supply chain**: tampers with `whitelist.json` or
  `whitelist.json.sig` in transit, in the CDN, or in the GitHub Release
  asset.
  - **Mitigation**: detached Ed25519 signature over raw body bytes;
    client (`src/plugins/envelope-verifier.ts`) recomputes
    `artifact_sha256`, rejects mismatches, requires `version === 1`.
- **Adversary B — rollback**: replays an older, broader grant document
  to expand a plugin's access.
  - **Mitigation**: client tracks `highestSeenIssuedAt`; documents with
    an older `issuedAt` are rejected even with a valid signature
    (`whitelist-registry.ts`).
- **Adversary C — manifest swap**: ships a different `plugin.json` than
  the one approved by the grant.
  - **Mitigation**: Tier-3 pins `approvedManifestSha256` (canonical JSON
    sha256). A swapped manifest fails the pin.
- **Adversary D — silent denial**: pulls the document off the primary
  host to revoke access.
  - **Mitigation**: 4xx on primary is terminal (intentional revocation),
    5xx falls back to the GitHub Release asset; cached doc remains
    usable inside a 7-day stale-grace window before clients fail closed.

## Key custody

| Item                | Location                                                                 |
| ------------------- | ------------------------------------------------------------------------ |
| Active key id       | `whitelist-v1`                                                           |
| Algorithm           | Ed25519 (32-byte raw seed)                                               |
| Public key          | `WHITELIST_PUBLIC_KEYS["whitelist-v1"]` in LVIS app `marketplace-keys.ts`|
| Private key (CI)    | GitHub Actions encrypted secret `WHITELIST_SIGNING_KEY` (base64 of 32-byte seed) |
| Private key (offline backup) | Operator hardware key (see internal ops runbook); not in this repo. |

The private key MUST NOT be written to disk by the signing script
(`scripts/sign-whitelist.mjs` consumes `WHITELIST_PRIVATE_KEY_BASE64`
from env only). The publish workflow injects it from the CI secret and
never echoes it; reviewers should fail any PR that adds `WHITELIST_SIGNING_KEY`
references outside `.github/workflows/publish.yml`.

## Rotation

1. Generate a new keypair (`node -e "const {generateKeyPairSync}=require('node:crypto'); ..."`).
2. Land the new public key + key id (`whitelist-v2`) in the LVIS app PR
   alongside the existing `whitelist-v1` entry. Keep both — clients
   accept either while caches still hold v1-signed docs.
3. Update the `WHITELIST_SIGNING_KEY` GitHub Actions secret to the new
   private key.
4. Cut a new release; verify with `scripts/verify-whitelist.mjs`.
5. After 30 days (≫ 7-day stale grace window), drop `whitelist-v1` from
   the app's `WHITELIST_PUBLIC_KEYS`.

## Revocation

To deny a previously granted plugin id:

- Open a PR removing its file in `src/grants/`.
- Merge, rebuild, re-sign, re-release. Clients will refresh within
  their poll window; cached entries hit Tier-3 only until the active
  document refreshes (worst case: cached snapshot + grace window).

For emergency revocation (active compromise of `whitelist-v1` signing
key), rotate the key per the procedure above AND publish an empty
`pluginGrants` document; cached snapshots will fall out of grace within
the configured stale-grace window.

## Reporting

Suspected key compromise: open a private security advisory on this
repository's GitHub Security tab. Do not file a public issue.
