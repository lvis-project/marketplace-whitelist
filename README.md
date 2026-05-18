# marketplace-whitelist

Signed plugin grants registry for host-owned LLM secret access in the LVIS
desktop app. This repo publishes the canonical document that gates Tier-3
of `resolve-api-key`: which marketplace plugin id may read which named host
secret (e.g. `llm.apiKey.openai`), pinned to an approved manifest sha256.

The LVIS desktop client fetches the artifact from:

- Primary: `https://lvis-project.github.io/marketplace-whitelist/v1/whitelist.json`
- Detached signature: `https://lvis-project.github.io/marketplace-whitelist/v1/whitelist.json.sig`
- Fallback: `https://github.com/lvis-project/marketplace-whitelist/releases/download/v1-latest/whitelist.json` (and `.sig`)

Both files MUST be served as a pair: clients verify the detached signature
over the raw body bytes before trusting any grant.

## Trust anchor

- Active signing key id: `whitelist-v1`
- Algorithm: `ed25519` (32-byte raw)
- Public key (base64 of raw 32-byte Ed25519): see `WHITELIST_PUBLIC_KEYS` in
  the LVIS app's `src/plugins/marketplace-keys.ts`. The matching private key
  is held out-of-band by the operator (see `SECURITY.md`).

Trust is **separate** from the marketplace tarball signing key
(`MARKETPLACE_PUBLIC_KEYS["poc-v1"]`). Compromising one trust domain does
not let an attacker rewrite the other.

## How to propose a new grant (PR workflow)

1. Add or edit a file in `src/grants/<plugin-id>.json`. The filename
   (sans `.json`) is the plugin id; the content matches the
   `WhitelistPluginGrant` shape:
   ```json
   {
     "publisher": "lvis-community",
     "hostSecrets": { "read": ["llm.apiKey.openai"] },
     "approvedManifestSha256": "<64 lowercase hex>"
   }
   ```
2. Compute `approvedManifestSha256` against the published plugin manifest
   using the canonical-JSON helper:
   ```bash
   node scripts/compute-sha.mjs ../path/to/<plugin>/plugin.json
   ```
   This mirrors the App's `src/plugins/whitelist/canonical-json.ts`
   (RFC 8785-style JCS at every depth).
3. Open a PR. Reviewers verify the sha matches the published plugin
   tarball's `plugin.json`, then approve.
4. After merge, a maintainer:
   - runs `node scripts/build-whitelist.mjs` (rebuilds `v1/whitelist.json`)
   - runs `WHITELIST_PRIVATE_KEY_BASE64=<base64> node scripts/sign-whitelist.mjs`
   - commits the new `v1/whitelist.json` + `v1/whitelist.json.sig`
   - tags `v1-latest` and creates a GitHub Release with the two files
     attached (this populates the fallback URL).

The GitHub Pages site serves `/v1/*` directly from `main`.

## Local verification

```bash
WHITELIST_PUBLIC_KEY_BASE64=<base64> \
  node scripts/verify-whitelist.mjs
```

Exits 0 on a valid signature, 1 on mismatch, 2 on config errors.

## Schema

| Field            | Type                                  | Notes                                          |
| ---------------- | ------------------------------------- | ---------------------------------------------- |
| `version`        | `1`                                   | Top-level format version.                      |
| `schemaVersion`  | `1`                                   | Reserved for forward-compatible field adds.    |
| `issuedAt`       | ISO-8601 string                       | Monotonicity floor (rollback guard).           |
| `expiresAt`      | ISO-8601 string                       | Beyond `expiresAt + 7d` clients fail closed.   |
| `pluginGrants`   | `Record<string, WhitelistPluginGrant>`| Keyed by plugin id.                            |

Each `WhitelistPluginGrant`:

| Field                    | Type        | Notes                                                            |
| ------------------------ | ----------- | ---------------------------------------------------------------- |
| `publisher`              | `string`    | Marketplace publisher slug. Must be non-empty.                   |
| `hostSecrets.read`       | `string[]`  | `llm.apiKey.<vendor>` keys this plugin may read.                 |
| `approvedManifestSha256` | hex string  | 64 lowercase hex digits; canonical-JSON sha256 of `plugin.json`. |

## Rotation

A new key id (`whitelist-v2`, etc.) is added to the App's `WHITELIST_PUBLIC_KEYS`
**alongside** the previous one. Clients accept any trusted key id until the
previous one is removed (after the 7-day cache TTL has expired everywhere).

## License

Documents and code in this repository are released under the MIT License
to match the upstream LVIS desktop client.
