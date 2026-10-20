# Electron App Audit - StashBase 2.16.9

- **Target:** Windows install, resources/app.asar
- **Generated:** 2026-10-20T03:52:24.651Z
- **Files scanned:** 3883 (1 over 8 MB skipped)
- **Credential findings:** 1 (1 medium)

## How to read this report

Findings carry a confidence level:

| Level | Meaning |
| --- | --- |
| `likely-valid` | Shape matches a known credential format and is not a placeholder. Not yet tested against the provider. |
| `needs-verification` | Flagged for review. Requires a functional test before it counts as a breach. |
| `informational` | Present by design. Listed for inventory, not as a defect. |

Secret values are redacted. We report location, shape and classification, never a usable credential.

Test files (145) are excluded from credential scanning: they ship fake credentials on purpose to test their own suites. Findings inside third-party libraries are marked and are more likely to belong to the library's author than to the app being audited.

## Executive summary

- No critical or high severity credential-shaped values were found in the scanned bundle.
- Telemetry/analytics SDKs present: Hotjar.
- 3 Electron hardening switch(es) left at defaults (run_as_node, enable_node_options_env, enable_node_cli_inspect_args).

Read **Coverage and limits** before treating a clean credential result as a clean bill of health.

## Credential findings

### PostHog Project API Key

Severity: **medium** | Confidence: **likely-valid** | Occurrences: 1

> Write-only ingest key; enables event spam and cost abuse.

| File | Line | Redacted value | Entropy |
| --- | --- | --- | --- |
| `dist/server/index.mjs` | 67171 | `phc_s8[redacted]WRgm` | 4.91 |

## Build and hardening observations

### Auto-updater present

The bundle includes `electron-updater`. The update channel is a high-value target: compromise the update feed or the signing key and you control what every user runs next. Confirm updates are signature-verified and served over HTTPS.

### Telemetry and analytics inventory

Present in the shipped bundle. Inventory, not a defect:

- Hotjar

## Security-relevant files in app code

Third-party library internals are excluded; these are the app's own files.

| File | Category | Why it matters |
| --- | --- | --- |
| `dist/electron/external-navigation/preload.cjs` | Preload script | Runs with Node access in the renderer; the main privilege boundary. |
| `dist/electron/project/preload.cjs` | Preload script | Runs with Node access in the renderer; the main privilege boundary. |
| `dist/electron/renderer/preload.cjs` | Preload script | Runs with Node access in the renderer; the main privilege boundary. |
| `dist/electron/updates/preload.cjs` | Preload script | Runs with Node access in the renderer; the main privilege boundary. |
| `dist/electron/window/preload.cjs` | Preload script | Runs with Node access in the renderer; the main privilege boundary. |
| `dist/electron/workspace/preload.cjs` | Preload script | Runs with Node access in the renderer; the main privilege boundary. |
| `electron/external-navigation/preload.ts` | Preload script | Runs with Node access in the renderer; the main privilege boundary. |
| `electron/main.cjs` | Main process entry | Full Node.js and OS access. |
| `electron/project/preload.ts` | Preload script | Runs with Node access in the renderer; the main privilege boundary. |
| `electron/renderer/preload.ts` | Preload script | Runs with Node access in the renderer; the main privilege boundary. |
| `electron/text-services/preload.ts` | Preload script | Runs with Node access in the renderer; the main privilege boundary. |
| `electron/updates/preload.ts` | Preload script | Runs with Node access in the renderer; the main privilege boundary. |
| `electron/window/preload.ts` | Preload script | Runs with Node access in the renderer; the main privilege boundary. |
| `electron/workspace/preload.ts` | Preload script | Runs with Node access in the renderer; the main privilege boundary. |

## Electron fuses

Binary: `StashBase.exe` | fuse version 1

| Fuse | State |
| --- | --- |
| `run_as_node` | **enabled (risk)** |
| `enable_cookie_encryption` | disabled |
| `enable_node_options_env` | **enabled (risk)** |
| `enable_node_cli_inspect_args` | **enabled (risk)** |
| `enable_embedded_asar_integrity` | disabled |
| `only_load_app_from_asar` | disabled |
| `load_browser_v8_snapshot` | disabled |
| `grant_file_protocol_extra_privileges` | enabled |

`run_as_node` enabled means `ELECTRON_RUN_AS_NODE=1 <app>` starts the binary as a plain Node runtime, dropping the Electron sandbox. 
`enable_node_options_env` enabled means `NODE_OPTIONS` is honoured, so a controlled launch environment can inject `--require` and load code at startup. 
`enable_node_cli_inspect_args` enabled means a launch argument can attach the Node inspector to the renderer process. 

Fuse wire version 1 with 8 entries and no explicit configuration is consistent with `@electron/fuses` never having been run against this build, which leaves every switch at its Electron framework default rather than a deliberate choice.

## External network endpoints

Documentation and comment URLs are filtered out. What remains are hosts referenced by executable code.

| Host | References | First seen in |
| --- | --- | --- |
| json-schema.org | 303 | `dist/mcp/server.mjs` |
| github.com | 248 | `dist/mcp/server.mjs` |
| goo.gl | 120 | `dist/renderer/assets/docx-preview.worker-C_AShDd6.js` |
| www.w3.org | 104 | `dist/renderer/assets/createLucideIcon-DAIWz0zR.js` |
| example.com | 53 | `dist/renderer/assets/pdf-BK0fN3ss.js` |
| schemas.openxmlformats.org | 48 | `dist/renderer/assets/docx-preview.worker-C_AShDd6.js` |
| localhost | 47 | `dist/server/index.mjs` |
| purl.oclc.org | 20 | `dist/renderer/assets/docx-preview.worker-C_AShDd6.js` |
| raw.githubusercontent.com | 17 | `dist/mcp/server.mjs` |
| platform.claude.com | 17 | `node_modules/@anthropic-ai/claude-agent-sdk/browser-sdk.js` |
| opencollective.com | 17 | `node_modules/@modelcontextprotocol/sdk/node_modules/express/package.json` |
| feross.org | 12 | `node_modules/base64-js/package.json` |
| api.anthropic.com | 11 | `node_modules/@anthropic-ai/claude-agent-sdk/browser-sdk.js` |
| blog.izs.me | 11 | `node_modules/chownr/package.json` |
| www.xfa.org | 9 | `dist/renderer/assets/worker-B-kR1qiR.js` |
| day.js.org | 9 | `node_modules/dayjs/esm/plugin/devHelper/index.js` |
| docs.expo.dev | 8 | `node_modules/@anthropic-ai/claude-agent-sdk/browser-sdk.js` |
| docs.anthropic.com | 8 | `node_modules/@anthropic-ai/claude-agent-sdk/browser-sdk.js` |
| sub.example.com | 8 | `node_modules/zod/src/v4/classic/tests/string.test.ts` |
| stuk.github.io | 6 | `dist/renderer/assets/docx-preview.worker-C_AShDd6.js` |
| www.patreon.com | 6 | `node_modules/base64-js/package.json` |
| schemas.microsoft.com | 4 | `dist/renderer/assets/docx-preview.worker-C_AShDd6.js` |
| schemas.zwobble.org | 4 | `dist/renderer/assets/docx-preview.worker-C_AShDd6.js` |
| ns.adobe.com | 4 | `dist/renderer/assets/worker-B-kR1qiR.js` |
| code.claude.com | 4 | `node_modules/@anthropic-ai/claude-agent-sdk/sdk.mjs` |
| localhost'); | 4 | `node_modules/@modelcontextprotocol/sdk/dist/cjs/examples/client/elicitationUrlExample.js` |
| tjholowaychuk.com) | 4 | `node_modules/bytes/package.json` |
| google.com | 4 | `node_modules/zod/src/v3/tests/string.test.ts` |
| claude.ai | 3 | `dist/server/index.mjs` |
| sindresorhus.com | 3 | `node_modules/decompress-response/package.json` |
| jongleberry.com) | 3 | `node_modules/express/node_modules/raw-body/package.json` |
| substack.net | 3 | `node_modules/github-from-package/package.json` |
| example.org | 3 | `node_modules/zod/src/v4/classic/tests/template-literal.test.ts` |
| evilmartians.com | 2 | `dist/renderer/assets/docx-preview.worker-C_AShDd6.js` |
| www.w3ctech.com | 2 | `dist/renderer/assets/docx-preview.worker-C_AShDd6.js` |
| foo.bar | 2 | `dist/renderer/assets/pdf-BK0fN3ss.js` |
| git.io | 2 | `dist/server/index.mjs` |
| dub.sh | 2 | `dist/server/index.mjs` |
| openrouter.ai | 2 | `dist/server/index.mjs` |
| api.openai.com | 2 | `dist/server/index.mjs` |

## Coverage and limits

What this audit did **not** cover, stated explicitly:

- Files larger than 8 MB were skipped (1 file(s)).
- Runtime behaviour. Nothing was executed; only the shipped bundle was read.
- Native binaries were not decompiled. Strings inside bundled `.node`/`.dll`/`.exe` modules are out of scope for this pass.
- Obfuscated or dynamically assembled secrets may be missed.
- No credential was tested against its provider. A `likely-valid` shape is not proof of a live key.
- The application's own backend, once deployed, is outside this artifact review.
