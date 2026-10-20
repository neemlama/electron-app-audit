# Electron App Audit - Gitify 7.9.0

- **Target:** macOS install, Contents/Resources/app.asar
- **Generated:** 2026-10-20T03:44:06.267Z
- **Files scanned:** 429
- **Credential findings:** 0

## How to read this report

Findings carry a confidence level:

| Level | Meaning |
| --- | --- |
| `likely-valid` | Shape matches a known credential format and is not a placeholder. Not yet tested against the provider. |
| `needs-verification` | Flagged for review. Requires a functional test before it counts as a breach. |
| `informational` | Present by design. Listed for inventory, not as a defect. |

Secret values are redacted. We report location, shape and classification, never a usable credential.

Test files (0) are excluded from credential scanning: they ship fake credentials on purpose to test their own suites. Findings inside third-party libraries are marked and are more likely to belong to the library's author than to the app being audited.

## Executive summary

- No critical or high severity credential-shaped values were found in the scanned bundle.
- 106 source map file(s) ship in the build (2.1 MB), which lets anyone reconstruct near-original source.
- 44 development-mode bundle(s) ship in what should be a production build.
- Telemetry/analytics SDKs present: Hotjar.
- 3 Electron hardening switch(es) left at defaults (run_as_node, enable_node_options_env, enable_node_cli_inspect_args).

Read **Coverage and limits** before treating a clean credential result as a clean bill of health.

## Credential findings

_None._
## Build and hardening observations

### Source maps shipped in the build (106 files, 2.1 MB)

Source maps let anyone reconstruct near-original source from the shipped binary. This is not a secret leak, but it removes obfuscation as a defence and makes every other finding easier to exploit.

- `node_modules/builder-util-runtime/out/CancellationToken.js.map` (6 KB)
- `node_modules/builder-util-runtime/out/CancellationToken.js.map` (6 KB)
- `node_modules/builder-util-runtime/out/blockMapApi.js.map` (0 KB)
- `node_modules/builder-util-runtime/out/blockMapApi.js.map` (0 KB)
- `node_modules/builder-util-runtime/out/httpExecutor.js.map` (42 KB)
- `node_modules/builder-util-runtime/out/httpExecutor.js.map` (42 KB)
- `node_modules/builder-util-runtime/out/error.js.map` (0 KB)
- `node_modules/builder-util-runtime/out/error.js.map` (0 KB)
- `node_modules/builder-util-runtime/out/index.js.map` (3 KB)
- `node_modules/builder-util-runtime/out/index.js.map` (3 KB)

### Development bundles in a production build (44)

These ship React/framework development builds. They are larger, contain verbose warnings and error text, and can include code paths that production builds omit.

- `node_modules/react/cjs/react-compiler-runtime.development.js` (1 KB)
- `node_modules/react/cjs/react-compiler-runtime.development.js` (1 KB)
- `node_modules/react/cjs/react-jsx-dev-runtime.development.js` (12 KB)
- `node_modules/react/cjs/react-jsx-dev-runtime.development.js` (12 KB)
- `node_modules/react/cjs/react-jsx-dev-runtime.react-server.development.js` (14 KB)
- `node_modules/react/cjs/react-jsx-dev-runtime.react-server.development.js` (14 KB)
- `node_modules/react/cjs/react-jsx-runtime.development.js` (13 KB)
- `node_modules/react/cjs/react-jsx-runtime.development.js` (13 KB)
- `node_modules/react/cjs/react-jsx-runtime.react-server.development.js` (14 KB)
- `node_modules/react/cjs/react-jsx-runtime.react-server.development.js` (14 KB)

### Auto-updater present

The bundle includes `electron-updater`. The update channel is a high-value target: compromise the update feed or the signing key and you control what every user runs next. Confirm updates are signature-verified and served over HTTPS.

### Telemetry and analytics inventory

Present in the shipped bundle. Inventory, not a defect:

- Hotjar

## Security-relevant files in app code

Third-party library internals are excluded; these are the app's own files.

| File | Category | Why it matters |
| --- | --- | --- |
| `build/main.js` | Main process entry | Full Node.js and OS access. |
| `build/preload.js` | Preload script | Runs with Node access in the renderer; the main privilege boundary. |

## Electron fuses

Binary: `Electron Framework` | fuse version 1

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
| `wasm_trap_handlers` | enabled |

`run_as_node` enabled means `ELECTRON_RUN_AS_NODE=1 <app>` starts the binary as a plain Node runtime, dropping the Electron sandbox. 
`enable_node_options_env` enabled means `NODE_OPTIONS` is honoured, so a controlled launch environment can inject `--require` and load code at startup. 
`enable_node_cli_inspect_args` enabled means a launch argument can attach the Node inspector to the renderer process. 

Fuse wire version 1 with 9 entries and no explicit configuration is consistent with `@electron/fuses` never having been run against this build, which leaves every switch at its Electron framework default rather than a deliberate choice.

## External network endpoints

Documentation and comment URLs are filtered out. What remains are hosts referenced by executable code.

| Host | References | First seen in |
| --- | --- | --- |
| www.w3.org | 89 | `build/assets/index-DOJv1l9_.js` |
| github.com | 54 | `build/main.js` |
| localhost | 18 | `build/assets/index-DOJv1l9_.js` |
| gitify.io | 4 | `build/main.js` |
| api.github.com | 3 | `build/assets/index-DOJv1l9_.js` |
| bitbucket.org | 2 | `build/assets/index-DOJv1l9_.js` |
| allyoucanleet.com | 2 | `node_modules/lodash.escaperegexp/package.json` |
| s3.amazonaws.com | 1 | `node_modules/builder-util-runtime/out/publishOptions.js` |
| api.atlassian.com | 1 | `build/assets/index-DOJv1l9_.js` |
| support.atlassian.com | 1 | `build/assets/index-DOJv1l9_.js` |
| id.atlassian.com | 1 | `build/assets/index-DOJv1l9_.js` |
| uploads.github.com | 1 | `build/assets/index-DOJv1l9_.js` |
| cli.github.com, | 1 | `build/assets/index-DOJv1l9_.js` |
| docs.gitea.com | 1 | `build/assets/index-DOJv1l9_.js` |
| cdn.jsdelivr.net | 1 | `build/assets/index-DOJv1l9_.js` |
| opencollective.com | 1 | `node_modules/cookie/package.json` |
| api.bitbucket.org | 1 | `node_modules/electron-updater/out/providers/BitbucketProvider.js` |
| blog.izs.me | 1 | `node_modules/sax/package.json` |
| nfriedly.com | 1 | `node_modules/set-cookie-parser/package.json` |

## Coverage and limits

What this audit did **not** cover, stated explicitly:

- Files larger than 8 MB were skipped (0 file(s)).
- Runtime behaviour. Nothing was executed; only the shipped bundle was read.
- Native binaries were not decompiled. Strings inside bundled `.node`/`.dll`/`.exe` modules are out of scope for this pass.
- Obfuscated or dynamically assembled secrets may be missed.
- No credential was tested against its provider. A `likely-valid` shape is not proof of a live key.
- The application's own backend, once deployed, is outside this artifact review.
