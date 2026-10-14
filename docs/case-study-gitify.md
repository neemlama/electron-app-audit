# Before / After — Gitify v7.9.0 Electron fuses

This is the portfolio centerpiece. It is the artifact that cannot be produced by a
scanner, a course, or an LLM, because it requires finding the issue, reporting it
responsibly, writing the fix, and proving the fix on the real binary.

## What was audited

| | |
| --- | --- |
| Artifact | `Gitify-Setup-7.9.0.exe` (Windows NSIS installer, 108.7 MB) |
| Release | v7.9.0, published 2026-09-24 |
| License | MIT |
| Method | Extracted with 7-Zip (two-stage: NSIS payload -> `app-64.7z`), never installed or executed |
| Files scanned | 630 discovered, 429 scanned |

## Before

Full report: `reports/gitify-v7.9.0-asis.md`

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

Fuse wire version 1 with 9 entries. No risk-relevant fuse is enabled by choice —
the switches are at their Electron framework defaults because `@electron/fuses` has
never been run against this build.

What those three mean:

- **`run_as_node`** — `ELECTRON_RUN_AS_NODE=1 Gitify.exe` runs the binary as a plain
  Node runtime, dropping the Electron sandbox entirely.
- **`enable_node_options_env`** — `NODE_OPTIONS` is honoured, so a controlled launch
  environment can inject `--require` and load code at startup.
- **`enable_node_cli_inspect_args`** — a launch argument can attach the Node inspector
  to the renderer process.

## After

Full report: `reports/gitify-v7.9.0-fused-fixed.md`

Same binary, same length, with the proposed configuration applied.

| Fuse | Before | After |
| --- | --- | --- |
| `run_as_node` | enabled | **disabled** |
| `enable_cookie_encryption` | disabled | **enabled** |
| `enable_node_options_env` | enabled | **disabled** |
| `enable_node_cli_inspect_args` | enabled | **disabled** |
| `only_load_app_from_asar` | disabled | **enabled** |
| everything else | — | untouched |

## Byte-level proof

The flip is an in-place patch of the fuse wire. Nothing else in the 245,726,208-byte
binary moved:

```
file length before : 245726208
file length after  : 245726208   (identical)
differing bytes    : 5           (offsets 198870250-198870255)

offset 198870250 : 49 -> 48   ('1'->'0')  run_as_node
offset 198870251 : 48 -> 49   ('0'->'1')  enable_cookie_encryption
offset 198870252 : 49 -> 48   ('1'->'0')  enable_node_options_env
offset 198870253 : 49 -> 48   ('1'->'0')  enable_node_cli_inspect_args
offset 198870255 : 48 -> 49   ('0'->'1')  only_load_app_from_asar
```

Five changed bytes, all inside the 9-entry wire, matching the proposed config exactly.

## The fix

Branch `security/flip-electron-fuses`, patch at `gitify-fuse-fix.patch`.

Added fuse flipping to Gitify's existing `scripts/afterPack.js`, so one change covers
win/mac/linux. `@electron/fuses` added as a devDependency.

Two judgement calls, both deliberate:

- **`EnableEmbeddedAsarIntegrityValidation` left off.** It requires a matching
  `asarIntegrity` build option in `electron-builder.js`, which Gitify does not set.
  Enabling the fuse without it stops the app launching.
- **`afterPack`, not `postinstall`.** Keeps the dependency in `devDependencies` and
  avoids an "Electron was rebuilt" notice on every `npm install`.

## Verification

The configuration was applied to a copy of the shipped `Gitify.exe` and the wire was
re-read with an independent decoder plus the `@electron/fuses` API:

```
before  {"0":49,"1":48,"2":49,"3":49,"4":48,"5":48,"6":48,"7":49,"8":49}
after   {"0":48,"1":49,"2":48,"3":48,"4":48,"5":49,"6":48,"7":49,"8":49}
```

40/40 pipeline self-test assertions pass, including a regression case for the fuse
wire decoder (see below).

## Other observations, unchanged by the fix

| Observation | Count | Note |
| --- | --- | --- |
| Source maps shipped | 53 files, 1.1 MB | Reconstructable near-original source |
| React development bundles | 22 | `react-dom-server-legacy.browser.development.js` etc. |
| `electron-updater` present | yes | Update channel is the highest-value target |
| Hotjar bundled | yes | Session-replay analytics in a menu-bar app |
| Credential findings | 0 | Sweep was clean |
| External endpoints | 19 | After filtering documentation URLs |

Source maps and dev bundles were left to the maintainer — both are often intentional.

## Scope and limits

Static review only. The installer was extracted, never installed, and nothing was
executed. No runtime testing, no native decompilation, no credential was tested
against its provider. Fuse state was read directly from the binary.

## A note on the decoder

The fuse wire is **not** a bit-packed bytefield. It is:

```
sentinel | version byte | LENGTH byte | N ASCII state bytes ('0' / '1' / 'r' / 'i')
```

An early version of this pipeline read a single byte and extracted bits from it. On
the shipped Gitify binary it produced the right answer for the first four fuses —
purely because the length byte `0x09` is `0b1001` and happened to match the first four
ASCII states `1011`. On any other binary it would have silently misreported.

The decoder is now pinned by self-test with a case the bit-packing reader cannot pass.
This is recorded because the failure mode was a confident wrong answer, not a crash.
