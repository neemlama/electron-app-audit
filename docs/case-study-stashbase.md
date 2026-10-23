# Before / After — StashBase v2.16.9 Electron fuses & build hygiene

This case study demonstrates a full build review: fuse hardening, duplicate binary
detection, and credential hygiene — all from the shipped installer, never from
source.

## What was audited

| | |
| --- | --- |
| Artifact | `StashBase-2.16.9-Windows-Installer.exe` (NSIS, 949.3 MB) |
| Release | v2.16.9, published 2026-10-15 |
| License | Apache-2.0 |
| Method | Extracted with 7-Zip (two-stage: NSIS payload → `$PLUGINSDIR/app-64.7z`), never installed or executed |
| Files scanned | 3,883 discovered, 3,738 scanned (145 test files skipped, 1 file > 8 MB skipped) |

---

## Before: Electron fuses (3 risk-relevant defaults)

Full report: `reports/stashbase-v2.16.9.md`

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

Fuse wire version 1 with 8 entries. No risk-relevant fuse is enabled by choice —
the switches are at their Electron framework defaults because `@electron/fuses`
has never been run against this build.

What those three mean:

- **`run_as_node`** — `ELECTRON_RUN_AS_NODE=1 StashBase.exe` runs the binary as a
  plain Node runtime, dropping the Electron sandbox entirely.
- **`enable_node_options_env`** — `NODE_OPTIONS` is honoured, so a controlled
  launch environment can inject `--require` and load code at startup.
- **`enable_node_cli_inspect_args`** — a launch argument can attach the Node
  inspector to the renderer process.

**Third-party signal:** Issue #228 filed, maintainer credited the analysis, fix
merged with test coverage. Closed as `Closes #228`.

---

## Before: Build hygiene — duplicate binary (342 MiB)

The Windows installer ships `opencode.exe` **twice**, identical byte-for-byte:

| Property | Value |
| --- | --- |
| File | `opencode.exe` |
| Size (each) | 179,243,560 bytes |
| MD5 (both) | `DD60A3F77FCF59A1F32758E714F1D90C` |
| Hardlink check | `fsutil hardlink list` → **NOT hardlinks** (separate inodes) |
| Combined waste | **342 MiB** = **36% of the 949.3 MiB install** |

This is a build artefact, not a security issue. It inflates download size,
install time, and disk footprint for every user.

---

## Before: Credential hygiene

| Finding | Confidence | Note |
| --- | --- | --- |
| PostHog `phc_` token in `dist/server/index.mjs:67171` | `informational` | Bundled in server bundle; not a leak — value is a project API key, not a secret. Masked in report. |
| Hotjar + PostHog gated on `STASHBASE_PACKAGED === "1"` | `informational` | Product/consent question, not a defect. |

**Zero `likely-valid` or `needs-verification` credential findings.** The
credential sweep was clean.

---

## After: Fuses (proposed, not yet shipped)

The maintainer's fix in #228 adds `electronFuses` config to disable the three
risk fuses on every platform before signing, with a test that flips the real
packaged binary and asserts only those three change.

| Fuse | Before | After (proposed) |
| --- | --- | --- |
| `run_as_node` | enabled | **disabled** |
| `enable_node_options_env` | enabled | **disabled** |
| `enable_node_cli_inspect_args` | enabled | **disabled** |
| `enable_cookie_encryption` | disabled | **enabled** (bonus hardening) |
| everything else | — | untouched |

The fix is in the repo; a release shipping it has not yet been published.

---

## After: Duplicate binary

Not yet addressed. The finding was communicated as a follow-up to #228. A
deduplication would remove 342 MiB from the installer.

---

## Verification

- Fuse state read directly from the binary via `@electron/fuses` API and an
  independent decoder.
- Duplicate binary confirmed with 7-Zip extraction + `fsutil hardlink list`.
- Credential scan: 3,883 files, entropy floor 4.5 on minified code, test-file
  heuristics, PEM-header-without-body rejection — 71/71 pipeline self-tests pass.
- Renderer hardening: **0 findings** — all five guards present
  (`contextIsolation`, `sandbox`, `nodeIntegration: false`, `setWindowOpenHandler`,
  `will-navigate`). `meta.guardSignals = {preload:true, windowOpen:true, navigation:true, permission:true, csp:true}`

---

## Other observations, unchanged by the fuse fix

| Observation | Count | Note |
| --- | --- | --- |
| Source maps shipped | 0 | Clean |
| Development bundles shipped | 0 | Clean |
| `electron-updater` present | yes | Update channel is the highest-value target — verify signature pinning |
| Python sidecar | yes | `pyarrow` 71 MB + `faiss` 50 MB — contributes to install size |
| Credential findings | 0 | Clean |
| External endpoints | 105 | After filtering documentation URLs |

---

## Scope and limits

Static review only. The installer was extracted, never installed, and nothing
was executed. No runtime testing, no native decompilation, no credential was
tested against its provider. Fuse state was read directly from the binary.
Strings inside bundled `.node`/`.dll`/`.exe` modules are out of scope.

---

## A note on the decoder

The fuse wire is **not** a bit-packed bytefield. It is:

```
sentinel | version byte | LENGTH byte | N ASCII state bytes ('0' / '1' / 'r' / 'i')
```

An early version of this pipeline read a single byte and extracted bits from it.
On the shipped StashBase binary it would have produced the right answer for the
first four fuses — purely because the length byte `0x08` is `0b1000` and happened
to match the first four ASCII states. On any other binary it would have silently
misreported.

The decoder is now pinned by self-test with a case the bit-packing reader cannot
pass. This is recorded because the failure mode was a confident wrong answer,
not a crash.