# Outreach: Gitify maintainers

## Why this is not a disclosure, and why that matters

`run_as_node` enabled is the **Electron framework default**, not a Gitify defect.
Same for shipped source maps and dev bundles. None of these are exploitable-by-
default vulnerabilities, so there is nothing to embargo and no reason to go
private. A public GitHub issue is the correct channel and is how OSS projects
actually receive this kind of feedback.

## The move that beats "may I publish my report?"

Do not lead with a request for permission. Lead with the finding, then offer the
fix.

| Approach | What you get |
| --- | --- |
| "May I publish an audit of your app?" | A maybe. Possibly no reply. |
| "Here's a hardening gap, here's the PR" | A merged PR and a public link. |

A public issue link in your portfolio, attached to a fix you contributed, is worth
more than a redacted PDF anyone could have produced themselves. It proves you can
find the issue *and* land the change.

---

## Step 1 — the GitHub issue

Title:

```
Electron fuses are still at v1 defaults in v7.9.0 (run_as_node enabled)
```

Body:

```markdown
Hi Gitify team,

I did a static review of the shipped v7.9.0 Windows build (Gitify-Setup-7.9.0.exe,
unpacked, nothing executed) and the credential sweep came back clean — no leaked
keys or tokens. Nice.

Four build/hardening observations came out of it. None are vulnerabilities and none
need an embargo; they are all visible to anyone who downloads the app. Raising them
because they are cheap to fix.

## 1. Electron fuses are still at version 1 (the part worth acting on)

`Gitify.exe` reports fuse wire version 1, with 9 entries:

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

Fuse wire version 1 means `@electron/fuses` has never been run against the build, so
every switch is at its framework default rather than a deliberate choice. Three of
them are the risky ones:

- `run_as_node` — `ELECTRON_RUN_AS_NODE=1 Gitify.exe` runs the binary as a plain Node
  runtime, dropping the Electron sandbox entirely. On a shared workstation, or where
  an attacker can influence how the app is launched, that removes the sandbox.
- `enable_node_options_env` — `NODE_OPTIONS` is honoured, which lets a launch
  environment inject `--require` and load arbitrary code at startup.
- `enable_node_cli_inspect_args` — a launch argument can attach the Node inspector
  to the renderer process.

None of these are remotely exploitable and none need an embargo. `run_as_node` and
the other two are the Electron framework defaults, so this is not a Gitify bug -- it
is just the set of switches that were never closed.

---

## Happy to send a PR

Branch and patch are ready: `docs/gitify-fuse-fix.patch`.

The change adds fuse flipping to the `afterPack` hook that already exists in the
repo, so it covers win/mac/linux in one place. Verified by running it against a
copy of the shipped v7.9.0 `Gitify.exe` and re-reading the fuse wire afterwards:

```
before: {"0":49,"1":48,"2":49,"3":49,"4":48,"5":48,"6":48,"7":49,"8":49}
after:  {"0":48,"1":49,"2":48,"3":48,"4":48,"5":49,"6":48,"7":49,"8":49}
```

Fuses set: `RunAsNode=false`, `EnableCookieEncryption=true`,
`EnableNodeOptionsEnvironmentVariable=false`, `EnableNodeCliInspectArguments=false`,
`OnlyLoadAppFromAsar=true`.

Two things I deliberately left alone:

- **`EnableEmbeddedAsarIntegrityValidation`** is *not* enabled. It needs the matching
  `asarIntegrity` build option in `electron-builder.js`, and switching it on without
  that stops the app launching. Worth a separate change.
- **`GrantFileProtocolExtraPrivileges`** is left enabled. That is Electron's default
  and turning it off breaks `file://` handling; the meaningful protection is
  `OnlyLoadAppFromAsar`, which this does set.

Also note `@electron/fuses` is currently only a `devDependency` and the flip runs in
`afterPack`, not `postinstall` -- so there is no "Electron was rebuilt" notice on
every `npm install`.

Source maps and dev bundles I would leave to your own call; they are often
deliberate.

## 2. 53 source maps ship in the bundle (1.1 MB)

`*.js.map` files for `builder-util-runtime`, `js-yaml`, `cookie` and others are
inside `app.asar`. Anyone can reconstruct near-original source from them, which is
not a secret leak but does remove obfuscation as a defence.

## 3. 22 React development bundles ship in production

`react-dom/cjs/react-dom-server-legacy.browser.development.js` and friends are in
the asar. Larger bundle, verbose error text, and code paths production builds omit.

## 4. Hotjar is bundled

Session-replay analytics in a menu-bar app that reads your GitHub notifications.
Probably intentional — flagging in case it was not a conscious decision for the
desktop build specifically.

---

## Happy to send a PR

The fuse fix is small. In `package.json`:

```json
"postinstall": "electron-fuses flip --version 2 --run-as-node=false --enable-cookie-encryption=true --enable-node-options-env=false --enable-node-cli-inspect-args=false --enable-embedded-asar-integrity-validation=true --only-load-app-from-asar=true"
```

with `@electron/fuses` as a devDependency. Or equivalently a small
`electron-builder` `afterPack` hook.

Two caveats before merging, since both can break things:

- `enable_node_cli_inspect_args=false` disables `electron --inspect`. If you rely on
  that for debugging, leave it on or gate it to a dev build.
- `only_load_app_from_asar=true` breaks any code that loads scripts from disk. Worth
  a grep before enabling.

@electron/fuses as a devDependency also triggers an Electron rebuild notice on
install — harmless, but worth expecting so it does not look like a breakage.

Source maps and dev bundles I would leave to your own call; they are often
deliberate.

## Scope of my review

Static only. I unpacked the installer, read `app.asar` and the fuse bytes, and ran
nothing. No runtime testing, no native decompilation, no credential was tested
against any provider. Full write-up and method available if useful.

Happy to open the PR if that is welcome, or to drop it entirely — no offence either way.
```

---

## Step 2 — what to ask for

Only after the issue lands and they respond. Do not bundle these into the first
message; it makes the ask look transactional.

1. **"May I reference this issue in my portfolio?"** — near-certain yes once the
   report is public anyway.
2. **"May I publish the full report?"** — same.
3. **A testimonial.** If they fixed it because of your report, one sentence with
   their name and role is worth more than the report itself. Ask only after a fix
   lands.

---

## Step 3 — if they would rather not have it public

Some maintainers dislike public hardening notes. If Gitify's team says so, take it
down and switch to the DM below. Their preference wins; you keep the finding and
the fix, and you can run the same play on a different app.

## DM / email fallback

```markdown
Subject: Electron fuses at v1 defaults in v7.9.0 — finding and a possible PR

Hi,

I did a static review of the shipped v7.9.0 Windows build (unpacked, nothing
executed). Credential sweep was clean. Four hardening observations, none requiring
an embargo:

1. Gitify.exe is at fuse version 1 with run_as_node enabled. Electron default, not
   your bug — but ELECTRON_RUN_AS_NODE=1 would run it as a plain Node runtime.
2. 53 source maps ship in app.asar (1.1 MB).
3. 22 React development bundles ship in production.
4. Hotjar is bundled.

The fuse fix is a few lines and I would be glad to send a PR, including the two
flags that can break things (--inspect and only_load_app_from_asar).

Would you prefer this as a public issue instead? Happy either way.
```

Short version exists because a long first message to a stranger gets ignored.

---

## After the fix lands

If they merge it, re-run the pipeline and the report becomes a **before/after**
piece. That is the strongest artifact in this entire plan:

> "I found this, reported it responsibly, and the fix is in v7.10.0. Here is the
> diff and here is my pipeline."

That is not something a scanner user, a course student, or an LLM can produce. It
requires judgment, restraint, and follow-through — which is exactly the thing the
lesson from Oct 13 said buyers actually pay for.
