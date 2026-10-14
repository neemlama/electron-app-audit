# Submission status

## Upstream contribution: SENT

| | |
| --- | --- |
| PR | https://github.com/gitify-app/gitify/pull/3423 |
| Title | `fix(build): flip Electron fuses in packaged builds` |
| Author | `neemlama` |
| Files | `scripts/afterPack.js`, `package.json` |
| Diff | +70 / -0 |
| Branch | `neemlama/gitify` @ `security/flip-electron-fuses` |

### Why the title is `fix(build):` and not `security:`

Gitify uses [release-please](https://github.com/googleapis/release-please) and requires
Conventional Commits on PR titles. Per their `CONTRIBUTING.md`: *"The commit type decides
the version bump and the changelog section it lands in."*

`security:` is not a valid Conventional Commit type, so it would have failed their
"Validate PR title" workflow and blocked release automation. `fix:` is correct here
because the change alters shipped behaviour and should land in a patch release.

### Awaiting

Maintainer review. If they ask for changes, the branch is on the fork and can be
amended directly.

## This repository

| | |
| --- | --- |
| Remote | https://github.com/neemlama/electron-app-audit |
| Visibility | **PRIVATE** |
| Branch | `main` |
| Commit | `4999989` |
| Author identity | `neemlama@users.noreply.github.com` |

### Before making it public

`reports/gitify-v7.9.0-asis.md` documents three unrepaired security findings in
Gitify v7.9.0. Those findings are not vulnerabilities — they are Electron framework
defaults, publicly observable by anyone who downloads the app — but publishing them
before the maintainer has responded reads as a drive-by disclosure regardless of
intent.

Wait for a response on PR #3423 first. Their reply is worth more to a portfolio than
the report itself, and it removes the disclosure question entirely.

## The patch file

`docs/gitify-fuse-fix.patch` is a `git format-patch` output and applies to a clean
checkout of `gitify-app/gitify`:

```bash
git clone https://github.com/neemlama/gitify.git
cd gitify
git checkout -b security/flip-electron-fuses
git apply --3way /path/to/gitify-fuse-fix.patch
```

An earlier version of this file was written through PowerShell redirection and ended up
UTF-16 encoded, which `git apply` rejected with "No valid patches in input". It has been
regenerated with `git format-patch -o` and the encoding verified.
