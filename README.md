# electron-app-audit

A pipeline that audits **shipped Electron desktop apps** and produces a client-ready
security and build-hygiene report.

It exists because a free tool can find the *candidates*. This finds them, grades how
much to trust each one, states what it could not determine, and produces something a
developer can act on in an afternoon.

## What it checks

| Check | What it finds |
| --- | --- |
| Credential sweep | API keys, OAuth secrets, tokens, private keys, bundled `.env` files |
| Electron fuses | Which hardening switches are open, and what each one permits |
| Build hygiene | Source maps and development bundles shipped in production |
| Update channel | Whether an auto-updater is present and what to confirm about it |
| Third-party inventory | Every external endpoint and analytics SDK in the bundle |

## Quick start

```bash
npm install

# Prove the detector works before trusting a clean result
npm run selftest

# Audit a packaged app. Accepts an install root, app.asar, or an unpacked app dir.
node pipeline/audit.mjs "path/to/App-install-dir" --out reports/my-app
```

On Windows, NSIS installers nest their payload and need two stages:

```bash
7z x App-Setup-1.0.0.exe -oApp-win
7z x "App-win/$PLUGINSDIR/app-64.7z" -oApp
node pipeline/audit.mjs "App" --out reports/my-app
```

You get `reports/my-app.md` (the deliverable) and `reports/my-app.json` (the data).

## Two design decisions that matter

**Secrets are masked.** The report gives you file, line, classification and entropy.
It never gives you a usable credential. That is what makes a report safe to email and
safe to publish as a portfolio sample.

**Every finding is graded.** `likely-valid`, `needs-verification`, `informational`.
Nothing is ever reported as "confirmed" without a functional test. A scanner that
reports 200 junk findings gets deleted; one that reports 6 graded findings gets
forwarded to a developer.

There is also a **Coverage and limits** section stating what was not checked. "Nothing
found" and "nothing checkable" are different, and most tools do not distinguish them.

## Verification

`npm run selftest` runs 40 assertions: known-bad input that must be detected,
known-good input that must not be flagged, a full end-to-end pipeline run, and the
Electron fuse wire decoder.

The fuse decoder matters more than it looks. The wire is **not** a bit-packed
bytefield — it is `sentinel | version | length | N ASCII state bytes`. An earlier
version of this pipeline read it as bits and returned the correct answer for the first
few fuses **by coincidence**, because the length byte `0x09` is `0b1001` and happened
to match the first four states `1011`. On any other binary it would have silently
misreported. The decoder is now pinned by a regression case that the bit-packing
reader cannot pass.

## Case study

[`docs/case-study-gitify.md`](docs/case-study-gitify.md) — a full before/after on
Gitify v7.9.0, including a byte-level proof of the fix.

Three risk fuses were open. The proposed fix was applied to a copy of the shipped
binary: **5 bytes changed, nothing else**, out of 245,726,208.

## Documentation

| File | What it covers |
| --- | --- |
| [`docs/offer.md`](docs/offer.md) | Positioning, pricing, scope boundaries |
| [`docs/listing-upwork.md`](docs/listing-upwork.md) | Paste-ready listing and proposal template |
| [`docs/case-study-gitify.md`](docs/case-study-gitify.md) | Worked before/after example |
| [`docs/outreach-gitify.md`](docs/outreach-gitify.md) | How the finding was reported, and how to report one |
| `docs/gitify-fuse-fix.patch` | The proposed upstream fix |

## Scope

Static review of the shipped artifact only. Nothing is executed. No runtime testing,
no native decompilation, no credential is tested against its provider, and nothing
found is ever exploited.

Auditing software you do not own requires written authorization. See
`docs/offer.md`.

## License

MIT
