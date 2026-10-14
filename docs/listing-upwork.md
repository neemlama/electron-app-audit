# Upwork / Fiverr Listing Copy

Paste-ready. Square brackets are yours to fill.

---

## Title (70 char limit)

```
I will audit your Electron app for leaked API keys and missing hardening
```

## Category / Subcategory

Programming & Dev → Web Development → Website Security
(or: Programming & Dev → QA & Testing → Security Testing)

## Tags

`electron`, `app security`, `api key exposure`, `security audit`, `hardcoded secrets`,
`electron fuses`, `desktop app`, `supply chain`, `secret scanning`, `build hardening`

## Overview (first 200 chars do the selling)

```
Most Electron apps ship with hardening left at defaults, source maps included, and
credentials nobody meant to publish. I audit the actual shipped build, not your
source, and hand you a report your developer fixes in an afternoon.
```

## Full Description

```
Two things go wrong in nearly every Electron app that ships to production, and
neither is visible in your source repo.

1. The Electron security fuses are left at their defaults. That means the app
   accepts a launch argument that hands Node.js to anything that can start it.
   It is a known, published class of issue and it is still everywhere.

2. Source maps, development bundles and build-time values ship inside the
   packaged app. Your JavaScript is not the minified file you think it is.

What you get from this audit:

  • Electron fuse report — which hardening switches are off and what each permits
  • Build hygiene review — source maps, dev bundles, auto-update channel
  • Credential sweep — API keys, OAuth secrets, tokens, bundled .env files
  • Third-party inventory — every external endpoint and analytics SDK present
  • A "coverage and limits" section stating exactly what was out of scope

How I work:

1. You send me the built installer, .exe, .zip or .asar. Source alone does not
   show what shipped, so I need the actual artifact your customers download.
2. I unpack it and analyse that artifact. Nothing is executed.
3. You get a short report, severity-ranked, with file and line for each finding.

Why this is worth more than running a free scanner yourself:

  • Every credential finding carries a confidence grade. I do not report a value
    as a leak until I have ruled out placeholders and test keys.
  • Secret values are masked in the report. You get location and shape, not a
    copy of the key sitting in your inbox.
  • I tell you what I could NOT determine. "Nothing found" and "nothing
    checkable" are very different, and most tools do not distinguish them.

Typical turnaround: 24-48 hours.

Scope: static review of the shipped artifact only. I do not run the application,
do not attempt to exploit anything I find, and do not test against live
third-party services. If you need runtime or infrastructure testing, this is the
wrong job and I will tell you before you hire me.

Message me with your app name and platform and I will tell you whether it is worth
looking at before you book anything.
```

## Pricing tiers

| Tier | Name | Price | Deliverable |
| --- | --- | --- | --- |
| Basic | Credential sweep | $75 | Credential + secret findings only, 1 build |
| Standard | Full bundle audit | $175 | **Most popular** — adds fuses, endpoints, telemetry, limits section |
| Premium | Audit + remediation session | $350 | Standard, plus a 60-min call walking your dev through each fix |

---

# Proposal template

Send this. Trim to the job. Do not send it word-for-word — clients can tell.

```
Hi [name],

Quick read on what you described: [restate their problem in one sentence, showing
you understood it].

[If they named a stack, address it specifically. If they did not, ask one sharp
question instead of guessing.]

What I would do:

1. Take the shipped build for [version/platform] and unpack the application
   bundle — that is the part your customers actually download, and it is where
   build-time values end up.
2. Sweep it for credential-shaped values, and separate real exposure from
   placeholders and test keys.
3. Check the Electron hardening switches, which control whether a launch argument
   can reach Node.js in the renderer.
4. Inventory every third-party endpoint and analytics SDK in the bundle.
5. Write it up with a clear "what I did not check" section.

You get the report and, if useful, a call with your developer to walk the fixes.
Secret values stay masked in the report.

[One relevant sentence about THEIR app specifically — a likely finding for their
stack. This is the part that wins jobs; do not skip it.]

Two questions so I scope it right:

1. Can you share the built installer or .asar? Source alone does not show what
   shipped — most of these leaks are invisible until the bundle is built.
2. Is there anything you specifically suspected?

[Your price and availability.]
```

## The "one relevant sentence"

This is the highest-leverage line in the whole template. It must be *true* and
*specific*. Examples by stack:

- **Electron** → "Electron packaging defaults leave `runAsNode` enabled in a
  large share of apps, which lets anyone who controls a launch argument execute
  Node in your renderer. That one alone is worth checking."
- **Next.js / Nuxt static export** → "Static exports routinely inline
  `NEXT_PUBLIC_*` values that were meant to be public. Worth confirming which of
  yours actually need to be."
- **React Native** → "Bundled Hermes bytecode hides strings from plain text search,
  so the usual scanners miss a lot."
- **Tauri** → "Tauri keeps most of your logic in Rust, so the exposure profile is
  very different from Electron. Worth confirming the capability list is minimal."

If you cannot write that sentence for their stack, do not send the proposal.
Send the question instead.

## Job-search search terms

Use these as literal Upwork search strings:

```
electron security audit
electron app security
hardcoded api key
secret scanning desktop app
api key exposure electron
security audit indie app
desktop app supply chain
```

## First-30-days operating rhythm

| Week | Action | Target |
| --- | --- | --- |
| 1 | Publish 1 portfolio audit. Fix Upwork profile headline + overview. Apply to 15 jobs/day. | 1 audit live |
| 2 | 15 applications/day. Reply to every proposal within 2h. | 1–2 interviews |
| 3 | Land first job at $75–125. Over-deliver slightly; request a 5-star review. | First revenue |
| 4 | Apply to 20/day. Raise rate to $150 on *existing* clients only. | 2–3 jobs done |

Two rules that matter more than volume:

1. **Speed wins the first three jobs.** Reply within 2 hours. Early Upwork jobs go
   to whoever answers fastest.
2. **Every job ends with a review request**, worded specifically — not "please
   leave a review" but "if the fuse section was useful, that is the part I would
   most like covered by a review."
