# The Offer

One product. One price. No custom scoping — custom scoping is where service
businesses lose their margin.

## Why the positioning is "build and hardening", not "find secrets"

The first real audit settled this. Gitify v7.9.0 — a well-maintained 5.4k-star
app — contained **zero** credential leaks. If you list "I find leaked API keys",
you need a lucky target for every job, and every clean report makes you look
ineffective.

But that same app produced four real findings from build and hardening review:

| Finding | Severity to a client |
| --- | --- |
| `run_as_node` fuse enabled (fuse version 1 — defaults never flipped) | High |
| 53 source maps shipped (1.1 MB) — reconstructable source | Medium |
| 22 React development bundles in a production build | Medium |
| `electron-updater` present without evidence of signature pinning | Needs verification |
| Hotjar session-replay SDK in a menu-bar app | Informational / consent question |

**Mature apps score badly on hardening, consistently, every time.** That is a
predictable supply of work. Credentials become the secondary line item that
sometimes finds something.

## The listing headline

> I will audit your Electron desktop app for leaked API keys, missing security
> hardening and undisclosed third-party tracking, and deliver an evidence-backed
> report your developer can act on in an afternoon.

## What the client actually receives

1. **Executive summary** — 10 lines, written for an owner, not an engineer.
2. **Findings table** — severity, file, line, masked value, confidence level.
3. **Electron fuse report** — which hardening switches are off and what each permits.
4. **Build hygiene review** — source maps, dev bundles, auto-update channel.
5. **Network and telemetry inventory** — every third-party endpoint in the bundle.
6. **Coverage and limits** — what you did *not* check, stated plainly.

Total: 4–8 pages. Readable by the owner, actionable by the developer.

## What makes this defensible against a $20 scanner

Anyone can run `grep` for `sk_live_`. The value is in four things:

1. **No false-positive noise.** Every rule carries a confidence grade. A report with
   200 junk findings gets deleted. A report with 6 graded findings gets forwarded.
2. **The unknowns section.** Saying what you could *not* determine is rarer than it
   should be, and it is the part a sophisticated buyer reads first.
3. **Cross-platform honesty.** State exactly which build you examined. "v7.9.0 macOS
   universal build, JS bundle" is a stronger claim than vague "we looked at it".
4. **Written scope.** The client knows exactly what was and was not covered before
   paying. This is what prevents the "you missed X" dispute.

## Pricing

Marketplace reality check: commodity secret-scan gigs floor at low rates. Do not
compete there. Compete on the deliverable and on clarity.

| Stage | Price | Purpose |
| --- | --- | --- |
| First 2–3 jobs | $75–125 | Buy reviews, not margin. Accept this deliberately. |
| Jobs 4–7 | $150–300 | Once Upwork shows 3+ five-star reviews on this niche. |
| Jobs 8+ | $400–650 | Raise rate on every repeat client, not on new leads. |
| Direct clients (later) | $800–1500 | Only reachable once a payment rail exists. |

**Rule: never raise the price on a new prospect.** Raise it on existing clients who
already trust you. New leads keep converting at the old rate forever, and nobody
who already signed off on a scope feels nickel-and-dimed.

## Scope and boundaries (put these in the proposal, every time)

**In scope**
- Static review of the shipped application bundle
- Hardcoded credential discovery
- Electron fuse / hardening configuration
- Third-party endpoint and telemetry inventory

**Explicitly out of scope**
- Dynamic or runtime testing
- Decompiling native `.node` / `.dll` modules
- Exploitation of anything found
- Backend or cloud infrastructure assessment

Write the out-of-scope list into the proposal *before* payment. It is the single
cheapest dispute-prevention measure available.

## The permission problem

Read this before auditing anything you did not build yourself. It is the only part of
this document that can turn a good engagement into a legal problem, and the distinction
below is the one people get wrong.

### Inspecting a shipped artifact is almost always fine

Downloading a publicly distributed app and reading its bundle requires no permission.
Nobody needs to authorise you to unzip something they gave away.

### Publishing findings about it is a separate question

Open source does **not** settle it. An open-source licence grants rights over the
*code* — use, modify, distribute. It says nothing about the right to publicise
*vulnerabilities* in the maintainer's product. Those are different claims, and only
the first is covered.

So the rule is:

| Target | Inspect | Publish findings |
| --- | --- | --- |
| Software you own or built | yes | yes |
| Open source, maintainer engaged first | yes | after telling them |
| Open source, no contact made | yes | tell them first |
| Commercial software | yes | written authorisation |

In every row where you publish, **the maintainer hears it from you first**. There is no
row where silence then publication is acceptable.

### Why this is stricter than it looks

The failure mode is not legal exposure so much as reputational. A finding published
before the owner knows it exists is indistinguishable from a drive-by disclosure, and
nobody in your portfolio is going to read the nuance. Setchy's handling of the Gitify
fuses is the model: a stranger found a real gap, sent it privately with the evidence
and an offer to help fix it, and ended up credited in the PR that shipped the fix. That
is what the same finding looks like when it is done in the right order.

### Portfolio strategy that keeps this clean

1. Audit an open-source app.
2. **Contact the maintainer privately with the findings.** Do not publish first.
3. Offer the fix, not just the problem.
4. Ask permission to publish, after they respond.

Step 3 is what most people skip. A report that only says "you have a problem" is an
obligation. A report that also says "here is the patch, verified" is a contribution,
and it is the reason the credit goes the other way.

## What never gets published

Even with permission:

- Full unredacted credential values — always masked, in every artifact
- A specific live key that grants access to anything
- Exploit steps against a system the owner did not authorize
- Findings about anything other than the artifact you were asked to examine

The report proves you can find and classify. It never becomes a working key.
