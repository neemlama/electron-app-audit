# Fiverr Setup

Paste-ready. Square brackets are yours to fill. Character limits are Fiverr's and
are noted so a paste does not get truncated.

The Upwork proposal template in `listing-upwork.md` does not belong here. Fiverr
is a listing marketplace: the gig does the selling, and the buyer messages first.

---

## 1. Seller profile

### Photo

A real photograph of you, plain background, decent light, face clearly visible.
Fiverr rejects logos, illustrations and avatars for the seller photo. This is not
optional and not worth arguing with.

### Description (600 character limit)

```
Independent reviewer of Electron desktop apps. I audit the build your
customers actually download, because most build-time exposure only exists
after packaging.

I found the Electron hardening fuses left unconfigured in Gitify (5.4k stars);
the maintainer credited the analysis and adopted the fix.

Every finding carries a confidence grade, secret values are masked, and the
report states plainly what I could not check. Static analysis only - nothing is
executed.
```

### Skills

Pick from Fiverr's suggested list where possible, then add free text:

`Electron` · `Application Security` · `Security Auditing` · `Vulnerability Assessment`
· `JavaScript` · `Node.js` · `Desktop Application` · `Technical Writing`

### Languages

English (your real level) · Nepali (Native/Bilingual). Do not inflate these; a
buyer who books expecting fluent English and gets something else leaves a bad
review, and the first three reviews are the whole business.

### Linked accounts

If Fiverr offers it for your region, add GitHub as `neemlama`. If it does not,
do not paste a URL into the gig description - see the ToS note at the bottom.

---

## 2. Gig

### Title (80 character limit)

```
I will audit your Electron app for leaked API keys and missing hardening
```

72 characters. The "I will" prefix is mandatory on Fiverr.

Keep "audit" in the title even though the category is Code Review. "Audit" is
what a buyer with a security worry types; the category and the tag list already
supply the word "review". Do not spend title space on a word the category hands
you for free.

Alternate, if you want the word "security" up front:

```
I will security audit your Electron desktop app and harden the build
```

### Category

**Confirmed on the live account: Cybersecurity & Data Protection is Fiverr Pro
(vetted) only and cannot be selected.** That changes the answer, and it changes
which channel is primary.

**Use this path:**

```
Programming & Tech > QA & Review > Code Review
```

**What is selectable, and why the rest lose:**

| Option | Subcategories | Verdict |
| --- | --- | --- |
| QA & Review | Software Testing, Code Review, Design Review | **Code Review.** The only bucket whose buyer already has software and wants a report on it. |
| Support & IT | Technical Support, Server Administration, Email Management, VoIP, Software Installation, Platform Migrations, CCTV | Operational IT. No security bucket exists. Wrong buyer. |
| Software Development | Desktop Applications, Bug Fixes, Scripting, API & Integrations, Plugins, Automations | 6,200+ Desktop Application gigs, all "I will build your app". Invisible and off-intent. |
| User Testing, Convert Files, Trading Bots, Mobile App Maintenance | - | No overlap at all. |

**The downside, stated once:** in Code Review the common price is $15-40 and the
visible ceiling is about $100. At $75 Basic you sit at the top of that band; at
$125 Standard you are above it, with no reviews. That is a real headwind.

Do not answer it by cutting price to match. A buyer shopping at $15 was never
going to buy a security audit at $55 either - they will buy the $15 review that
says "your variable names are inconsistent". Price is not what separates you
here; the claim on the first image and the first line of the description is.

**The strategic point, which matters more than the category:**

Fiverr gates security work behind Pro vetting. That is not a quirk of your
account, it is the platform saying where it wants this service to sit. So Fiverr
is the secondary channel now. Upwork - where you already have history, and where
a proposal goes to the buyer instead of waiting for search traffic - is primary.
Publish the gig because it costs nothing to leave standing, not because it will
produce the first invoice.

**If impressions arrive and orders do not:** test Basic at $55 for two weeks.
That is a test of the listing, not a change to the offer. Revert if it does not
move.

**If Fiverr Pro is ever offered:** create a second gig under
Cybersecurity > Assessment & Penetration Test. Do not move this one - by then it
will have reviews.

### Search tags (5 maximum, 20 characters each)

```
electron
security audit
code review
electron fuses
api key leak
```

"code review" replaces the earlier "desktop app" tag. It matches the category,
and "electron" already implies desktop. The other four carry intent.

### Development technology (single choice)

The gig builder asks for one primary language. Answer:

```
JavaScript
```

Three reasons, in order:

1. It is what you actually read. An Electron `app.asar` contains compiled or
   minified JavaScript. Choosing TypeScript would describe your client's repo,
   not the artifact you were paid to audit.
2. It is the widest filter. This field is a buyer-side filter, not a badge. More
   people filtering Code Review for JavaScript than for anything else.
3. Electron apps are JavaScript even when the source is TypeScript, so the
   answer is accurate for both kinds of client.

**Exception:** if `Electron` or `Desktop Applications` appears as an option, take
that instead. A narrower label that exactly matches the buyer beats a broad one.

**Second fallback:** `Node.js`, if JavaScript is somehow absent.

Do not pick `TypeScript` for accuracy-by-appearance. The filter is there to put
you in front of the buyer, and TypeScript narrows the net without adding truth.

### Types & techniques (up to 5)

Available options: Algorithmic, Clean Code, Code efficiency, Data structure,
Design patterns, Error handling, Unit tests, Version control.

None of them describe a security audit. Select **three**, not five:

```
Error handling
Design patterns
Code efficiency
```

**Why these three are defensible, with the evidence from the audits:**

| Selection | Justification |
| --- | --- |
| Error handling | The Gitify analysis found a missing `await` on `flipFuses` and a `productFilename` casing bug that silently skipped the Linux build. Both are failure-path defects. Hardening review is largely the question "does this fail safely?" |
| Design patterns | The renderer review is a review of the main/renderer boundary: `contextIsolation`, the preload surface, `setWindowOpenHandler`, `will-navigate`. That is architecture, and architecture is what this label means to a buyer. |
| Code efficiency | The StashBase finding is a 342 MiB duplicate binary, 36% of a 949 MiB install. That is shipped-artifact efficiency, not algorithmic efficiency. Weakest of the three - drop it if you want to stay strict. |

**Leave these unselected, deliberately:**

- **Clean Code** - a buyer selecting this wants naming and readability feedback.
  You do not sell that, and a one-star review is the price of pretending.
- **Unit tests** - implies coverage review.
- **Version control** - implies git workflow help.
- **Algorithmic, Data structure** - no overlap whatsoever.

Five selections would widen the filter net and narrow the quality of buyer. The
first three reviews decide whether this gig ever earns anything, and a refunded
order does not produce a review - it produces a dispute.

### Packages

Launch pricing. The first three reviews are worth more than the margin, and the
price rises only after they exist.

| | Basic | Standard | Premium |
| --- | --- | --- | --- |
| Name | Credential & Fuse Check | Full Bundle Audit | Audit + Developer Walkthrough |
| Price | $75 | $125 | $250 |
| Delivery | 2 days | 3 days | 4 days |
| Revisions | 1 | 2 | 2 |
| Contents | Credential sweep + fuse report + build hygiene. Short report. | All five sections, 4-8 pages. Marked Most Popular. | Full audit plus a 60-minute call walking your developer through each fix. |

After three five-star reviews, move Standard to $175 and Premium to $350. Do not
raise it on a new prospect at the same time - raise it, then let the next
prospect see the new number.

### Description (1200 character limit)

Measured at 1161 characters. Long lines on purpose: Fiverr counts line breaks,
so the paragraph wrapping above is not what gets pasted.

```
Two things go wrong in most Electron apps, and neither shows in your repo.

1. The Electron security fuses stay at their defaults, so the app accepts launch arguments that hand a Node.js runtime to anything that can start it.
2. Build-time values ship in the package: source maps, dev bundles, credentials nobody meant to publish.

I audit the artifact your customers download, not your repo. Nothing runs.

You get:
- Fuse report: which hardening switches are off, and what each permits
- Build hygiene: source maps, dev bundles, auto-update channel
- Credential sweep: API keys, OAuth secrets, tokens, bundled .env files
- Endpoint and analytics inventory
- Coverage and limits: what I did not check

Not a free scanner:
- Every credential is graded; placeholders and test keys ruled out
- Secrets are masked - location and shape, never a usable key
- "Nothing found" and "nothing checkable" are different results

I found the fuses unconfigured in Gitify (5.4k stars); the maintainer credited the analysis in the PR adopting the fix.

Static review only. Nothing is executed.

Message me your app and platform first; I will say honestly if it is worth doing.
```

### Requirements (questions the buyer answers at checkout)

1. Which platform and version? (for example: Windows 11, v2.4.1)
2. Please attach the built installer, .dmg, AppImage or .asar that your users download.
3. Is this app yours, or do you have written permission from the owner to have it reviewed?
4. Is there anything you specifically suspect, or want checked first?
5. Do you want the report as PDF or Markdown?

Question 3 is not bureaucracy. It is the cheapest possible filter against a job
you should not take, and it protects the buyer too.

### FAQ

**Do you need my source code?**
No. The shipped build is the point. A source review cannot show what was baked in
at package time.

**Will you always find a leaked key?**
No. Plenty of apps are clean on credentials and still fail on hardening. That is
why the fuse and build checks are the main deliverable, not the credential sweep.

**Do you run the application?**
No. Static analysis of the shipped files only. Nothing is launched and no
credential is tested against a live service.

**Is this a penetration test?**
No, and do not buy it expecting one. A penetration test attacks a running system
to prove what is exploitable. This is a static review of the build: it says which
hardening switches are off, what that permits, and what shipped in the package.
If you need exploitation and a proof-of-concept, you need a pentest from someone
else and I will say so before you order.

**What if you find nothing?**
You still receive the report, documenting what was checked and what was out of
scope. A clean result with a stated method is a useful result; a clean result
with no method is worthless.

**Can you fix the issues?**
The Premium package includes a walkthrough call with your developer. Implementation
is a separate scope and can be quoted after the report.

**Is my build kept confidential?**
Yes. I can sign an NDA. Findings are never published without written permission,
and secret values are masked in every artifact including the report itself.

---

## 3. Gig images

Fiverr shows three thumbnails. Use all three; one stock image reads as a template.

1. **Title card.** Dark background, large text: `ELECTRON APP SECURITY AUDIT`.
   Below it, three words: `Fuses · Source maps · Credentials`.
2. **Proof.** A cropped, redacted excerpt of the real Gitify report showing the
   fuse table with `run_as_node | enabled (risk)`. This is the only image that
   matters, because it is evidence rather than a claim.
3. **Deliverable.** A simple checklist of the five report sections.

Recommended size 1280 x 769. Do not put your email, phone or a URL on any image.

---

## 4. ToS cautions

Worth reading once, because a suspension at this stage costs weeks.

- **Do not link out for hiring.** No "email me", no "DM me on GitHub", no link
  to a booking page. Fiverr treats that as taking payment off-platform.
- **A URL in the gig description can be flagged.** Writing `GitHub: neemlama` in
  plain text is tolerated; `https://github.com/neemlama` is likelier to be
  auto-flagged. The PR reference in the description is enough without a link.
- **Do not name another marketplace.** No Upwork, no Freelancer, anywhere.
- **Do not promise a guaranteed finding.** A gig that promises "I will find your
  leaked keys" invites a refund demand on a clean app.
- **Response time.** Only advertise a response time you will actually keep. Early
  on, "within 24 hours" is safer than "within 1 hour".

---

## 5. Order of operations

1. Complete ID verification and payout details first. A gig cannot go live without them.
2. Photo, description, skills, languages.
3. Create the gig, paste title, category, tags, description.
4. Build the three packages and the requirements questions.
5. Upload three images.
6. Publish and wait for approval, usually 24-48 hours.
7. Once live: send the gig link to nobody, and instead start applying on Upwork
   in parallel. Fiverr discovery for a new seller is slow; Upwork proposals are
   not. The two channels are not either/or.

---

## 6. The claim, stated correctly

Use this wording. It survives someone checking.

> I found the Electron hardening fuses left unconfigured in Gitify (5.4k stars).
> The maintainer credited the analysis in the replacement PR that adopts the fix.

Do not write, anywhere:

- "my fix was merged into Gitify" - PR #3442 is still an open draft
- "my pull request shipped in Gitify vX" - it did not
- "I found a vulnerability in Gitify" - the fuses are a framework default, not a
  vulnerability, and the maintainer's own PR describes them the same way

The difference between the first sentence and the other three is the difference
between a claim that gets you hired and a claim that gets you caught.
