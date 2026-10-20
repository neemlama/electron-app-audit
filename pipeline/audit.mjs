#!/usr/bin/env node
// Electron App Audit pipeline.
//
//   node pipeline/audit.mjs <path-to-electron-app> [--out reports/<slug>] [--json]
//
// The path can be an extracted app directory (resources/app or app.asar unpacked)
// or an .asar file, which is unpacked into targets/ first.
//
// Every finding carries a confidence level. We never report "confirmed" for a value
// we could not test, because an unverified finding destroys client trust faster than
// a missed one costs money.

import * as fs from "node:fs/promises"
import * as fsSync from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"
import {
  SECRET_PATTERNS,
  TELEMETRY_SDKS,
  SENSITIVE_FILENAMES,
  TEST_FILE,
  looksLikeRealSecret,
  entropy,
} from "./lib/patterns.mjs"

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(__dirname, "..")

// -- tuning ------------------------------------------------------------
const MAX_FILE_BYTES = 8 * 1024 * 1024 // skip anything larger; secrets are never this big
const SCAN_EXTENSIONS = new Set([
  ".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx", ".json", ".html", ".css",
  ".yml", ".yaml", ".env", ".txt", ".xml", ".sh", ".ps1", ".bat",
])
const SKIP_DIRS = new Set([".git", "__pycache__"])
const CONCURRENCY = 32

const argv = process.argv.slice(2)
const targetArg = argv.find((a) => !a.startsWith("--"))
const outIndex = argv.indexOf("--out")
const outDir = outIndex >= 0 ? argv[outIndex + 1] : null
const asJson = argv.includes("--json")

if (!targetArg) {
  console.error("usage: node pipeline/audit.mjs <path-to-electron-app> [--out reports/<slug>] [--json]")
  process.exit(1)
}

const rel = (base, p) => path.relative(base, p).replace(/\\/g, "/")

/**
 * Strip JS/TS comments before pulling URLs out.
 *
 * Bundled dev builds are full of JSDoc with documentation links. Without this,
 * react.dev and en.wikipedia.org outrank a client's actual API hosts and the
 * report becomes actively misleading.
 *
 * Conservative: a line comment only starts at "//" not preceded by ":", which
 * keeps http:// intact.
 */
function stripComments(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'`\\])\/\/[^\n\r]*/g, "$1")
}

// Documentation and infrastructure references. Never runtime egress, so they are
// excluded from the endpoint inventory rather than shown to a client as if they were.
const NON_EGRESS = new Set([
  "react.dev", "reactjs.org", "reactrouter.com", "stackoverflow.com", "en.wikipedia.org",
  "ecma-international.org", "www.ecma-international.org", "bugs.webkit.org", "lodash.com",
  "underscorejs.org", "jquery.org", "js.foundation", "mathiasbynens.be", "mths.be",
  "html.spec.whatwg.org", "datatracker.ietf.org", "tools.ietf.org", "www.yaml.org", "yaml.org",
  "nodejs.org", "electronjs.org", "www.electron.build", "docs.aws.amazon.com", "aws.amazon.com",
  "docs.microsoft.com", "developer.mozilla.org", "help.github.com", "docs.github.com",
  "docs.gitlab.com", "github.io", "semver.org", "opensource.org", "libraries.io",
])

// -- helpers -----------------------------------------------------------
async function mapLimit(items, limit, fn) {
  const out = new Array(items.length)
  let i = 0
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (i < items.length) {
        const idx = i++
        try {
          out[idx] = await fn(items[idx], idx)
        } catch {
          out[idx] = null
        }
      }
    }),
  )
  return out
}

async function walk(dir, acc = []) {
  let entries
  try {
    entries = await fs.readdir(dir, { withFileTypes: true })
  } catch {
    return acc
  }
  for (const e of entries) {
    if (SKIP_DIRS.has(e.name)) continue
    const full = path.join(dir, e.name)
    if (e.isDirectory()) await walk(full, acc)
    else if (e.isFile()) acc.push(full)
  }
  return acc
}

function mask(v) {
  const s = String(v)
  if (s.length <= 12) return s.slice(0, 3) + "[redacted]"
  return `${s.slice(0, 6)}[redacted]${s.slice(-4)}`
}

function placeholderLike(v) {
  return /^(x{4,}|a{4,}|b{4,}|\.{3,}|<[^>]*>|\$\{[^}]+\}|\{\{[^}]+\}\})/i.test(String(v))
}

/**
 * Minified bundles pack thousands of tokens onto few long lines. Long runs of
 * random-looking identifier characters then match credential shapes by chance -
 * two "PayPal tokens" in the stashbase audit were exactly that.
 *
 * Real credentials are high-entropy random strings. Coincidental matches in
 * jumbled code are not, so in minified files we hold matches to a higher entropy
 * floor rather than discarding the file and losing genuine leaks.
 */
function isMinified(text) {
  const lines = text.split("\n")
  if (lines.length > 200) return false
  const longest = lines.reduce((m, l) => Math.max(m, l.length), 0)
  const avg = text.length / lines.length
  return longest > 2000 || avg > 300
}

const MINIFIED_ENTROPY_FLOOR = 4.5

// -- step 1: resolve target --------------------------------------------
async function resolveTarget(input) {
  const abs = path.resolve(input)
  const stat = await fs.stat(abs)

  if (stat.isDirectory()) {
    // Specific locations first, the directory itself last. `abs` must not be
    // tried first or it always wins and we never reach the nested asar.
    // macOS keeps the payload under Contents/Resources, Windows and Linux do not.
    for (const nested of [
      path.join(abs, "resources", "app.asar"),
      path.join(abs, "Contents", "Resources", "app.asar"),
    ]) {
      if (fsSync.existsSync(nested)) return resolveTarget(nested)
    }

    for (const c of [path.join(abs, "resources", "app"), path.join(abs, "app")]) {
      try {
        if ((await fs.stat(c)).isDirectory()) {
          return { root: c, installRoot: abs, artifact: path.relative(abs, c) || "." }
        }
      } catch {}
    }
    return { root: abs, installRoot: abs, artifact: "." }
  }

  if (abs.endsWith(".asar")) {
    // Key the unpack directory on the source path so two builds with the same
    // basename (app.asar everywhere) never collide and silently reuse stale files.
    const { createHash } = await import("node:crypto")
    const key = createHash("sha1").update(abs).digest("hex").slice(0, 8)
    const dest = path.join(ROOT, "targets", `${path.basename(abs, ".asar")}-${key}-unpacked`)
    let asar
    try {
      asar = await import("@electron/asar")
    } catch {
      console.error("@electron/asar is not installed. Run: npm install")
      process.exit(2)
    }
    if (!fsSync.existsSync(dest)) await asar.extractAll(abs, dest)
    // The fuse binary is the platform executable, which lives two levels up from
    // app.asar (app root / resources / app.asar), not inside the unpacked tree.
    // On macOS that lands on Contents/, so step out to the .app bundle itself.
    let installRoot = path.dirname(path.dirname(abs))
    if (path.basename(installRoot).toLowerCase() === "contents") installRoot = path.dirname(installRoot)
    return {
      root: dest,
      installRoot,
      artifact: path.relative(installRoot, abs),
    }
  }

  const asar = path.join(abs, "resources", "app.asar")
  if (fsSync.existsSync(asar)) return resolveTarget(asar)

  console.error(`unrecognised target: ${abs}`)
  process.exit(1)
}

// -- step 1b: what to call this app in the report -----------------------
// A report is read by a client, not by us. "# Electron App Audit - app
// (StashBase-app)" was the name inside app.asar plus our scratch directory;
// neither means anything outside this machine. Prefer what the user sees on
// their desktop: the shipped binary's name.
const GENERIC_NAMES = new Set(["app", "electron", "application", "main", "desktop", "index"])

function tidyName(s) {
  return String(s ?? "")
    .replace(/-unpacked$/i, "")
    .replace(/-[0-9a-f]{8}$/i, "")
    .replace(/\.app$/i, "")
    .replace(/[-_.]+/g, " ")
    .trim()
}

async function resolveIdentity(installRoot, root) {
  let pkg = null
  try {
    pkg = JSON.parse(await fs.readFile(path.join(root, "package.json"), "utf-8"))
  } catch {}

  const candidates = []

  // On macOS the bundle name is what the user sees in Finder and the Dock.
  if (/\.app$/i.test(installRoot)) candidates.push(path.basename(installRoot, path.extname(installRoot)))

  // The main executable, largest first. On Windows this is the name the user double-clicks.
  try {
    const exes = (await fs.readdir(installRoot)).filter((f) => /\.exe$/i.test(f))
    exes.sort(
      (a, b) =>
        fsSync.statSync(path.join(installRoot, b)).size - fsSync.statSync(path.join(installRoot, a)).size,
    )
    if (exes[0]) candidates.push(path.basename(exes[0], path.extname(exes[0])))
  } catch {}

  if (pkg?.productName) candidates.push(pkg.productName)
  if (pkg?.name && !GENERIC_NAMES.has(String(pkg.name).toLowerCase())) candidates.push(pkg.name)
  candidates.push(tidyName(path.basename(installRoot)))

  const name =
    candidates.map(tidyName).find((c) => c && !GENERIC_NAMES.has(c.toLowerCase())) ?? "Unknown app"
  const version = typeof pkg?.version === "string" ? pkg.version : null
  const label = version ? `${name} ${version}` : name
  const slug = label
    .toLowerCase()
    .replace(/[^a-z0-9.]+/g, "-")
    .replace(/^-+|-+$/g, "")

  return { name, version, label, slug }
}

function platformOf(installRoot) {
  if (/\.app$/i.test(installRoot)) return "macOS"
  try {
    const entries = fsSync.readdirSync(installRoot)
    if (entries.some((f) => /\.exe$/i.test(f))) return "Windows"
    if (entries.some((f) => /\.app$/i.test(f))) return "macOS"
  } catch {}
  return null
}

function describeArtifact(installRoot, artifact) {
  // Say what is actually known. An extracted asar install has a platform and a
  // location; a bare application directory may have neither.
  const platform = platformOf(installRoot)
  const where = artifact && artifact !== "." ? String(artifact).replace(/\\/g, "/") : null
  if (where) return platform ? `${platform} install, ${where}` : where
  return platform ? `${platform} application directory` : "application directory"
}

// -- step 2: electron fuses --------------------------------------------
// Wire format (verified against @electron/fuses source):
//   sentinel | version byte | length byte | `length` ASCII state bytes
// Each state byte is '0' disabled (48), '1' enabled (49), 'r' removed (114),
// 'i' inherit (144). It is NOT a bit-packed bytefield, which is the obvious
// wrong assumption and silently misreads most builds.
const FUSE_SENTINEL = "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
const FUSE_NAMES = [
  "run_as_node",
  "enable_cookie_encryption",
  "enable_node_options_env",
  "enable_node_cli_inspect_args",
  "enable_embedded_asar_integrity",
  "only_load_app_from_asar",
  "load_browser_v8_snapshot",
  "grant_file_protocol_extra_privileges",
  "wasm_trap_handlers",
]
const FUSE_STATE = { 48: "disabled", 49: "enabled", 114: "removed", 144: "inherit" }
const RISKY_FUSES = new Set(["run_as_node", "enable_node_options_env", "enable_node_cli_inspect_args"])

/**
 * Find the Electron main executable inside an install root.
 *
 * Deliberately does NOT walk to the parent directory. For a .app bundle the
 * parent is the audit operator's scratch folder, and an earlier version picked
 * the largest installer there - which produced a macOS report that named a
 * different app's Windows installer. Wrong identification is worse than no
 * identification, so this returns null instead of guessing.
 */
async function findMainBinary(appRoot) {
  // macOS: @electron/fuses writes the wire into the Electron Framework binary,
  // not the ~100 KB launcher stub in Contents/MacOS. Reading the stub reports
  // "no sentinel" on a build that really does have a fuse wire.
  if (/\.app$/i.test(appRoot)) {
    const fw = path.join(appRoot, "Contents", "Frameworks", "Electron Framework.framework")
    for (const rel of [path.join("Versions", "A", "Electron Framework"), "Electron Framework"]) {
      const full = path.join(fw, rel)
      try {
        const st = await fs.stat(full)
        return { full, name: "Electron Framework", size: st.size }
      } catch {}
    }
    // Unusual bundle: fall back to the launcher so the report can still say
    // which file it looked at.
    const macos = path.join(appRoot, "Contents", "MacOS")
    try {
      const entries = (await fs.readdir(macos, { withFileTypes: true })).filter((e) => e.isFile())
      if (!entries.length) return null
      const sized = await Promise.all(
        entries.map(async (e) => {
          const full = path.join(macos, e.name)
          return { full, name: e.name, size: (await fs.stat(full)).size }
        }),
      )
      sized.sort((a, b) => b.size - a.size)
      return sized[0]
    } catch {
      return null
    }
  }

  // Windows: the largest .exe directly in the install root.
  const found = []
  try {
    for (const e of await fs.readdir(appRoot, { withFileTypes: true })) {
      if (!e.isFile() || !/\.exe$/i.test(e.name)) continue
      const full = path.join(appRoot, e.name)
      found.push({ full, name: e.name, size: (await fs.stat(full)).size })
    }
  } catch {}
  if (!found.length) return null
  found.sort((a, b) => b.size - a.size)
  return found[0]
}

async function readFuses(appRoot) {
  const exe = await findMainBinary(appRoot)
  if (!exe) {
    return {
      available: false,
      reason: `no Electron executable found in ${path.basename(appRoot)}`,
    }
  }

  let buf
  try {
    buf = await fs.readFile(exe.full)
  } catch (e) {
    return { available: false, reason: `could not read ${exe.name}: ${e.message}` }
  }
  const idx = buf.indexOf(Buffer.from(FUSE_SENTINEL, "utf-8"))
  if (idx < 0) return { available: false, reason: `no fuse sentinel in ${exe.name} (not an Electron app, or fuses were never written)` }

  const base = idx + FUSE_SENTINEL.length
  const version = buf[base]
  const length = buf[base + 1]
  const fuses = []
  for (let i = 0; i < length && i < FUSE_NAMES.length; i++) {
    fuses.push({ name: FUSE_NAMES[i], state: FUSE_STATE[buf[base + 2 + i]] ?? `unknown(${buf[base + 2 + i]})` })
  }

  return {
    available: true,
    binary: exe.name,
    version,
    fuseCount: length,
    fuses,
    risky: fuses.filter((f) => f.state === "enabled" && RISKY_FUSES.has(f.name)),
    unconfigured: version === 1,
  }
}

// -- step 3: scan -------------------------------------------------------
async function scanFiles(files, root) {
  const findings = []
  const urls = new Map()
  const telemetry = new Set()
  const sourceMaps = []
  const devBundles = []
  let autoUpdater = false
  let scanned = 0
  let skippedLarge = 0
  let testFilesSkipped = 0

  await mapLimit(files, CONCURRENCY, async (file) => {
    let st
    try {
      st = await fs.stat(file)
    } catch {
      return
    }
    if (st.size > MAX_FILE_BYTES) {
      skippedLarge++
      return
    }
    const ext = path.extname(file).toLowerCase()
    const base = path.basename(file)
    const relPath = rel(root, file)
    const isSensitiveName = SENSITIVE_FILENAMES.some((s) => s.pattern.test(relPath))

    if (!SCAN_EXTENSIONS.has(ext) && !isSensitiveName && !base.startsWith(".env") && ext !== ".map") return

    let text
    try {
      text = await fs.readFile(file, "utf-8")
    } catch {
      return
    }
    // A NUL in the first block means binary, not source.
    if (text.indexOf("\0") >= 0 && ext !== ".map") return
    scanned++

    // -- structural signals -------------------------------------------
    if (ext === ".map") sourceMaps.push({ file: relPath, size: st.size })
    if (/\.(development|dev)\.(js|mjs|cjs)$/i.test(base)) devBundles.push({ file: relPath, size: st.size })
    if (/node_modules[\\/](electron-updater|auto-updater)[\\/]/.test(relPath)) autoUpdater = true

    // -- credentials -------------------------------------------------
    // Test files ship fake credentials deliberately. Skipping them is not a
    // trade-off: reporting them guarantees noise.
    const isTestFile = TEST_FILE.test(relPath)
    if (isTestFile) testFilesSkipped++
    const minified = !isTestFile && isMinified(text)

    if (!isTestFile) {
      for (const p of SECRET_PATTERNS) {
        if (p.fileMatch && !p.fileMatch.test(relPath)) continue
        const flags = p.regex.flags.includes("g") ? p.regex.flags : p.regex.flags + "g"
        const re = new RegExp(p.regex.source, flags)
        let m
        let guard = 0
        while ((m = re.exec(text)) !== null && guard++ < 50) {
          const value = m[1] ?? m[0]
          if (p.notPlaceholder && value.length > 4000) continue

          if (p.context) {
            const window = text.slice(Math.max(0, m.index - 300), m.index + m[0].length + 300)
            if (!p.context.test(window)) continue
          }

          const ent = entropy(String(value))
          // Minified code produces low-entropy accidental matches. Real tokens do not.
          if (minified && ent < MINIFIED_ENTROPY_FLOOR) continue

          let confidence = "needs-verification"
          if (p.informational) confidence = "informational"
          else if (!p.needsEntropyCheck && !placeholderLike(value)) confidence = "likely-valid"
          else if (p.needsEntropyCheck && !looksLikeRealSecret(value)) continue

          findings.push({
            ruleId: p.id,
            title: p.title,
            severity: p.severity,
            confidence,
            file: relPath,
            line: text.slice(0, m.index).split("\n").length,
            preview: mask(value),
            valueLength: value.length,
            entropy: Number(ent.toFixed(2)),
            inLibrary: relPath.startsWith("node_modules/"),
            note: p.note,
            informational: !!p.informational,
          })
          if (m.index === re.lastIndex) re.lastIndex++
        }
      }
    }

    for (const sdk of TELEMETRY_SDKS) {
      if (sdk.pattern.test(text)) telemetry.add(sdk.label)
    }

    // -- structural signals -------------------------------------------
    if (ext === ".map") sourceMaps.push({ file: relPath, size: st.size })
    if (/\.(development|dev)\.(js|mjs|cjs)$/i.test(base)) devBundles.push({ file: relPath, size: st.size })
    if (/node_modules[\\/](electron-updater|auto-updater)[\\/]/.test(relPath)) autoUpdater = true

    // -- endpoints -----------------------------------------------------
    if (ext !== ".map") {
      const scannable = stripComments(text)
      for (const um of scannable.matchAll(/https?:\/\/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,}/g)) {
        try {
          const host = new URL(um[0]).hostname.toLowerCase().replace(/\.$/, "")
          if (NON_EGRESS.has(host)) continue
          if (!urls.has(host)) urls.set(host, { host, count: 0, firstSeen: relPath })
          urls.get(host).count++
        } catch {}
      }
    }
  })

  return { findings, urls, telemetry: [...telemetry], sourceMaps, devBundles, autoUpdater, scanned, skippedLarge, testFilesSkipped }
}

// -- step 4: sensitive files -------------------------------------------
// Restricted to app-owned code. A library file inside node_modules that happens
// to be named preload.js is not the app's Electron preload script, and reporting
// it as one is both wrong and alarming to whoever reads the report.
async function findSensitiveFiles(files, root) {
  const hits = []
  for (const f of files) {
    const r = rel(root, f)
    if (r.startsWith("node_modules/")) continue
    for (const s of SENSITIVE_FILENAMES) {
      if (s.pattern.test(path.basename(f)) || s.pattern.test(r)) {
        hits.push({ file: r, label: s.label, why: s.why, size: (await fs.stat(f)).size })
        break
      }
    }
  }
  return hits
}

// -- step 5: report -----------------------------------------------------
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 }

function buildReport(meta, scan, sensitive, fuses) {
  const findings = [...scan.findings].sort(
    (a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.file.localeCompare(b.file),
  )
  const bySeverity = {}
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1

  const external = [...scan.urls.values()].sort((a, b) => b.count - a.count)
  const mapBytes = scan.sourceMaps.reduce((n, m) => n + m.size, 0)

  return {
    meta: {
      ...meta,
      generatedAt: new Date().toISOString(),
      filesScanned: scan.scanned,
      filesSkippedLarge: scan.skippedLarge,
      totals: {
        findings: findings.length,
        urls: external.length,
        telemetry: scan.telemetry.length,
        sourceMaps: scan.sourceMaps.length,
        devBundles: scan.devBundles.length,
        autoUpdater: scan.autoUpdater,
        testFilesSkipped: scan.testFilesSkipped,
        libraryFindings: findings.filter((f) => f.inLibrary).length,
      },
      bySeverity,
    },
    findings,
    sensitiveFiles: sensitive,
    fuses,
    externalHosts: external.slice(0, 40),
    telemetry: scan.telemetry,
    sourceMaps: { count: scan.sourceMaps.length, totalBytes: mapBytes, sample: scan.sourceMaps.slice(0, 10) },
    devBundles: { count: scan.devBundles.length, sample: scan.devBundles.slice(0, 10) },
  }
}

function renderMarkdown(r) {
  const L = []
  const sev = r.meta.bySeverity
  const crit = sev.critical ?? 0
  const high = sev.high ?? 0

  L.push(`# Electron App Audit - ${r.meta.label}`, "")
  L.push(`- **Target:** ${r.meta.target}`)
  L.push(`- **Generated:** ${r.meta.generatedAt}`)
  L.push(`- **Files scanned:** ${r.meta.filesScanned}${r.meta.filesSkippedLarge ? ` (${r.meta.filesSkippedLarge} over 8 MB skipped)` : ""}`)
  L.push(`- **Credential findings:** ${r.meta.totals.findings}${Object.keys(sev).length ? ` (${Object.entries(sev).map(([k, v]) => `${v} ${k}`).join(", ")})` : ""}`)
  L.push("")

  L.push("## How to read this report", "")
  L.push("Findings carry a confidence level:", "")
  L.push("| Level | Meaning |")
  L.push("| --- | --- |")
  L.push("| `likely-valid` | Shape matches a known credential format and is not a placeholder. Not yet tested against the provider. |")
  L.push("| `needs-verification` | Flagged for review. Requires a functional test before it counts as a breach. |")
  L.push("| `informational` | Present by design. Listed for inventory, not as a defect. |")
  L.push("")
  L.push("Secret values are redacted. We report location, shape and classification, never a usable credential.")
  L.push("")
  L.push(
    `Test files (${r.meta.totals.testFilesSkipped}) are excluded from credential scanning: they ship fake credentials on purpose to test their own suites. Findings inside third-party libraries are marked and are more likely to belong to the library's author than to the app being audited.`,
  )
  L.push("")

  L.push("## Executive summary", "")
  const lines = []
  if (crit) lines.push(`${crit} critical and ${high} high severity credential item(s) require attention. A critical item is a value that would grant direct access to a third-party service if it is live.`)
  else if (high) lines.push(`${high} high severity credential item(s) require attention. No critical credential-shaped values were found.`)
  else lines.push("No critical or high severity credential-shaped values were found in the scanned bundle.")

  if (r.meta.totals.sourceMaps) lines.push(`${r.meta.totals.sourceMaps} source map file(s) ship in the build (${(r.meta.totals.sourceMaps ? (r.sourceMaps.totalBytes / 1048576).toFixed(1) : 0)} MB), which lets anyone reconstruct near-original source.`)
  if (r.meta.totals.devBundles) lines.push(`${r.meta.totals.devBundles} development-mode bundle(s) ship in what should be a production build.`)
  if (r.telemetry.length) lines.push(`Telemetry/analytics SDKs present: ${r.telemetry.join(", ")}.`)
  if (r.fuses?.available && r.fuses.risky?.length) lines.push(`${r.fuses.risky.length} Electron hardening switch(es) left at defaults (${r.fuses.risky.map((f) => f.name).join(", ")}).`)

  for (const l of lines) L.push(`- ${l}`)
  L.push("")
  if (!crit && !high) L.push("Read **Coverage and limits** before treating a clean credential result as a clean bill of health.")
  L.push("")

  L.push("## Credential findings", "")
  if (r.findings.length === 0) {
    L.push("_None._")
  } else {
    const groups = {}
    for (const f of r.findings) (groups[f.title] ??= []).push(f)
    for (const [title, items] of Object.entries(groups)) {
      L.push(`### ${title}`)
      L.push("")
      L.push(`Severity: **${items[0].severity}** | Confidence: **${items[0].confidence}** | Occurrences: ${items.length}`)
      if (items[0].note) {
        L.push("")
        L.push(`> ${items[0].note}`)
      }
      L.push("")
      L.push("| File | Line | Redacted value | Entropy |")
      L.push("| --- | --- | --- | --- |")
      for (const f of items.slice(0, 25)) L.push(`| \`${f.file}\` | ${f.line} | \`${f.preview}\` | ${f.entropy} |`)
      if (items.length > 25) L.push(`| and ${items.length - 25} more | | | |`)
      L.push("")
    }
  }

  L.push("## Build and hardening observations", "")
  if (r.meta.totals.sourceMaps) {
    L.push(`### Source maps shipped in the build (${r.meta.totals.sourceMaps} files, ${(r.sourceMaps.totalBytes / 1048576).toFixed(1)} MB)`)
    L.push("")
    L.push("Source maps let anyone reconstruct near-original source from the shipped binary. This is not a secret leak, but it removes obfuscation as a defence and makes every other finding easier to exploit.")
    L.push("")
    for (const m of r.sourceMaps.sample) L.push(`- \`${m.file}\` (${(m.size / 1024).toFixed(0)} KB)`)
    L.push("")
  }
  if (r.meta.totals.devBundles) {
    L.push(`### Development bundles in a production build (${r.meta.totals.devBundles})`)
    L.push("")
    L.push("These ship React/framework development builds. They are larger, contain verbose warnings and error text, and can include code paths that production builds omit.")
    L.push("")
    for (const d of r.devBundles.sample) L.push(`- \`${d.file}\` (${(d.size / 1024).toFixed(0)} KB)`)
    L.push("")
  }
  if (r.meta.totals.autoUpdater) {
    L.push("### Auto-updater present")
    L.push("")
    L.push("The bundle includes `electron-updater`. The update channel is a high-value target: compromise the update feed or the signing key and you control what every user runs next. Confirm updates are signature-verified and served over HTTPS.")
    L.push("")
  }
  if (r.telemetry.length) {
    L.push("### Telemetry and analytics inventory")
    L.push("")
    L.push("Present in the shipped bundle. Inventory, not a defect:")
    L.push("")
    for (const t of r.telemetry) L.push(`- ${t}`)
    L.push("")
  }

  if (r.sensitiveFiles.length) {
    L.push("## Security-relevant files in app code", "")
    L.push("Third-party library internals are excluded; these are the app's own files.")
    L.push("")
    L.push("| File | Category | Why it matters |")
    L.push("| --- | --- | --- |")
    for (const s of r.sensitiveFiles) L.push(`| \`${s.file}\` | ${s.label} | ${s.why} |`)
    L.push("")
  }

  if (r.fuses?.available) {
    L.push("## Electron fuses", "")
    L.push(`Binary: \`${r.fuses.binary}\` | fuse version ${r.fuses.version}`)
    L.push("")
    L.push("| Fuse | State |")
    L.push("| --- | --- |")
    for (const f of r.fuses.fuses) {
      const mark = f.state === "enabled" && RISKY_FUSES.has(f.name) ? "**enabled (risk)**" : f.state
      L.push(`| \`${f.name}\` | ${mark} |`)
    }
    L.push("")

    // Prose must follow the data. A static paragraph contradicts the table on a
    // hardened build and makes the report read as broken.
    const riskyOn = r.fuses.risky.map((f) => f.name)
    if (riskyOn.length) {
      const notes = []
      if (riskyOn.includes("run_as_node"))
        notes.push(
          "`run_as_node` enabled means `ELECTRON_RUN_AS_NODE=1 <app>` starts the binary as a plain Node runtime, dropping the Electron sandbox.",
        )
      if (riskyOn.includes("enable_node_options_env"))
        notes.push(
          "`enable_node_options_env` enabled means `NODE_OPTIONS` is honoured, so a controlled launch environment can inject `--require` and load code at startup.",
        )
      if (riskyOn.includes("enable_node_cli_inspect_args"))
        notes.push(
          "`enable_node_cli_inspect_args` enabled means a launch argument can attach the Node inspector to the renderer process.",
        )
      for (const n of notes) L.push(`${n} `)
      L.push("")
      if (r.fuses.unconfigured) {
        L.push(
          `Fuse wire version ${r.fuses.version} with ${r.fuses.fuseCount} entries and no explicit configuration is consistent with \`@electron/fuses\` never having been run against this build, which leaves every switch at its Electron framework default rather than a deliberate choice.`,
        )
        L.push("")
      }
    } else {
      L.push("No risk-relevant fuse is enabled. Every switch that would let Node.js be reached from a launch argument is closed.")
      L.push("")
    }
  } else if (r.fuses) {
    L.push("## Electron fuses", "")
    L.push(`_Not readable: ${r.fuses.reason}._`)
    L.push("")
    L.push("This is the one hardening check that genuinely requires the platform binary. Re-run against the Windows or macOS executable to close this gap.")
    L.push("")
  }

  if (r.externalHosts.length) {
    L.push("## External network endpoints", "")
    L.push("Documentation and comment URLs are filtered out. What remains are hosts referenced by executable code.")
    L.push("")
    L.push("| Host | References | First seen in |")
    L.push("| --- | --- | --- |")
    for (const h of r.externalHosts) L.push(`| ${h.host} | ${h.count} | \`${h.firstSeen}\` |`)
    L.push("")
  }

  L.push("## Coverage and limits", "")
  L.push("What this audit did **not** cover, stated explicitly:")
  L.push("")
  L.push(`- Files larger than 8 MB were skipped (${r.meta.filesSkippedLarge} file(s)).`)
  L.push("- Runtime behaviour. Nothing was executed; only the shipped bundle was read.")
  L.push("- Native binaries were not decompiled. Strings inside bundled `.node`/`.dll`/`.exe` modules are out of scope for this pass.")
  L.push("- Obfuscated or dynamically assembled secrets may be missed.")
  L.push("- No credential was tested against its provider. A `likely-valid` shape is not proof of a live key.")
  L.push("- The application's own backend, once deployed, is outside this artifact review.")
  if (!r.fuses?.available) L.push("- Electron fuses were not readable from this build (see above).")
  L.push("")
  return L.join("\n")
}

// -- run ----------------------------------------------------------------
// Reports are published in portfolios, so nothing about the operator's machine
// may reach a deliverable. The header carries an app identity and an artifact
// description instead of a filesystem path.
const { root, installRoot, artifact } = await resolveTarget(targetArg)
const identity = await resolveIdentity(installRoot ?? root, root)
console.error(`[audit] target: ${root}`)
console.error(`[audit] identified as: ${identity.label}`)
console.error(`[audit] install root (for fuses): ${installRoot ?? root}`)

const files = await walk(root)
console.error(`[audit] files discovered: ${files.length}`)

const fuses = await readFuses(installRoot ?? root)
const sensitive = await findSensitiveFiles(files, root)
const scan = await scanFiles(files, root)
console.error(`[audit] scanned ${scan.scanned} files | ${scan.findings.length} credential findings`)

const report = buildReport(
  { label: identity.label, target: describeArtifact(installRoot ?? root, artifact) },
  scan,
  sensitive,
  fuses,
)

const slug = (outDir ?? path.join(ROOT, "reports", identity.slug)).replace(/\\/g, "/")
const outBase = path.isAbsolute(slug) ? slug : path.resolve(ROOT, slug)
await fs.mkdir(path.dirname(outBase), { recursive: true })

await fs.writeFile(`${outBase}.json`, JSON.stringify(report, null, 2), "utf-8")
await fs.writeFile(`${outBase}.md`, renderMarkdown(report), "utf-8")

console.error(`[audit] report written: ${outBase}.md`)
if (asJson) console.log(JSON.stringify(report, null, 2))
else {
  const s = report.meta.bySeverity
  console.log(`Credentials: ${report.meta.totals.findings}${Object.keys(s).length ? ` (${Object.entries(s).map(([k, v]) => `${v} ${k}`).join(", ")})` : ""}`)
  console.log(`Structural:   ${report.meta.totals.sourceMaps} source maps, ${report.meta.totals.devBundles} dev bundles, updater=${report.meta.totals.autoUpdater}`)
  console.log(`Telemetry:    ${report.telemetry.join(", ") || "none"}`)
  console.log(`Endpoints:    ${report.meta.totals.urls} hosts`)
  console.log(`Report:       ${outBase}.md`)
}
