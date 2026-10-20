#!/usr/bin/env node
// Self-test: proves the detector fires on known-bad input and stays quiet on
// known-good input. Without this, a clean report is meaningless.

import * as fs from "node:fs/promises"
import * as fsSync from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"
import { execFileSync } from "node:child_process"
import { SECRET_PATTERNS, looksLikeRealSecret, TEST_FILE, entropy } from "./lib/patterns.mjs"

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(__dirname, "..")
const FIXTURE = path.join(ROOT, "targets", "_selftest-fixture", "resources", "app")

// Each planted secret is a structurally valid but non-functional value.
// They are synthetic and grant access to nothing.
const MUST_FIND = [
  ["aws", "const key = 'AKIAIOSFODNN7EXAMPLE'"],
  ["gcp", `const g = "AIzaSyD-1234567890abcdefghijklmnopqrstu"`],
  ["stripe", `stripe = "sk_live_51H8xKzLmNoPqRsTuVwXyZ0123"`],
  ["github", `const t = "ghp_16CharactersOfNoiseAbCdEfGhIjKlMnOpQrStUvWxYz"`],
  ["slack", `const slack = "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"`],
  ["anthropic", `const ai = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij"`],
  ["openai", `const openaiKey = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ"`],
  ["privatekey", `const k = "-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDLtVkOJ0dRHhMz\n-----END RSA PRIVATE KEY-----"`],
  ["basicauth", `const upstream = "https://admin:hunter2secret@internal.corp/api"`],
  ["posthog", `posthog.init("phc_abcdefghijklmnopqrstuvwx", {})`],
  ["webhook", `const hook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"`],
]

// These must NOT be reported as secrets.
const MUST_NOT_FLAG = [
  ["placeholder-x", `const apiKey = "xxxxxxxxxxxxxxxxxxxx"`],
  ["template-literal", `const apiKey = "\${process.env.API_KEY}"`],
  ["angle-placeholder", `const apiKey = "<your-api-key-here>"`],
  ["env-reference", `const apiKey = process.env.API_KEY`],
  ["prose", `const description = "this is a normal english sentence here"`],
  ["url-only", `const endpoint = "https://api.example.com/v1/thing"`],
  ["public-sentry-dsn", `Sentry.init({ dsn: "https://abc123def456abc123def456@o1.ingest.sentry.io/1234" })`],
  // jose's real line: a format check, not key material.
  ["pem-header-only", `if (typeof pkcs8 !== 'string' || pkcs8.indexOf('-----BEGIN PRIVATE KEY-----') !== 0) {}`],
]

let pass = 0
let fail = 0
const check = (ok, label, detail = "") => {
  if (ok) {
    pass++
    console.log(`  PASS  ${label}`)
  } else {
    fail++
    console.log(`  FAIL  ${label} ${detail}`)
  }
}

console.log("\n1. pattern-level detection")
for (const [label, line] of MUST_FIND) {
  const hit = SECRET_PATTERNS.some((p) => new RegExp(p.regex.source, p.regex.flags).test(line))
  check(hit, `detects ${label}`, `-> no rule matched: ${line.slice(0, 50)}`)
}
console.log("\n2. false-positive resistance")
for (const [label, line] of MUST_NOT_FLAG) {
  // Sentry DSNs and hooks are intentionally informational; exclude them here.
  const value = line.match(/["'`]([^"'`]+)["'`]/)?.[1] ?? ""
  const hit = SECRET_PATTERNS.some((p) => {
    if (p.informational) return false
    const m = new RegExp(p.regex.source, p.regex.flags).exec(line)
    return m && looksLikeRealSecret(m[1] ?? m[0])
  })
  check(!hit, `ignores ${label}`, `-> falsely matched on "${value}"`)
}

console.log("\n3. end-to-end pipeline run")
await fs.rm(path.join(ROOT, "targets", "_selftest-fixture"), { recursive: true, force: true })
await fs.mkdir(FIXTURE, { recursive: true })
await fs.writeFile(path.join(FIXTURE, "main.js"), MUST_FIND.map(([, l]) => l).join("\n"), "utf-8")
await fs.writeFile(path.join(FIXTURE, "clean.js"), MUST_NOT_FLAG.map(([, l]) => l).join("\n"), "utf-8")
await fs.writeFile(path.join(FIXTURE, ".env.production"), "DATABASE_URL=postgres://u:p@host/db\nAPI_KEY=abcdef1234567890abcdef1234567890\n", "utf-8")

const outBase = path.join(ROOT, "reports", "_selftest")
try {
  execFileSync(process.execPath, [path.join(ROOT, "pipeline", "audit.mjs"), path.join(ROOT, "targets", "_selftest-fixture"), "--out", outBase], { stdio: "pipe" })
} catch (e) {
  console.log(`  FAIL  pipeline exited: ${e.message}`)
  process.exit(1)
}

const report = JSON.parse(await fs.readFile(`${outBase}.json`, "utf-8"))
const ids = new Set(report.findings.map((f) => f.ruleId))
check(ids.has("aws-access-key-id"), "pipeline reports AWS key")
check(ids.has("private-key-block"), "pipeline reports private key")
check(ids.has("posthog-key"), "pipeline reports PostHog key")
check(ids.has("dotenv-file"), "pipeline reports bundled .env")
check(!report.findings.some((f) => f.file === "clean.js" && !f.informational), "clean.js produces no secret findings")
check(report.meta.filesScanned >= 3, "scanned the expected file count")
check(report.sensitiveFiles.some((s) => /\.env/.test(s.file)), "flags .env as security-relevant")

const criticals = report.findings.filter((f) => f.severity === "critical").length
check(criticals >= 5, "assigns critical severity to credential items", `-> got ${criticals}`)
check(report.meta.filesSkippedLarge === 0, "no unexpected skips")

await fs.rm(path.join(ROOT, "targets", "_selftest-fixture"), { recursive: true, force: true })
await fs.rm(`${outBase}.json`, { force: true }).catch(() => {})
await fs.rm(`${outBase}.md`, { force: true }).catch(() => {})

console.log("\n4. electron fuse wire decoding")
// The wire is NOT a bit-packed bytefield. It is:
//   sentinel | version byte | LENGTH byte | N ASCII state bytes ('0'/'1')
// A reader that assumes bit-packing can return the right answer by coincidence
// on one binary and be wrong on every other one, so it is pinned here.
{
  const SENT = Buffer.from("dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX", "utf-8")
  const NAMES = [
    "run_as_node", "enable_cookie_encryption", "enable_node_options_env",
    "enable_node_cli_inspect_args", "enable_embedded_asar_integrity",
    "only_load_app_from_asar", "load_browser_v8_snapshot",
    "grant_file_protocol_extra_privileges", "wasm_trap_handlers",
  ]

  // Section 3 removes the fixture, so rebuild a minimal app root here.
  await fs.mkdir(FIXTURE, { recursive: true })
  await fs.writeFile(path.join(FIXTURE, "main.js"), "module.exports = {}\n", "utf-8")

  // Build a fake Windows install. The .exe sits at the install root as a sibling
  // of resources/, which is where a real packaged app puts it.
  const installRoot = path.join(ROOT, "targets", "_selftest-fixture")
  const states = ["1", "0", "1", "1", "0", "0", "0", "1", "1"] // gitify v7.9.0 as shipped
  const exe = path.join(installRoot, "Fixture.exe")
  const head = Buffer.alloc(2048, 0x41)
  const wire = Buffer.from([1, states.length, ...states.map((s) => (s === "1" ? 49 : 48))])
  fsSync.writeFileSync(exe, Buffer.concat([head, SENT, wire, Buffer.alloc(2048, 0x42)]))

  const outBase2 = path.join(ROOT, "reports", "_selftest-fuses")
  try {
    execFileSync(process.execPath, [path.join(ROOT, "pipeline", "audit.mjs"), path.join(ROOT, "targets", "_selftest-fixture"), "--out", outBase2], { stdio: "pipe" })
  } catch (e) {
    console.log(`  FAIL  fuse run exited: ${e.message}`)
    process.exit(1)
  }
  const r2 = JSON.parse(await fs.readFile(`${outBase2}.json`, "utf-8"))

  check(r2.fuses?.available === true, "reads fuse wire from the app binary")
  check(r2.fuses?.fuseCount === 9, `decoded 9 fuse entries (got ${r2.fuses?.fuseCount})`)
  check(r2.fuses?.version === 1, "decoded fuse version 1")

  const got = Object.fromEntries((r2.fuses?.fuses ?? []).map((f) => [f.name, f.state]))
  check(got.run_as_node === "enabled", "run_as_node decodes as enabled")
  check(got.enable_cookie_encryption === "disabled", "enable_cookie_encryption decodes as disabled")
  check(got.enable_node_options_env === "enabled", "enable_node_options_env decodes as enabled")
  check(got.enable_node_cli_inspect_args === "enabled", "enable_node_cli_inspect_args decodes as enabled")
  check(got.only_load_app_from_asar === "disabled", "only_load_app_from_asar decodes as disabled")
  check(
    (r2.fuses?.risky ?? []).map((f) => f.name).join(",") === "run_as_node,enable_node_options_env,enable_node_cli_inspect_args",
    "flags exactly the three risk fuses",
  )

  // The bit-packing bug returns the right answer here by coincidence, so assert
  // a case where it cannot: length 9 with a different state pattern.
  const states2 = ["0", "1", "0", "0", "0", "1", "0", "0", "0"]
  const wire2 = Buffer.from([1, states2.length, ...states2.map((s) => (s === "1" ? 49 : 48))])
  fsSync.writeFileSync(exe, Buffer.concat([head, SENT, wire2, Buffer.alloc(2048, 0x42)]))
  execFileSync(process.execPath, [path.join(ROOT, "pipeline", "audit.mjs"), path.join(ROOT, "targets", "_selftest-fixture"), "--out", outBase2], { stdio: "pipe" })
  const r3 = JSON.parse(await fs.readFile(`${outBase2}.json`, "utf-8"))
  const got2 = Object.fromEntries((r3.fuses?.fuses ?? []).map((f) => [f.name, f.state]))
  check(got2.run_as_node === "disabled", "run_as_node disabled when the wire says so")
  check(got2.enable_cookie_encryption === "enabled", "cookie encryption enabled when the wire says so")
  check(got2.only_load_app_from_asar === "enabled", "only_load_app_from_asar enabled when the wire says so")
  check((r3.fuses?.risky ?? []).length === 0, "no risk fuses reported on a hardened wire")

  await fs.rm(`${outBase2}.json`, { force: true }).catch(() => {})
  await fs.rm(`${outBase2}.md`, { force: true }).catch(() => {})
  await fs.rm(path.join(ROOT, "targets", "_selftest-fixture"), { recursive: true, force: true }).catch(() => {})
}

// -- section 5: false-positive regressions found in a real audit --------
// Auditing stashbase v2.16.9 produced 7 credential findings, 6 of which were
// noise: library test fixtures, a bare PEM header used as a format check, and
// accidental matches inside minified SDK code. The synthetic fixtures in
// sections 1-4 were too clean to surface any of it. These lock the fixes in.

console.log("\n5. false-positive regressions (from a real audit)")

// -- 5a. test files are excluded ---------------------------------------
{
  const cases = [
    ["node_modules/zod/src/v4/mini/tests/string.test.ts", true],
    ["node_modules/zod/src/v4/classic/tests/string.test.ts", true],
    ["src/__tests__/auth.spec.js", true],
    ["test/helpers/token.ts", true],
    ["dist/server/index.mjs", false],
    ["build/main.js", false],
    ["node_modules/@anthropic-ai/claude-agent-sdk/assistant.mjs", false],
    ["node_modules/jose/dist/webapi/key/import.js", false],
  ]
  let ok = true
  for (const [p, want] of cases) {
    if (TEST_FILE.test(p) !== want) {
      console.log(`  FAIL  TEST_FILE("${p}") should be ${want}`)
      ok = false
    }
  }
  check(ok, "test file detection covers the real paths")
}

// -- 5b. a bare PEM header is not a private key ------------------------
{
  const pat = SECRET_PATTERNS.find((p) => p.id === "private-key-block")
  const re = (s) => new RegExp(pat.regex.source, pat.regex.flags).test(s)

  // What jose actually contains: a format check, not key material.
  const headerOnly =
    "if (typeof pkcs8 !== 'string' || pkcs8.indexOf('-----BEGIN PRIVATE KEY-----') !== 0)"
  check(!re(headerOnly), "bare BEGIN header is NOT reported as a private key")

  const body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDLtVkOJ0dRHhMz"
  const real = `-----BEGIN RSA PRIVATE KEY-----\n${body}\n-----END RSA PRIVATE KEY-----`
  check(re(real), "full PEM block with a body IS reported")
}

// -- 5c. minified code needs a higher entropy floor ---------------------
{
  // In the real audit the two accidental "PayPal tokens" reported from minified
  // SDK code measured 3.54 entropy, while the genuine PostHog token measured 4.91.
  // The floor sits between them. These two strings test the MECHANISM: one
  // clearly below the floor, one clearly above. They are not byte-identical to
  // the incident, because the original value was never stored unmasked.
  const accidental = "EAA" + "EAAAoBcmWb".repeat(8) + "AQBB"
  check(entropy(accidental) < 4.5, "a low-entropy accidental match sits below the floor")

  const realToken =
    "EAAAoBwQrTn0ZxPq7LkJmVh4Gd9SfN2bWyCtRv6DlKmIh8GfNbWyCtRv4DlKmIh2GfNbWyCtRv9DlKmIh"
  check(entropy(realToken) >= 4.5, "a genuine random token clears the floor")
  check(entropy(realToken) > entropy(accidental), "the two are genuinely separated")
}

// -- 5d. the live finding must NOT be lost ------------------------------
{
  const pat = SECRET_PATTERNS.find((p) => p.id === "posthog-key")
  // Synthetic on purpose. This repository will be public, so no fixture may carry
  // any part of a token that was actually observed in an audit.
  const line = '  projectToken: "phc_selftestfixture0000000000000000000000",'
  check(new RegExp(pat.regex.source, pat.regex.flags).test(line), "PostHog-shaped token still detected")
}

// -- 5e. end-to-end: same JWT, test file vs app file --------------------
// This is the actual zod situation from the stashbase audit. The identical
// credential-shaped string is noise in a test fixture and a real finding in the
// app's own code. The distinction is the file path, not the content.
{
  const JWT = 'const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.dozjgNryP4J3jVmNHl0w5N_X9aEz3kJ7YvB2c";'
  const PHK = 'const k = "-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDLtVkOJ0dRHhMz\n-----END RSA PRIVATE KEY-----";'

  const root = path.join(ROOT, "targets", "_selftest-fp")
  await fs.rm(root, { recursive: true, force: true })
  await fs.mkdir(path.join(root, "node_modules", "zod", "tests"), { recursive: true })
  await fs.mkdir(path.join(root, "node_modules", "some-lib"), { recursive: true })
  await fs.mkdir(path.join(root, "dist"), { recursive: true })
  await fs.writeFile(path.join(root, "node_modules", "zod", "tests", "string.test.ts"), `${JWT}\n${PHK}\n`, "utf-8")
  await fs.writeFile(path.join(root, "dist", "server.mjs"), `${JWT}\n`, "utf-8")
  // A non-test library file that genuinely contains a credential. Reported, but
  // marked as belonging to the library's author, not to the app being audited.
  await fs.writeFile(
    path.join(root, "node_modules", "some-lib", "index.mjs"),
    'export const key = "AKIAIOSFODNN7EXAMPLE";\n',
    "utf-8",
  )

  const outBase3 = path.join(ROOT, "reports", "_selftest-fp")
  try {
    execFileSync(process.execPath, [path.join(ROOT, "pipeline", "audit.mjs"), root, "--out", outBase3], { stdio: "pipe" })
  } catch (e) {
    console.log(`  FAIL  fp run exited: ${e.message}`)
    process.exit(1)
  }
  const r4 = JSON.parse(await fs.readFile(`${outBase3}.json`, "utf-8"))
  const files = new Set(r4.findings.map((f) => f.file))

  check(!files.has("node_modules/zod/tests/string.test.ts"), "test fixture produces NO findings")
  check(files.has("dist/server.mjs"), "identical JWT in app code IS still reported")
  check(r4.meta.totals.testFilesSkipped >= 1, "test file counted as skipped")
  check(
    r4.findings.some((f) => f.inLibrary),
    "library findings are flagged as such when they do occur",
  )

  await fs.rm(root, { recursive: true, force: true }).catch(() => {})
  await fs.rm(`${outBase3}.json`, { force: true }).catch(() => {})
  await fs.rm(`${outBase3}.md`, { force: true }).catch(() => {})
}

console.log(`\n${pass} passed, ${fail} failed\n`)
process.exit(fail ? 1 : 0)
