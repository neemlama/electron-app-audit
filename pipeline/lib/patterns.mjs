// Detection rules for Electron app audits.
// Design rule: a pattern that fires on its own proves nothing. Every rule needs
// either a high-specificity shape (AWS AKIA...) or a context keyword nearby.
// Anything we cannot verify is reported as "needs-verification", never "confirmed".

/** Placeholder text that looks like a secret but is not one. */
const PLACEHOLDER =
  /(?:x{4,}|y{4,}|z{4,}|a{4,}|b{4,}|\.{3,}|<[^>]{0,40}>|\$\{[^}]+\}|\{\{[^}]+\}\}|%[SDsd][A-Za-z]?\b|REPLACE_ME|CHANGEME|your[_-]?(?:key|token|secret|api)|example|placeholder|dummy|sample|redacted|insert[_-]?here|foo|bar|baz)/i

/**
 * Test files ship fake credentials ON PURPOSE so their own suites can verify
 * detection. Reporting them is guaranteed noise: three of seven findings in the
 * stashbase audit came from zod's fixtures.
 *
 * These are skipped for credential scanning. Structural checks still run.
 */
export const TEST_FILE =
  /(^|\/)(tests?|__tests__|__mocks__|spec|specs|fixtures|test-fixtures|e2e)(\/|$)|(\.(test|spec)\.[cm]?[jt]sx?$)|(\.test\.[a-z]+$)/i

/**
 * Real key material has a body. A bare BEGIN header is a label - libraries check
 * `str.indexOf('-----BEGIN PRIVATE KEY-----') !== 0` as a format test, and that
 * string is not a private key. Requiring base64 between BEGIN and END removes
 * that entire false-positive class.
 */
export const SECRET_PATTERNS = [
  // ── Cloud providers ────────────────────────────────────────────
  {
    id: "aws-access-key-id",
    title: "AWS Access Key ID",
    severity: "critical",
    regex: /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,
    note: "Pairs with a secret access key. Alone it is an identifier, not a login.",
  },
  {
    id: "aws-secret-access-key",
    title: "AWS Secret Access Key",
    severity: "critical",
    regex: /\baws_?secret_?access_?key\b\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    note: "40-char secret. Confirmed credential if a key ID sits nearby.",
  },
  {
    id: "gcp-api-key",
    title: "Google Cloud API Key",
    severity: "critical",
    regex: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
    note: "Unrestricted key allows billing abuse and quota theft.",
  },
  {
    id: "gcp-oauth-client-secret",
    title: "Google OAuth Client Secret",
    severity: "high",
    regex: /\bGOCSPX-[A-Za-z0-9_-]{28}\b/g,
    context: /oauth|client_secret|clientSecret/i,
  },
  {
    id: "azure-storage-key",
    title: "Azure Storage Account Key",
    severity: "critical",
    regex: /\bAccountKey\s*=\s*([A-Za-z0-9+/]{60,}={0,2})/gi,
  },

  // ── Payments ───────────────────────────────────────────────────
  {
    id: "stripe-secret-key",
    title: "Stripe Secret Key",
    severity: "critical",
    regex: /\b(sk_live_[0-9a-zA-Z]{10,})\b/g,
    note: "Live key: full control of the Stripe account.",
  },
  {
    id: "stripe-restricted-key",
    title: "Stripe Restricted Key",
    severity: "high",
    regex: /\b(rk_live_[0-9a-zA-Z]{10,})\b/g,
  },
  {
    id: "stripe-webhook-secret",
    title: "Stripe Webhook Signing Secret",
    severity: "medium",
    regex: /\bwhsec_[0-9a-zA-Z]{16,}\b/g,
    note: "Forges webhook events if leaked.",
  },
  {
    id: "paypal-token",
    title: "PayPal Access Token",
    severity: "critical",
    regex: /\b(EAA[A-Za-z0-9]{80,})\b/g,
  },

  // ── AI providers ───────────────────────────────────────────────
  {
    id: "anthropic-api-key",
    title: "Anthropic API Key",
    severity: "critical",
    regex: /\b(sk-ant-(?:api\d{2}|admin\d{2})-[A-Za-z0-9_-]{80,})\b/g,
  },
  {
    id: "openai-api-key",
    title: "OpenAI API Key",
    severity: "critical",
    regex: /\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{40,})\b/g,
    note: "Validate shape before reporting; short or structured values are often not keys.",
  },
  {
    id: "google-vertex-key",
    title: "Google GenAI / Vertex Key",
    severity: "critical",
    regex: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
  },

  // ── Developer platforms ────────────────────────────────────────
  {
    id: "github-pat",
    title: "GitHub Token",
    severity: "critical",
    regex: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/g,
  },
  {
    id: "gitlab-pat",
    title: "GitLab Token",
    severity: "critical",
    regex: /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    id: "npm-token",
    title: "npm Token",
    severity: "critical",
    regex: /\b(npm_[A-Za-z0-9]{36})\b/g,
  },
  {
    id: "slack-token",
    title: "Slack Token",
    severity: "critical",
    regex: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g,
  },
  {
    id: "slack-webhook",
    title: "Slack Incoming Webhook",
    severity: "medium",
    regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9+/]{20,}/g,
    note: "Anyone holding this can post into the channel.",
  },
  {
    id: "discord-webhook",
    title: "Discord Webhook",
    severity: "medium",
    regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{60,}/g,
  },
  {
    id: "discord-bot-token",
    title: "Discord Bot Token",
    severity: "critical",
    regex: /\b(MT[A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27})\b/g,
  },

  // ── SaaS / analytics ───────────────────────────────────────────
  {
    id: "sentry-dsn",
    title: "Sentry DSN",
    severity: "low",
    regex: /https:\/\/[a-f0-9]{16,32}@[a-z0-9.-]+\.ingest\.sentry\.io\/\d+/g,
    note: "DSNs are semi-public by design. Reported for completeness, not a breach.",
    informational: true,
  },
  {
    id: "posthog-key",
    title: "PostHog Project API Key",
    severity: "medium",
    regex: /\b(phc_[A-Za-z0-9]{20,})\b/g,
    note: "Write-only ingest key; enables event spam and cost abuse.",
  },
  {
    id: "segment-write-key",
    title: "Segment Write Key",
    severity: "low",
    regex: /\b([0-9a-z]{24})\b/g,
    context: /segment\.com|analytics/i,
    note: "Write-only by design.",
    informational: true,
  },
  {
    id: "supabase-url-key",
    title: "Supabase Service Key",
    severity: "critical",
    regex: /\b(supabase\.co\/)\b/gi,
    context: /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/,
  },
  {
    id: "firebase-database-url",
    title: "Firebase Realtime Database URL",
    severity: "low",
    regex: /https:\/\/[a-z0-9-]+\.firebaseio\.com/gi,
    note: "Security depends entirely on database rules, not the URL.",
    informational: true,
  },
  {
    id: "sendgrid-key",
    title: "SendGrid API Key",
    severity: "critical",
    regex: /\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b/g,
  },
  {
    id: "twilio-key",
    title: "Twilio API Key",
    severity: "critical",
    regex: /\b(SK[0-9a-fA-F]{32})\b/g,
    context: /twilio|AC[0-9a-f]{32}/,
  },

  // ── Cryptographic material ─────────────────────────────────────
  {
    id: "private-key-block",
    title: "Embedded Private Key",
    severity: "critical",
    // Requires a real base64 body between BEGIN and END. A header on its own is a
    // format check, not key material.
    regex:
      /-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY(?: BLOCK)?-----[\s\S]{0,120}?[A-Za-z0-9+/]{64,}={0,2}[\s\S]{0,120}?-----END\s+(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY(?: BLOCK)?-----/g,
    note: "A complete key block in a shipped client is a critical finding on its own.",
    notPlaceholder: true,
  },
  {
    id: "jwt-token",
    title: "Hardcoded JWT",
    severity: "high",
    regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    note: "If unexpired and unsigned-exempt, may grant access.",
  },
  {
    id: "basic-auth-url",
    title: "Credentials Embedded in URL",
    severity: "high",
    regex: /\bhttps?:\/\/([A-Za-z0-9._%+-]+):([^\s@/'"]{3,})@/g,
    note: "Leaks via logs, referrers and proxy records.",
  },

  // ── Generic assignment (needs a sensitive keyword nearby) ──────
  {
    id: "generic-secret-assignment",
    title: "Hardcoded Secret Assignment",
    severity: "medium",
    regex: /\b(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|pwd|bearer[_-]?token|private[_-]?token|refresh[_-]?token)\b\s*[:=]\s*["'`]([^"'`\s]{8,})["'`]/gi,
    note: "Shape only. Must be reviewed against the value before it is a real finding.",
    needsEntropyCheck: true,
  },
  {
    id: "dotenv-file",
    title: "Bundled .env File",
    severity: "high",
    regex: /^[A-Z0-9_]{2,40}\s*=\s*.+$/gm,
    fileMatch: /(^|\/)\.env(\.[\w-]+)?$/i,
    note: "A shipped .env means build-time secrets reached the client.",
  },
]

/** Analytics / telemetry SDKs worth reporting as inventory, not breach. */
export const TELEMETRY_SDKS = [
  { id: "google-analytics", label: "Google Analytics", pattern: /\b(gtag\(|google-analytics\.com|GTM-[A-Z0-9]{4,})/ },
  { id: "segment", label: "Segment", pattern: /\bsegment\.(com|io)|analytics\.load\(/ },
  { id: "mixpanel", label: "Mixpanel", pattern: /mixpanel\.(init|com)|api\.mixpanel\.com/ },
  { id: "amplitude", label: "Amplitude", pattern: /amplitude\.(getInstance|init)|api2\.amplitude\.com/ },
  { id: "posthog", label: "PostHog", pattern: /posthog\.(init|capture)|app\.posthog\.com/ },
  { id: "sentry", label: "Sentry", pattern: /@sentry\/node|Sentry\.init\(/ },
  { id: "hotjar", label: "Hotjar", pattern: /static\.hotjar\.com|hj\(/ },
  { id: "intercom", label: "Intercom", pattern: /intercomSettings|widget\.intercom\.io/ },
  { id: "fullstory", label: "FullStory", pattern: /fullstory\.com|FS\.identify\(/ },
  { id: "logrocket", label: "LogRocket", pattern: /logrocket|LogRocket\.init\(/ },
  { id: "heap", label: "Heap", pattern: /heap\.io|heap\.track\(/ },
  { id: "datadog-rum", label: "Datadog RUM", pattern: /datadogRum|datadog-browser-rum/ },
  { id: "bugsnag", label: "Bugsnag", pattern: /bugsnag/i },
  { id: "crashlytics", label: "Firebase Crashlytics", pattern: /crashlytics|fabric\.io/i },
  { id: "rudderstack", label: "RudderStack", pattern: /rudderstack/i },
  { id: "matomo", label: "Matomo", pattern: /matomo|piwik/i },
]

/** Files that ship in almost every Electron app and control the app's security posture. */
export const SENSITIVE_FILENAMES = [
  { pattern: /^preload\.(js|cjs|mjs|ts)$/i, label: "Preload script", why: "Runs with Node access in the renderer; the main privilege boundary." },
  { pattern: /^main\.(js|cjs|mjs|ts)$/i, label: "Main process entry", why: "Full Node.js and OS access." },
  { pattern: /^background\.(js|cjs|mjs)$/i, label: "Service worker", why: "Controls offline behaviour and caches." },
  { pattern: /\.env(\.|$)/i, label: "Environment file", why: "Build-time secrets land here." },
  { pattern: /keystore|keychain|credential/i, label: "Credential store", why: "Where secrets should live." },
  { pattern: /\.pem$|\.p12$|\.pfx$|\.key$/i, label: "Key material", why: "Private key file." },
]

/**
 * Shannon entropy per character. A real key looks random; a placeholder does not.
 * English words and config values sit near 3.5-4.5; random base64/hex runs 4.8+.
 */
export function entropy(s) {
  if (!s || s.length < 2) return 0
  const freq = new Map()
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1)
  let h = 0
  for (const n of freq.values()) {
    const p = n / s.length
    h -= p * Math.log2(p)
  }
  return h
}

/** A value is suspicious when it is long, not a placeholder, and not low-entropy prose. */
export function looksLikeRealSecret(value, { minEntropy = 3.6, minLength = 12 } = {}) {
  if (typeof value !== "string") return false
  if (value.length < minLength) return false
  if (PLACEHOLDER.test(value)) return false
  if (/^(https?:|wss?:)/i.test(value)) return false // a URL is not a secret by itself
  if (/^[a-z]+([_\-][a-z]+)*$/i.test(value) && value.length < 32) return false // snake/kebab words
  if (entropy(value) < minEntropy) return false
  return true
}

export { PLACEHOLDER }
