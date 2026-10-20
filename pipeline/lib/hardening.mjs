// Renderer hardening rules for shipped Electron bundles.
//
// Two kinds of check, and the distinction matters for how the report reads:
//
//   explicit  - a webPreferences value that is known to be unsafe.
//   absence   - a protection that is simply not there. Absence checks are
//               heuristics: they look for the guard's identifier anywhere in
//               the app's own code. A guard written in a way these patterns
//               miss will read as missing, so the report says "not found"
//               rather than "not present".
//
// Minified bundles write booleans as !0 / !1, so both spellings are matched.
// These key names also appear in unrelated config objects, so every
// webPreferences rule requires that identifier within a short window of the
// match. Without it the false-positive rate is not worth the signal.

export const CONTEXT_WINDOW = 300

export const HARDENING_RULES = [
  {
    id: "node-integration",
    title: "nodeIntegration enabled in a renderer",
    severity: "high",
    regex: /\bnodeIntegration\s*:\s*(?:!0|true)\b/g,
    context: /webPreferences/,
    why:
      "A renderer with Node integration can require() any module, including child_process. " +
      "Any script injection in that page becomes code execution on the user's machine.",
  },
  {
    id: "context-isolation-off",
    title: "contextIsolation disabled",
    severity: "high",
    regex: /\bcontextIsolation\s*:\s*(?:!1|false)\b/g,
    context: /webPreferences/,
    why:
      "Without context isolation the preload script and the page share one JavaScript context, " +
      "so page code can reach and replace the privileged objects the preload relies on.",
  },
  {
    id: "sandbox-off",
    title: "Renderer sandbox disabled",
    severity: "medium",
    regex: /\bsandbox\s*:\s*(?:!1|false)\b/g,
    context: /webPreferences/,
    why:
      "sandbox: false gives the renderer process the full Chromium sandbox exemption, " +
      "widening the impact of any renderer compromise.",
  },
  {
    id: "websecurity-off",
    title: "webSecurity disabled",
    severity: "high",
    regex: /\bwebSecurity\s*:\s*(?:!1|false)\b/g,
    context: /webPreferences/,
    why:
      "With webSecurity off the renderer ignores the same-origin policy, so a page can read " +
      "cross-origin responses, including services listening on the user's own machine.",
  },
  {
    id: "websecurity-env-gated",
    title: "webSecurity decided by an environment variable",
    severity: "medium",
    regex: /\bwebSecurity\s*:\s*!\s*process\.env\./g,
    context: /webPreferences/,
    why:
      "A development switch that is evaluated unconditionally. In a packaged build this value " +
      "is decided by whatever the launching environment contains, not by the build configuration.",
  },
  {
    id: "webview-tag",
    title: "webviewTag enabled",
    severity: "medium",
    regex: /\bwebviewTag\s*:\s*(?:!0|true)\b/g,
    context: /webPreferences/,
    why: "The <webview> tag is a documented Electron security liability and is off by default.",
  },
  {
    id: "insecure-content",
    title: "allowRunningInsecureContent enabled",
    severity: "high",
    regex: /\ballowRunningInsecureContent\s*:\s*(?:!0|true)\b/g,
    context: /webPreferences/,
    why: "Permits HTTPS pages to load and run HTTP subresources, removing transport guarantees.",
  },
  {
    id: "remote-module",
    title: "enableRemoteModule enabled",
    severity: "high",
    regex: /\benableRemoteModule\s*:\s*(?:!0|true)\b/g,
    context: /webPreferences/,
    why:
      "The remote module exposes main-process objects to the renderer. It was removed from " +
      "Electron precisely because it turns renderer access into main-process access.",
  },
]

// Presence signals, aggregated across the app's own code. Each entry is either a
// RegExp or an array of them (any match counts).
export const GUARD_SIGNALS = {
  preload: [/preload\s*:/],
  windowOpen: [/setWindowOpenHandler/],
  navigation: [/will-navigate/, /will-redirect/],
  permission: [/setPermissionRequestHandler/, /setPermissionCheckHandler/],
  csp: [/http-equiv\s*=\s*["']?Content-Security-Policy/i, /["']content-security-policy["']\s*:/i],
}

export const ABSENCE_CHECKS = [
  {
    id: "no-window-open-handler",
    requires: "preload",
    signal: "windowOpen",
    title: "No window-open handler in the main process",
    severity: "medium",
    why:
      "Without setWindowOpenHandler, a window.open() from the renderer is handled by Electron's " +
      "default, which creates a new window rather than refusing. The safe default is to deny and " +
      "route genuine external links through shell.openExternal.",
  },
  {
    id: "no-navigation-guard",
    requires: "preload",
    signal: "navigation",
    title: "Navigation is not restricted in the main process",
    severity: "medium",
    why:
      "Without a will-navigate handler the window may navigate away from the bundled page. " +
      "The preload script is re-attached to whatever page ends up in that window, so a preload " +
      "that exposes IPC would be exposed to that origin too.",
  },
  {
    id: "no-content-security-policy",
    requires: "preload",
    signal: "csp",
    title: "No Content-Security-Policy found",
    severity: "medium",
    why:
      "No CSP meta tag and no CSP response header were found in the app's own code. CSP is the " +
      "main control that limits what injected script can do.",
  },
]
