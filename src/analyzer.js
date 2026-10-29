/*
 * ClickFix Guard analyzer.
 *
 * analyze(text, context) decides whether text a web page put on the clipboard
 * is a "paste-and-run" lure command. Pure and synchronous: runs inside the page
 * hook (MAIN world) and under Node for tests. It never executes or fetches
 * anything; decoding is only for inspection.
 *
 * Verdict: score >= BLOCK_AT -> "block", >= WARN_AT -> "warn", else "allow".
 * Page context only counts when the text already looks like a command, so
 * ordinary copies on lure-looking pages are never blocked.
 */
(function (root) {
  "use strict";

  const WARN_AT = 5;
  const BLOCK_AT = 8;
  const MAX_LEN = 20000;

  // Zero-width, bidi control and soft-hyphen characters used to split keywords.
  const INVISIBLE_RE = /[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/g;
  const SUSPICIOUS_TLD_RE =
    /\bhttps?:\/\/[^\s/'"`]*\.(?:xyz|top|icu|click|shop|live|lol|cyou|sbs|cfd|bond|rest|online|site|fun|buzz|monster|quest|zip|mov|ru|su|tk|ml|ga|cf|gq|pw)(?::\d+)?(?:[/'"`\s]|$)/i;
  const RAW_IP_URL_RE = /\b(?:https?:\/\/|\\\\)\d{1,3}(?:\.\d{1,3}){3}\b/i;
  const ABUSED_HOST_RE =
    /\b(?:trycloudflare\.com|ngrok(?:-free)?\.(?:io|app|dev)|pastebin\.com|paste\.ee|transfer\.sh|temp\.sh|files\.catbox\.moe|litter\.catbox\.moe|0x0\.st|discord(?:app)?\.com\/attachments|bit\.ly|tinyurl\.com|rentry\.co|glitch\.me|workers\.dev)\b/i;

  // [id, weight, label, regex]. Weights add up; see WARN_AT / BLOCK_AT.
  const COMMAND_RULES = [
    // --- Windows ---------------------------------------------------------------
    ["powershell", 2, "Starts PowerShell", /\b(?:powershell|pwsh)(?:\.exe)?\b/i],
    ["cmd", 1, "Starts cmd.exe", /\bcmd(?:\.exe)?\s+\/[ck]\b/i],
    ["hidden_window", 3, "Runs in a hidden or minimised window",
      /\s[-\/]w(?:in(?:dow)?(?:style)?)?\s+['"]?(?:h(?:idden)?|1|2|min(?:imized)?)\b|-windowstyle\s+hidden|\bstart\s+\/min\b|conhost(?:\.exe)?\s+--headless/i],
    ["encoded_command", 3, "Uses an encoded PowerShell command",
      /\s-e(?:c|nc|ncodedcommand|ncoded|ncod|nco)?\s+[A-Za-z0-9+/]{16,}={0,2}/i],
    ["policy_bypass", 1, "Bypasses the script execution policy", /-(?:ep|exec(?:utionpolicy)?)\s+(?:bypass|unrestricted)/i],
    ["no_profile", 1, "Skips the PowerShell profile", /\s-nop(?:rofile)?\b/i],
    ["invoke_expression", 3, "Executes a string as code (iex)", /\b(?:iex|invoke-expression)\b|\|\s*&?\s*\(?\s*\$?(?:iex)\b|\.invoke\(\)|scriptblock\]::create/i],
    ["downloader", 2, "Downloads content from the internet",
      /\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|net\.webclient|downloadstring|downloadfile|downloaddata|start-bitstransfer|wget|curl(?:\.exe)?|httpclient|xmlhttp)\b/i],
    ["mshta", 6, "Runs a remote HTML application with mshta", /\bmshta(?:\.exe)?\b/i],
    ["rundll32_remote", 5, "rundll32 loading remote or script content", /\brundll32(?:\.exe)?\b[^\n]*(?:https?:|\\\\|javascript:|davclnt)/i],
    ["regsvr32_remote", 6, "regsvr32 scriptlet download (Squiblydoo)", /\bregsvr32(?:\.exe)?\b[^\n]*\/i:\s*https?:/i],
    ["certutil", 5, "certutil used to download or decode", /\bcertutil(?:\.exe)?\b[^\n]*-(?:urlcache|decode|decodehex|split|f\b)/i],
    ["bitsadmin", 4, "bitsadmin file transfer", /\bbitsadmin(?:\.exe)?\b[^\n]*\/transfer/i],
    ["msiexec_remote", 5, "Installs an MSI straight from a URL", /\bmsiexec(?:\.exe)?\b[^\n]*\/(?:i|package)\s*['"]?https?:/i],
    ["finger", 5, "finger.exe used as a download channel", /\bfinger(?:\.exe)?\s+\S+@\S+/i],
    ["pipe_to_cmd", 4, "Pipes downloaded output into cmd", /\|\s*cmd(?:\.exe)?\b/i],
    ["script_host", 3, "Runs a script with wscript/cscript", /\b[wc]script(?:\.exe)?\b/i],
    ["defender_tamper", 5, "Adds a Microsoft Defender exclusion or disables protection",
      /add-mppreference\b[^\n]*-exclusion|set-mppreference\b[^\n]*-disable/i],
    ["reflective_load", 4, "Loads a .NET assembly from memory", /reflection\.assembly\]::load|\[system\.reflection\.assembly\]/i],
    ["from_base64", 3, "Decodes base64 at run time", /frombase64string|\bbase64\s+(?:-d|--decode|-D)\b|\[convert\]::/i],
    ["temp_drop_exec", 5, "Downloads to a temp folder and runs it",
      /(?:%temp%|%appdata%|%localappdata%|%programdata%|\$env:(?:temp|appdata|localappdata|programdata)|\/tmp\/)[^\n]*(?:\bstart\b|start-process|&\s*["']?(?:%temp%|\$env)|\.\/|chmod\s+\+x)/i],
    ["persistence", 3, "Creates a scheduled task or Run key", /\bschtasks(?:\.exe)?\s+\/create|currentversion\\run\b/i],
    // --- macOS / Linux -----------------------------------------------------------
    ["pipe_to_shell", 3, "Pipes a download straight into a shell",
      /\b(?:curl|wget)\b[^|\n;]*\|\s*(?:sudo\s+)?(?:ba|z|da|k|fi)?sh\b|\b(?:ba|z)?sh\s+-c\s+["']?\$\(\s*(?:curl|wget)\b|\b(?:curl|wget)\b[^|\n;]*\|\s*(?:sudo\s+)?python3?\b/i],
    ["base64_to_shell", 6, "Decodes base64 and pipes it into a shell",
      /base64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\becho\s+['"]?[A-Za-z0-9+/]{24,}={0,2}['"]?\s*\|\s*base64/i],
    ["osascript", 4, "Runs AppleScript (often a fake password prompt)", /\bosascript\b/i],
    ["quarantine_strip", 4, "Removes the macOS quarantine flag", /\bxattr\b[^\n]*(?:-c\b|-d\s+com\.apple\.quarantine|-r?d\s+com\.apple\.quarantine)/i],
    ["background_detach", 2, "Detaches the process to run in the background", /\bnohup\b|\bdisown\b|&\s*>\s*\/dev\/null/i],
  ];

  // URL and social-engineering features that only matter alongside a command.
  const URL_RULES = [
    ["raw_ip_url", 3, "Contacts a bare IP address", RAW_IP_URL_RE],
    ["suspicious_tld", 2, "Uses a domain TLD common in malware campaigns", SUSPICIOUS_TLD_RE],
    ["abused_host", 3, "Uses a tunnelling, paste or file-drop host", ABUSED_HOST_RE],
    ["plain_http", 1, "Downloads over unencrypted http://", /\bhttp:\/\//i],
  ];

  // Decoy comments shown in the Run dialog so the victim sees "verification" text.
  const DECOY_RE =
    /(?:#|\brem\b|::|<#|;\s*#)[^\n]{0,120}?(?:not\s+a\s+robot|i\s*(?:'?m|\s+am)\s+(?:not\s+a\s+robot|human)|human\s+verification|verif(?:y|ied|ication)\b|captcha|recaptcha|hcaptcha|cloudflare|ray\s*id|verification\s*(?:id|code|hash)|\u2705|\u2714)/i;

  const LURE_PHRASES = [
    [/(?:win(?:dows)?|\u229e|\u2756|\u{1FA9F})\s*(?:key\s*)?\+\s*r\b|windows\s+key\s+and\s+r\b|run\s+dialog/iu, 4, "Page tells you to open the Run dialog (Win+R)"],
    [/(?:win(?:dows)?|\u229e)\s*(?:key\s*)?\+\s*x\b|open\s+(?:windows\s+)?(?:terminal|powershell)(?:\s+\(admin\))?|press\s+(?:cmd|command)\s*\+\s*space|open\s+(?:the\s+)?terminal\s+app/iu, 3, "Page tells you to open a terminal"],
    [/ctrl\s*\+\s*v|cmd\s*\+\s*v|\u2318\s*\+?\s*v|paste\s+(?:it|the\s+(?:code|command|text))/i, 2, "Page tells you to paste something"],
    [/verify\s+(?:you\s+are|you're|that\s+you\s+are)\s+(?:a\s+)?human|i\s*(?:'|\u2019)?m\s+not\s+a\s+robot|verification\s+steps|complete\s+(?:the\s+)?verification|human\s+verification|captcha\s+verification/i, 3, "Page shows a fake CAPTCHA / human verification"],
    [/press\s+enter|hit\s+enter/i, 1, "Page tells you to press Enter"],
    [/fix\s+(?:it|the\s+(?:error|issue|problem))|how\s+to\s+fix|copy\s+(?:the\s+)?fix|update\s+(?:your\s+)?(?:browser|driver|font)/i, 1, "Page offers a 'fix' to run"],
  ];

  function normalize(text) {
    let s = String(text == null ? "" : text).slice(0, MAX_LEN);
    const signals = [];
    if (INVISIBLE_RE.test(s)) signals.push("invisible_chars");
    s = s.replace(INVISIBLE_RE, "");
    try { s = s.normalize("NFKC"); } catch (_) { /* old engine */ }
    // Runs of spaces / NBSP push the real command out of view in the Run dialog.
    const padded = /[ \u00A0\t]{25,}/.test(s);
    if (padded) signals.push("whitespace_padding");
    let deob = s
      .replace(/\u00A0/g, " ")
      .replace(/\^(?=[^\s^])/g, "")                 // cmd caret escapes: p^o^w^e^r^shell
      .replace(/`(?=[A-Za-z])/g, "")                // PowerShell backtick escapes: i`e`x
      .replace(/(['"])\s*\+\s*\1/g, "")             // 'pow'+'ershell' concatenation
      .replace(/[ \t]{2,}/g, " ");
    return { text: s, deobfuscated: deob, signals };
  }

  function b64ToBinary(b64) {
    const clean = b64.replace(/[^A-Za-z0-9+/=]/g, "");
    if (clean.length < 16) return null;
    try {
      return atob(clean + "===".slice((clean.length + 3) % 4));
    } catch (_) {
      return null;
    }
  }

  function printableRatio(s) {
    if (!s) return 0;
    let ok = 0;
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13 || c > 159) ok++;
    }
    return ok / s.length;
  }

  function decodeUtf16le(bin) {
    let out = "";
    for (let i = 0; i + 1 < bin.length; i += 2) out += String.fromCharCode(bin.charCodeAt(i) | (bin.charCodeAt(i + 1) << 8));
    return out;
  }

  function decodeUtf8(bin) {
    try {
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch (_) {
      return null;
    }
  }

  // Decode embedded payloads for inspection only (one level, bounded count).
  function decodePayloads(s) {
    const out = [];
    const enc = /\s-e(?:c|nc|ncodedcommand|ncoded|ncod|nco)?\s+([A-Za-z0-9+/]{16,}={0,2})/gi;
    let m;
    while ((m = enc.exec(s)) && out.length < 5) {
      const bin = b64ToBinary(m[1]);
      if (bin) {
        const txt = decodeUtf16le(bin);
        if (printableRatio(txt) > 0.9) out.push(txt);
      }
    }
    const blob = /[A-Za-z0-9+/]{24,}={0,2}/g;
    while ((m = blob.exec(s)) && out.length < 5) {
      const bin = b64ToBinary(m[0]);
      if (!bin) continue;
      const txt = decodeUtf8(bin);
      if (txt && printableRatio(txt) > 0.95 && /[a-z]{3}/i.test(txt) && !out.includes(txt)) out.push(txt);
    }
    return out;
  }

  function firstMatch(re, s) {
    const m = re.exec(s);
    return m ? m[0].trim().slice(0, 120) : null;
  }

  function analyze(text, context) {
    const ctx = context || {};
    const norm = normalize(text);
    const decoded = decodePayloads(norm.deobfuscated);
    const corpus = [norm.deobfuscated].concat(decoded).join("\n");
    const reasons = [];
    const add = (id, weight, label, match) => reasons.push({ id, weight, label, match: match || null });

    for (const [id, w, label, re] of COMMAND_RULES) {
      const hit = firstMatch(re, corpus);
      if (hit) add(id, w, label, hit);
    }
    const isCommand = reasons.length > 0;
    if (!isCommand) {
      return { verdict: "allow", score: 0, reasons: [], decoded, signals: norm.signals };
    }

    const ids = new Set(reasons.map((r) => r.id));
    for (const [id, w, label, re] of URL_RULES) {
      const hit = firstMatch(re, corpus);
      if (hit) { add(id, w, label, hit); ids.add(id); }
    }
    const shady = ids.has("raw_ip_url") || ids.has("suspicious_tld") || ids.has("abused_host") || ids.has("plain_http");

    // Download + execute is the core of every lure. Over HTTPS from an ordinary
    // domain it is also how real installers work (Chocolatey, Scoop), so the
    // extra weight applies only to shady sources or hidden windows.
    if (ids.has("downloader") && ids.has("invoke_expression") && (shady || ids.has("hidden_window"))) {
      add("download_execute", 4, "Downloads code from an untrusted source and executes it immediately");
    }
    if (ids.has("pipe_to_shell") && shady) {
      add("shady_pipe_to_shell", 3, "Pipes a script from an untrusted location into a shell");
    }

    const decoy = firstMatch(DECOY_RE, norm.text);
    if (decoy) add("decoy_comment", 5, "Hides the command behind a fake 'verification' comment", decoy);
    if (norm.signals.includes("whitespace_padding")) add("whitespace_padding", 3, "Pads the command with spaces to hide it in the Run dialog");
    if (norm.signals.includes("invisible_chars")) add("invisible_chars", 2, "Contains invisible characters that split keywords");
    if (norm.deobfuscated !== norm.text.replace(/\u00A0/g, " ").replace(/[ \t]{2,}/g, " ")) {
      add("escape_obfuscation", 2, "Uses ^, ` or string concatenation to disguise keywords");
    }
    if (decoded.length) add("decoded_payload", 1, "Contains an encoded payload (decoded for inspection)");

    if (ctx.programmatic) add("programmatic_copy", 1, "The page wrote this to your clipboard by script");
    const page = typeof ctx.pageText === "string" ? ctx.pageText.slice(0, MAX_LEN) : "";
    let lureScore = 0;
    for (const [re, w, label] of LURE_PHRASES) {
      const hit = firstMatch(re, page);
      if (hit) { add("lure_text", w, label, hit); lureScore += w; }
    }

    const score = reasons.reduce((a, r) => a + r.weight, 0);
    const verdict = score >= BLOCK_AT ? "block" : score >= WARN_AT ? "warn" : "allow";
    reasons.sort((a, b) => b.weight - a.weight);
    return { verdict, score, reasons, decoded, signals: norm.signals, lureScore };
  }

  // Text written to the clipboard instead of a blocked command. Starts with '#'
  // so pasting it into Run, cmd, PowerShell or a Unix shell does nothing.
  function notice(host) {
    const where = host ? ` copied by ${String(host).slice(0, 80)}` : "";
    return `# ClickFix Guard blocked a malicious command${where}. Websites never ask you to paste commands into the Run box or a terminal.`;
  }

  const api = { analyze, normalize, notice, WARN_AT, BLOCK_AT };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.ClickFixAnalyzer = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
