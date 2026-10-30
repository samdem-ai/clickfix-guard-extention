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

  // On-device classifier weights (src/model.js). Optional: rules work without it.
  let MODEL = root.ClickFixModel || null;
  if (!MODEL && typeof module !== "undefined" && typeof require === "function") {
    try { MODEL = require("./model.js"); } catch (_) { MODEL = null; }
  }

  const WARN_AT = 5;
  const BLOCK_AT = 8;
  const MAX_LEN = 20000;

  // Zero-width, bidi control and soft-hyphen characters used to split keywords.
  const INVISIBLE_RE = /[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/g;
  const SUSPICIOUS_TLD_RE =
    /\bhttps?:\/\/[^\s/'"`]*\.(?:xyz|top|icu|click|shop|live|lol|cyou|sbs|cfd|bond|rest|online|site|fun|buzz|monster|quest|zip|mov|ru|su|tk|ml|ga|cf|gq|pw)(?::\d+)?(?:[/'"`\s]|$)/i;
  const RAW_IP_URL_RE = /(?:\bhttps?:\/\/|\\\\)\d{1,3}(?:\.\d{1,3}){3}\b/i; // URL or UNC/WebDAV share
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

  // Official installer one-liners that fetch-and-run by design (HTTPS only).
  // Host-exact; GitHub raw content only for specific projects, since attackers
  // host payloads there too. Lowers the score, never overrides lure evidence.
  const KNOWN_INSTALLERS = [
    /^https:\/\/(?:astral\.sh|get\.scoop\.sh|deno\.land|community\.chocolatey\.org|bun\.sh|get\.docker\.com|sh\.rustup\.rs|ollama\.com|get\.pnpm\.io|tailscale\.com|starship\.rs|fly\.io|get\.k3s\.io|get\.sdkman\.io|get\.volta\.sh|mise\.run|claude\.ai|brew\.sh|install\.python-poetry\.org|nixos\.org|sh\.uv\.dev)(?:[\/:"'\s]|$)/i,
    /^https:\/\/raw\.githubusercontent\.com\/(?:Homebrew\/install|nvm-sh\/nvm|ohmyzsh\/ohmyzsh)\//i,
  ];
  const URL_ALL_RE = /\bhttps?:\/\/[^\s'"`)|;]+|\\\\\d{1,3}(?:\.\d{1,3}){3}\S*/gi;
  // Reasons that mean the command executes something (not just downloads it).
  const EXEC_IDS = new Set(["invoke_expression", "pipe_to_shell", "base64_to_shell", "mshta", "rundll32_remote", "regsvr32_remote",
    "certutil", "bitsadmin", "msiexec_remote", "finger", "pipe_to_cmd", "script_host", "temp_drop_exec", "osascript",
    "fetch_and_run", "reflective_load", "encoded_command", "from_base64", "persistence", "defender_tamper",
    "quarantine_strip", "unknown_program_url", "string_reconstruction", "interpreter_remote"]);

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

  // Labels of buttons that copy as a side effect of "verifying" or "continuing".
  const DECEPTIVE_TRIGGER_RE =
    /verif|robot|human|captcha|continue|proceed|confirm|agree|accept|access|unlock|fix|update|download|install|open|view|play|watch|next|submit|check|start|ok\b|got it/i;
  // Reasons that mean the page is hiding or misrepresenting what it copied.
  const DECEPTION_IDS = new Set(["hidden_copy", "deceptive_trigger", "lure_text", "decoy_comment", "whitespace_padding", "invisible_chars"]);

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
    const escaped = deob;
    deob = rebuildStrings(deob);
    return { text: s, escaped, deobfuscated: deob, signals };
  }

  // --- PowerShell string reconstruction ------------------------------------------
  // Evaluates the string tricks lures use to hide keywords ([char] codes, -join,
  // -f, -replace, reversed indexing, characters picked out of $env:ComSpec), as
  // pure text rewriting. Nothing is executed. Repeats until stable (max 4 passes).
  const Q = `(?:'[^'\\n]*'|"[^"\\n]*")`;
  const QLIST = `${Q}(?:\\s*,\\s*${Q})*`;
  const unq = (t) => t.slice(1, -1);
  const lit = (t) => "'" + t.replace(/'/g, "") + "'";
  const listItems = (t) => (t.match(new RegExp(Q, "g")) || []).map(unq);
  // Typical values of variables lures index into.
  const KNOWN_VARS = {
    "$env:comspec": "C:\\WINDOWS\\system32\\cmd.exe",
    "$pshome": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
    "$shellid": "Microsoft.PowerShell",
    "$verbosepreference": "SilentlyContinue",
  };
  const PS_REWRITES = [
    // [char]105+[char]101+[char]120  /  [char[]](105,101,120)
    [/(?:\[char\]\s*(?:\(\s*(?:0x[0-9a-f]+|\d{1,5})\s*\)|0x[0-9a-f]+|\d{1,5})(?:\s*[+,]\s*(?=\[char\]))?){2,}/gi, (m) =>
      lit((m.match(/0x[0-9a-f]+|\d{1,5}/gi) || []).map((n) => String.fromCharCode(Number(n))).join(""))],
    [/\[char\[\]\]\s*\(\s*((?:0x[0-9a-f]+|\d{1,5})(?:\s*,\s*(?:0x[0-9a-f]+|\d{1,5}))*)\s*\)/gi, (_m, list) =>
      lit(list.split(/\s*,\s*/).map((n) => String.fromCharCode(Number(n))).join(""))],
    // ("{1}{0}" -f 'ex','i')
    [new RegExp(`\\(?\\s*(${Q})\\s*-f\\s*(${QLIST})\\s*\\)?`, "gi"), (_m, fmt, args) => {
      const a = listItems(args);
      return lit(unq(fmt).replace(/\{(\d+)\}/g, (_x, i) => (a[+i] !== undefined ? a[+i] : "")));
    }],
    // ('i','e','x') -join ''   /   -join ('i','e','x')
    [new RegExp(`\\(\\s*(${QLIST})\\s*\\)\\s*-join\\s*(?:''|"")?`, "gi"), (_m, list) => lit(listItems(list).join(""))],
    [new RegExp(`-join\\s*\\(\\s*(${QLIST})\\s*\\)`, "gi"), (_m, list) => lit(listItems(list).join(""))],
    // 'xei'[-1..-3]  (reverse)
    [new RegExp(`(${Q})\\s*\\[\\s*-1\\s*\\.\\.\\s*-\\s*\\(?\\s*(?:\\d+|${Q}\\.length)\\s*\\)?\\s*\\]`, "gi"), (_m, q) =>
      lit(unq(q).split("").reverse().join(""))],
    // 'iXeXx' -replace 'X',''   (case-insensitive, like PowerShell)   /   -creplace
    [new RegExp(`(${Q})\\s*-(c?)replace\\s*(${Q})\\s*(?:,\\s*(${Q}))?`, "gi"), (_m, q, cs, pat, rep) => {
      try { return lit(unq(q).replace(new RegExp(unq(pat), cs ? "g" : "gi"), rep ? unq(rep) : "")); } catch (_) { return _m; }
    }],
    // $env:comspec[4,15,25]  /  $pshome[21]
    [/(\$env:comspec|\$pshome|\$shellid|\$verbosepreference)\s*\[\s*(\d+(?:\s*,\s*\d+)*)\s*\]/gi, (_m, v, idx) =>
      lit(idx.split(/\s*,\s*/).map((i) => KNOWN_VARS[v.toLowerCase()][+i] || "").join(""))],
    // 'a'+'b' left over from the rewrites above, and  'iex' -join ''
    [/(['"])\s*\+\s*\1/g, ""],
    [new RegExp(`(${Q})\\s*-join\\s*(?:''|"")`, "gi"), (_m, q) => q],
  ];

  function rebuildStrings(text) {
    let s = text;
    for (let pass = 0; pass < 4; pass++) {
      const before = s;
      for (const [re, fn] of PS_REWRITES) s = s.replace(re, fn);
      if (s === before) break;
    }
    return s;
  }

  // --- Generic command-line parsing -------------------------------------------------
  // Rules name known tools; the parser recognises the *shape* of fetch-and-run
  // command lines so that an unlisted binary or interpreter is still caught.
  const BENIGN_PROGRAMS = new Set(("git npm npx pnpm yarn bun deno node pip pip3 pipx uv poetry python python3 py cargo " +
    "rustup go docker podman kubectl helm terraform ansible brew apt apt-get dnf yum pacman snap flatpak winget choco " +
    "scoop code dotnet java mvn gradle make cmake gcc clang ssh scp rsync ls cd cat echo grep find sed awk tar unzip " +
    "mkdir cp mv rm touch chmod sudo nvm sdk gh az aws gcloud ollama conda mamba wsl set-executionpolicy").split(" "));
  const INTERPRETERS = new Set(("sh bash zsh dash ksh fish python python3 perl ruby node osascript powershell pwsh cmd " +
    "iex invoke-expression wscript cscript mshta").split(" "));
  const URL_TOKEN_RE = /\bhttps?:\/\/\S+|\\\\\d{1,3}(?:\.\d{1,3}){3}\S*/i;
  const SAVE_RE = /(?:\s-o\s+|\s-O\s+|\s--output\s+|-outfile\s+|\s>\s*)(['"]?)([^\s'"|;&]+)\1/i;
  const EXEC_EXT_RE = /\.(?:exe|com|bat|cmd|ps1|vbs|vbe|js|jse|hta|msi|scr|dll|sh|command|app|pkg|dmg|py)\b/i;

  // Split on ; && || & | and newlines outside quotes. Returns [{text, op}].
  function splitSegments(text) {
    const out = [];
    let cur = "", quote = "", op = "";
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (quote) { cur += c; if (c === quote) quote = ""; continue; }
      if (c === "'" || c === '"') { quote = c; cur += c; continue; }
      const two = text.slice(i, i + 2);
      let sep = null;
      if (two === "&&" || two === "||") sep = two;
      else if (c === ";" || c === "\n" || c === "|" || (c === "&" && text[i - 1] !== ">" && text[i + 1] !== ">")) sep = c;
      if (sep) {
        if (cur.trim()) out.push({ text: cur.trim(), op });
        cur = ""; op = sep; i += sep.length - 1;
      } else cur += c;
    }
    if (cur.trim()) out.push({ text: cur.trim(), op });
    return out.slice(0, 50);
  }

  function programOf(seg) {
    let t = seg.replace(/^[&.(\s]+/, "").replace(/^(?:start(?:-process)?|call|sudo|exec|nohup|cmd(?:\.exe)?\s+\/[ck])\s+(?:\/\w+\s+)*/i, "");
    const tok = (t.match(/^(['"])(.*?)\1|^\S+/) || [""])[0].replace(/^['"]|['"]$/g, "");
    const base = tok.split(/[\\/]/).pop().toLowerCase();
    return { token: tok, name: base.replace(/\.(?:exe|com|bat|cmd|ps1|vbs|js|hta|msi)$/, "") };
  }

  function parseCommandLine(text) {
    const segs = splitSegments(text);
    const f = { pipeToInterpreter: false, runsSaved: false, unknownWithUrl: null, looksLikeCommand: false, hasUrl: false, inlineRemote: null };
    const saved = [];
    segs.forEach((seg, i) => {
      const prog = programOf(seg.text);
      const url = URL_TOKEN_RE.test(seg.text);
      const flags = /\s(?:--?[a-z]|\/[a-z?]\b)/i.test(seg.text);
      const isUrl = /^(?:https?:|www\.)/i.test(prog.token);
      const execLike = !isUrl && (EXEC_EXT_RE.test(prog.token) || /[\\/]/.test(prog.token) || INTERPRETERS.has(prog.name));
      if (url) f.hasUrl = true;
      // python -c / node -e / perl -e / powershell -Command "...https://..."
      if (url && INTERPRETERS.has(prog.name) && /\s-(?:c|e|command|enc\w*)\b/i.test(seg.text) && !f.inlineRemote) f.inlineRemote = prog.name;
      if (execLike || (flags && /^[\w.-]+$/.test(prog.name))) f.looksLikeCommand = true;
      if (seg.op === "|" && INTERPRETERS.has(prog.name) && segs.slice(0, i).some((s) => URL_TOKEN_RE.test(s.text))) f.pipeToInterpreter = true;
      const m = url && SAVE_RE.exec(seg.text);
      if (m) saved.push(m[2].split(/[\\/]/).pop().toLowerCase());
      if (i > 0 && saved.length && saved.some((name) => name && seg.text.toLowerCase().includes(name)) && !m) f.runsSaved = true;
      // Named interpreters are scored by their own rules; this is for the rest.
      if (url && !isUrl && (execLike || flags) && !BENIGN_PROGRAMS.has(prog.name) && !INTERPRETERS.has(prog.name) && !f.unknownWithUrl) {
        f.unknownWithUrl = prog.name || prog.token;
      }
    });
    return f;
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

  // --- Classifier features ------------------------------------------------------
  // Hashed character 3-5-grams of the deobfuscated + decoded text, digits folded
  // to 0 so addresses and IDs generalise. Shared verbatim by ml/train.mjs.
  const NGRAM_BUCKETS = 1 << 14;

  function corpusOf(text) {
    const norm = normalize(text);
    const decoded = decodePayloads(norm.deobfuscated);
    return { norm, decoded, corpus: [norm.deobfuscated].concat(decoded).join("\n") };
  }

  function fnv1a(str) {
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h;
  }

  // Returns parallel arrays of bucket indices and L2-normalised values.
  function featurize(corpus) {
    const t = " " + corpus.toLowerCase().replace(/[0-9]/g, "0").replace(/\s+/g, " ").slice(0, 4000) + " ";
    const counts = new Map();
    for (let n = 3; n <= 5; n++) {
      for (let i = 0; i + n <= t.length; i++) {
        const k = (fnv1a(n + t.slice(i, i + n)) % NGRAM_BUCKETS);
        counts.set(k, (counts.get(k) || 0) + 1);
      }
    }
    const idx = [], val = [];
    let norm = 0;
    for (const [k, c] of counts) {
      const v = Math.log1p(c);
      idx.push(k); val.push(v); norm += v * v;
    }
    norm = Math.sqrt(norm) || 1;
    for (let i = 0; i < val.length; i++) val[i] /= norm;
    return { idx, val };
  }

  function predict(model, corpus) {
    const { idx, val } = featurize(corpus);
    let z = model.b;
    for (let i = 0; i < idx.length; i++) z += (model.w[idx[i]] || 0) * val[i];
    return 1 / (1 + Math.exp(-z));
  }

  function firstMatch(re, s) {
    const m = re.exec(s);
    return m ? m[0].trim().slice(0, 120) : null;
  }

  function analyze(text, context) {
    const ctx = context || {};
    const { norm, decoded, corpus } = corpusOf(text);
    const model = ctx.model !== undefined ? ctx.model : MODEL;
    const ml = model ? predict(model, corpus) : null;
    const reasons = [];
    const add = (id, weight, label, match) => reasons.push({ id, weight, label, match: match || null });

    for (const [id, w, label, re] of COMMAND_RULES) {
      const hit = firstMatch(re, corpus);
      if (hit) add(id, w, label, hit);
    }
    const parsed = parseCommandLine(corpus);
    const ruleIds = new Set(reasons.map((r) => r.id));
    // Shapes the named rules already score (including irm|iex, which is weighed
    // by download_execute with its installer exemption) are not double-counted.
    const known = ["pipe_to_shell", "download_execute", "temp_drop_exec", "base64_to_shell", "mshta", "certutil",
      "bitsadmin", "msiexec_remote", "regsvr32_remote", "rundll32_remote", "finger", "pipe_to_cmd"].some((id) => ruleIds.has(id)) ||
      (ruleIds.has("downloader") && ruleIds.has("invoke_expression"));
    if (!known && (parsed.pipeToInterpreter || (parsed.hasUrl && parsed.runsSaved))) {
      add("fetch_and_run", 4, "Downloads something and runs it in the same command");
    }
    if (parsed.inlineRemote && !known && !ruleIds.has("invoke_expression")) {
      add("interpreter_remote", 2, `Runs inline ${parsed.inlineRemote} code that reaches out to the internet`, parsed.inlineRemote);
    }
    if (parsed.unknownWithUrl && !known && !ruleIds.has("downloader")) {
      add("unknown_program_url", 2, `Runs a program (${parsed.unknownWithUrl.slice(0, 30)}) against a remote address`, parsed.unknownWithUrl);
    }
    // The model adds evidence. Weights were set on a validation corpus (seed 555)
    // where p >= 0.5 already had ~0.2% benign false positives and p >= 0.8 none;
    // the model is under-confident on attack families it has not seen.
    // Only a confident score may open the command gate on its own.
    const mlLabel = () => `On-device model rates this as a malicious command (${Math.round(ml * 100)}%)`;
    const executes = () => reasons.some((r) => EXEC_IDS.has(r.id));
    // A download with no execution step is never pushed over the line by the model alone.
    if (ml !== null && ml >= 0.8) add("ml_malicious", executes() ? 5 : 2, mlLabel());
    const isCommand = reasons.length > 0 || (parsed.looksLikeCommand && parsed.hasUrl);
    if (!isCommand) {
      return { verdict: "allow", score: 0, reasons: [], decoded, signals: norm.signals, isCommand: false, deceptive: false, ml };
    }
    if (ml !== null && ml >= 0.5 && ml < 0.8 && executes()) add("ml_malicious", 3, mlLabel());

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

    const urls = norm.deobfuscated.match(URL_ALL_RE) || [];
    if (urls.length && !shady && !ids.has("hidden_window") && !ids.has("encoded_command") &&
        urls.every((u) => KNOWN_INSTALLERS.some((re) => re.test(u)))) {
      add("known_installer", -4, "Official installer from a well-known project");
    }

    const decoy = firstMatch(DECOY_RE, norm.text);
    if (decoy) add("decoy_comment", 5, "Hides the command behind a fake 'verification' comment", decoy);
    if (norm.signals.includes("whitespace_padding")) add("whitespace_padding", 3, "Pads the command with spaces to hide it in the Run dialog");
    if (norm.signals.includes("invisible_chars")) add("invisible_chars", 2, "Contains invisible characters that split keywords");
    if (norm.escaped !== norm.text.replace(/\u00A0/g, " ").replace(/[ \t]{2,}/g, " ")) {
      add("escape_obfuscation", 2, "Uses ^, ` or string concatenation to disguise keywords");
    }
    if (norm.deobfuscated !== norm.escaped) {
      add("string_reconstruction", 3, "Builds hidden keywords from character codes or string tricks");
    }
    if (decoded.length) add("decoded_payload", 1, "Contains an encoded payload (decoded for inspection)");

    if (ctx.programmatic) {
      add("programmatic_copy", 1, "The page wrote this to your clipboard by script");
      // Intent mismatch: what was copied vs. what the user could see and click.
      // These hold for any payload, so they catch commands no rule knows.
      const trigger = typeof ctx.trigger === "string" ? ctx.trigger.trim() : "";
      const saysCopy = /\bcop(?:y|ier)\b|\bclipboard\b/i.test(trigger);
      if (ctx.visibleOnPage === false) {
        add("hidden_copy", 3, "The copied command is not shown anywhere on the page");
      }
      if (trigger && !saysCopy && DECEPTIVE_TRIGGER_RE.test(trigger)) {
        add("deceptive_trigger", 2, `The button you clicked ("${trigger.slice(0, 40)}") does not say it copies anything`, trigger);
      } else if (saysCopy && ctx.visibleOnPage === true) {
        add("honest_copy", -2, "Copied from text shown on the page with an explicit Copy button");
      }
    }
    const page = typeof ctx.pageText === "string" ? ctx.pageText.slice(0, MAX_LEN) : "";
    let lureScore = 0;
    for (const [re, w, label] of LURE_PHRASES) {
      const hit = firstMatch(re, page);
      if (hit) { add("lure_text", w, label, hit); lureScore += w; }
    }

    const score = reasons.reduce((a, r) => a + r.weight, 0);
    const verdict = score >= BLOCK_AT ? "block" : score >= WARN_AT ? "warn" : "allow";
    reasons.sort((a, b) => b.weight - a.weight);
    const deceptive = reasons.some((r) => DECEPTION_IDS.has(r.id));
    return { verdict, score, reasons, decoded, signals: norm.signals, lureScore, isCommand: true, deceptive, ml };
  }

  // Text written to the clipboard instead of a blocked command. Starts with '#'
  // so pasting it into Run, cmd, PowerShell or a Unix shell does nothing.
  function notice(host) {
    const where = host ? ` copied by ${String(host).slice(0, 80)}` : "";
    return `# ClickFix Guard blocked a malicious command${where}. Websites never ask you to paste commands into the Run box or a terminal.`;
  }

  const api = { analyze, normalize, notice, parseCommandLine, rebuildStrings, corpusOf, featurize, predict, NGRAM_BUCKETS, WARN_AT, BLOCK_AT };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.ClickFixAnalyzer = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
