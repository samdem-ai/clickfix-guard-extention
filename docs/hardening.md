# Hardening beyond the browser

ClickFix Guard works inside the browser. The attack finishes outside it, when
the victim pastes into the Run dialog or a terminal. For managed machines,
these OS controls close that gap. Use them together with the extension.

## Windows

| Control | How | Effect on ClickFix |
|---|---|---|
| Remove the Run dialog for standard users | GPO: *User Configuration → Administrative Templates → Start Menu and Taskbar → Remove Run menu from Start Menu* | Win+R does nothing, which breaks the most common lure flow |
| Block `mshta.exe` | AppLocker / WDAC deny rule for `%SystemRoot%\System32\mshta.exe` and `SysWOW64\mshta.exe` | Kills the most common first stage |
| Disable Windows Script Host | `HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings` → `Enabled` = `0` (DWORD) | Stops `wscript` / `cscript` stages, including over WebDAV |
| ASR: block obfuscated scripts | Defender ASR rule `5beb7efe-fd9a-4556-801d-275e5ffc04cc` | Blocks many `-enc` / string-built PowerShell stages |
| ASR: block JS/VBS launching downloads | Defender ASR rule `d3e037e1-3eb8-44c8-a917-57927947596d` | Stops script-host droppers |
| PowerShell Constrained Language Mode | WDAC policy in enforced mode (not the `__PSLockdownPolicy` variable) | `iex` of downloaded .NET-heavy loaders fails |
| Block WebClient / WebDAV from users | Disable the `WebClient` service where it isn't needed | Defeats `\\host@SSL\DavWWWRoot\…` delivery |

### Detection and forensics

- **RunMRU.** Every command run from Win+R is recorded in
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`. Hunt
  there for `mshta`, `powershell … iex`, `curl … &&`, or decoy comments like
  `# I am not a robot`. Velociraptor's `Windows.Registry.RunMRU`-style
  collection or a simple registry query across endpoints finds victims
  quickly.
- **Process lineage.** Look for `explorer.exe → powershell.exe / mshta.exe /
  cmd.exe` whose command line contains a URL. A user double-clicking a script
  normally has a different parent chain.
- **PowerShell logging.** Enable Script Block Logging (Event ID 4104). It
  records the *deobfuscated* script blocks, including the second stage.

## macOS

- Restrict `osascript` for standard users through MDM (a PPPC / TCC profile
  and a binary allow-list). Fake password-prompt stealers depend on it.
- Alert on `curl … | bash` and on `xattr -d com.apple.quarantine` /
  `xattr -c` run from Terminal by non-admin users (EDR or Endpoint Security
  framework rules).
- Teach users that no website verification asks them to open Terminal.

## Not built: native companion

A native-messaging host (supported by both Chrome and Firefox) could watch for
the Run dialog, PowerShell or Terminal coming to the foreground right after a
flagged copy, and clear the clipboard at that moment. It would need a
per-OS installer, so it is left as future work. The extension's
leave-the-browser guard covers most of that window from inside the browser.
