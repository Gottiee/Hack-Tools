# GTFOBins

## Table of Contents

1. [Overview](#overview)
2. [When to Use GTFOBins](#when-to-use-gtfobins)
3. [Common Categories](#common-categories)

---

## Overview

[GTFOBins](https://gtfobins.github.io/) is a curated list of standard Unix binaries that can be abused to bypass security restrictions. For each binary, it documents how to exploit it depending on the context (SUID, sudo, capabilities, etc.).

It is not an exploit database — it documents **intended features** of legitimate binaries that can be misused for privilege escalation.

## When to Use GTFOBins

Check GTFOBins when you find a binary in one of these contexts:

| Context | Example | GTFOBins filter |
|---|---|---|
| **SUID** | `find / -perm -4000` finds `/usr/bin/vim` | [+suid](https://gtfobins.github.io/#+suid) |
| **Sudo** | `sudo -l` shows `(root) /usr/bin/find` | [+sudo](https://gtfobins.github.io/#+sudo) |
| **Capabilities** | `getcap -r /` finds `python3 = cap_setuid+ep` | [+capabilities](https://gtfobins.github.io/#+capabilities) |
| **SGID** | `find / -perm -2000` finds a binary | Check SUID section (similar techniques) |
| **File read** | Need to read `/etc/shadow` via an allowed binary | [+file-read](https://gtfobins.github.io/#+file-read) |
| **File write** | Need to write to `/etc/passwd` via an allowed binary | [+file-write](https://gtfobins.github.io/#+file-write) |

> **Cron** is not a GTFOBins category. If a cron job runs a binary, the exploitation depends on whether you can modify the script, hijack its path, or inject into its arguments — not on GTFOBins techniques directly.

## Common Categories

GTFOBins classifies exploitation techniques:

- **Shell** — the binary can spawn an interactive shell
- **Command** — the binary can execute arbitrary commands
- **File read** — the binary can read files it shouldn't (e.g., reading `/etc/shadow` through `sudo less`)
- **File write** — the binary can write to arbitrary files
- **File upload / download** — the binary can transfer files (useful for exfiltration)
- **SUID** — the binary can be exploited when the SUID bit is set
- **Sudo** — the binary can be exploited when allowed via `sudo -l`
- **Capabilities** — the binary can be exploited when it has dangerous capabilities
- **Reverse shell** — the binary can open a reverse connection
- **Bind shell** — the binary can listen for incoming connections
- **Limited SUID** — exploitation is possible but with limitations (e.g., no full shell, only file read)
