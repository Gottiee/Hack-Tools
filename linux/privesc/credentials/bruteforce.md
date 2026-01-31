# Local Bruteforce

## Table of Contents

1. [Overview](#overview)
2. [Cracking Hashes](#cracking-hashes)
   - [Attack Modes](#attack-modes)
   - [John the Ripper](#john-the-ripper)
   - [Hashcat](#hashcat)
3. [Password Spraying](#password-spraying)
4. [su Bruteforce](#su-bruteforce)
5. [Wordlists](#wordlists)

---

## Overview

Bruteforce is the process of systematically testing a large set of passwords to gain access to a service or crack a hash.

Important in engagements: always check the **lockout policy** before bruteforcing. If the target has an account lockout threshold (e.g., 5 failed attempts), you can lock out legitimate users. Password spraying is the safer alternative.

## Cracking Hashes

**Offline** attack — you have the hash (from `/etc/shadow`, a database dump, etc.) and crack it locally. No lockout risk, speed depends on hardware.

### Attack Modes

| Mode              | Description                                              |
|-------------------|----------------------------------------------------------|
| Dictionary        | Test every word from a wordlist                          |
| Rules             | Apply transformations to wordlist (e.g., `password` → `P@ssw0rd!`) |
| Brute-force       | Try every possible combination (slow, last resort)       |
| Rainbow tables    | Precomputed hash → plaintext lookup tables. Fast but only works if the hash is **unsalted**. Modern hashes (sha512crypt, bcrypt) use salts, making rainbow tables useless. |

### John the Ripper

Runs on **CPU**. Good for quick cracks, supports many hash formats out of the box, auto-detects hash type.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --show hash.txt
```

### Hashcat

Runs on **GPU**. Much faster than John for large wordlists. Requires you to specify the hash mode (`-m`).

```bash
hashcat -m 1800 -a 0 hash.txt /usr/share/wordlists/rockyou.txt   # sha512crypt
hashcat -m 0 -a 0 hash.txt rockyou.txt                            # MD5
```

Use `hashcat --example-hashes` to identify the mode from a hash format.

## Password Spraying

**Not** the same as bruteforce. Instead of testing many passwords against one account, you test **one password against many accounts**. This avoids lockout policies.

Typical scenario: you find one password (e.g., from a config file) and try it against all users on the machine or network.

```bash
# Try one password against all users in /etc/passwd
for user in $(cat /etc/passwd | grep '/bin/bash' | cut -d: -f1); do
    echo "$password" | timeout 1 su - $user -c 'whoami' 2>/dev/null && echo "[+] $user:$password"
done
```

## su Bruteforce

When you have a shell but no password for another user, you can bruteforce `su` locally. Unlike SSH or service bruteforce, `su` has **no lockout** by default.

```bash
# Using sucrack (automated su bruteforcer)
sucrack -w 50 -u target_user /usr/share/wordlists/rockyou.txt
```

This is a **local-only** attack — you need an existing shell on the machine.

## Wordlists

| Wordlist           | Location / Source                              |
|--------------------|------------------------------------------------|
| `rockyou.txt`      | `/usr/share/wordlists/rockyou.txt` (Kali)      |
| `SecLists`         | github.com/danielmiessler/SecLists             |
| Custom (cewl)      | `cewl https://target.com -w custom.txt` — generates wordlist from target website |
