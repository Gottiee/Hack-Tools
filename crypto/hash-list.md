# Hash list

## Vuln

- md5 et moindre
- LM (14 char (mdp + padding) + capital + split in two -> md4 + concat both parts)
    - blank : `aad3b435b51404eeaad3b435b51404ee`
- NT (unicode + md4)
- NTLM (NT:LM) (:warning: do not confuse with NET-NTLMv1/v2)
