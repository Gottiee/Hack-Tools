<h1 align="center">Hack-Tools</h1>

<h3 align="center">
  Share resources, assets and information :robot:
</h3>

In this repository, you will find useful informations, bypasses and payloads for Application Security.

### Table of Contents

- [Unix missconfiguration](#Unix-missconfiguration)
- [Pwn](#pwn)
- [Reverse](#reverse)
- [Web](#web)
- [Tools](#tools)
- [Languages](#languages)

## Unix MissConfiguration

Vulnerabilities and potential risks caused by Unix misconfigurations

- [Sudo](missConfig/sudo.md)
- [CronTab](missConfig/crontab.md)
- [Hash in /ect/passwd](/tools/john.md)

## Pwn

Collection of pwn exploit, tools and payloads to help you control binaries.

### [Pwn.md](/pwn/pwn.md)

[Binaries Securities](/pwn/security-of-binaries.md)

- **Exploit**
  - [Ret2libc](pwn/ret2libc.md)
  - [FormatString](pwn/format-string.md)
  - [Shell Code Injection](pwn/shell-code-injection.md)
  - [Strcpy](/language/c/strcpy.md)
  - [Bypass Pie](/pwn/bypassPie.md)
  - [Ret2dl_resolve](/pwn/ret2dlresolve.md)
  - [ROP execve syscall](/pwn/rop-execve-syscall.md)
- **tools**
  - [Gdb-gef](tools/gdb/gdb-gef.md)
  - [Ghidra](tools/ghidra.md)
  - [ROPgadget](/tools/RopGadget.md)

#### Payload

- [PayloadPwn.md](pwn/payload.md)
- **Payload**
  - [Payload Vierge](pwn/payload/payload.py)
  - [Ret2libc without aslr payload](/pwn/payload/payload_ret2libc.py)
  - [Ret2libc with aslr payload](pwn/payload/payload_ret2libc_aslr.py)
  - [Shell-code-injection](/pwn/payload/payload-shell-code-injection.py)
  - [bypass PIE](/pwn/payload/payload_bypassPIE.py)

## Reverse

Reverse engineering is the process of analyzing and understanding a product, system, or software by deconstructing it to reveal its inner workings, design, or source code.

- [Set register in gdb](/tools/gdb/gdb-set-register.md)
- **tools**
  - [Ghidra](tools/ghidra.md)
  - [Gdb-gef](tools/gdb/gdb-gef.md)

## Web

A web exploit refers to a security vulnerability or technique used to take advantage of weaknesses in web applications, servers, or client-side components to gain unauthorized access, control, or steal sensitive information.

- [Web.md](/web/web.md)
  - **Client side**
    - [Md-to-Pdf injection](/web/md-to-pdf-injection.md)
    - [Pdf Injection](/web/pdf-injection.md)
    - [Xss](/web/xss.md)
    - [CSP](/web/csp.md)
    - [CSRF](/web/csrf.md)
  - **Server side**
    - [open redirect](/web/open-Redirect.md)
    - [bypass ip filtering](/web/bypasse-ip-filtering.md)

## Tools

- [John /etc/passwd hash brut force](tools/john.md)
- [PCAP file](tools/pcap.md)
- [Gdb-gef](tools/gdb/gdb-gef.md)
- [Ghidra](tools/ghidra.md)
- [ROPgadget](tools/RopGadget.md)
- [dirb](/tools/dirb.md)

## Languages

- [**C**](language/c/c.md)
  - [strcpy exploit](/language/c/strcpy.md)
  - [access_data_race](/language/c/access_data_race.md)
- [**php**](language/php/php.md)
  - [preg_replace](/language/php/preg_replace.md)
- [**bash**](/language/bash/bash.md)
  - [relative path to run binary](/language/bash/relative_path_binary.md)
- **Javascript**
  - [Js obfucated code](/language/java-script/js-obfuscation.md)
