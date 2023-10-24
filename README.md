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
- **Other**
  - [Construct your own shellCode](/pwn/construct_shellcode.md)

#### Payload

- [PayloadPwn.md](pwn/payload.md)
- **Payload**
  - [Payload Vierge](pwn/payload/payload.py)
  - [Ret2libc without aslr payload](/pwn/payload/payload_ret2libc.py)
  - [Ret2libc with aslr payload](pwn/payload/payload_ret2libc_aslr.py)
  - [Shell-code-injection](/pwn/payload/payload-shell-code-injection.py)
  - [bypass PIE](/pwn/payload/payload_bypassPIE.py)
  - [ret2dlresolve_32bit_partialRELRO](/pwn/payload/payload_ret2dlresolve_32bit_partialRELRO.py)

## Reverse

Reverse engineering is the process of analyzing and understanding a product, system, or software by deconstructing it to reveal its inner workings, design, or source code.

- [Call an uncall function in gdb](/tools/gdb/gdb-call-func.md)
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
      - [WAF bypass XSS](/web/WAF-bypass.md)
    - [CSP](/web/csp.md)
    - [CSRF](/web/csrf.md)
  - **Server side**
    - [open redirect](/web/open-Redirect.md)
    - [bypass ip filtering](/web/bypasse-ip-filtering.md)
    - [Acess-Control](/web/access-control.md)
      - [Unprotected functionality](/web/access-control.md#unprotected-functionality)
      - [Parameter-based access control method](/web/access-control.md#parameter-based-access-control-method)
      - [Horizontal privilerge escaladation](/web/access-control.md#horizontal-privilerge-escaladation)
      - [Path Traversal](/web/path-traversal.md)
    - [Authentification](/web/authentification.md)
      - [Bypass 2FA](/web/authentification.md#bypass-2fa-two-factor-authentification)
      - [UserName Enumeration](/web/authentification.md#username-enumeration)
      - [Brut Force with Burpsuite](/tools/burpsuite/brutforce.md)
    - [SSRF (server side request forgery)](/web/ssrf.md)
    - [Upload files](/web/upload-files.md)
    - [command injection](/web/command-injection.md)
    - [sql injection](/language/sql/README.md)
      - [retrieving hidden data](/language/sql/retrieving-hidden-data.md)
      - [bypass login](/language/sql/bypass-login.md)
      - [Union attack](/language/sql/union-injection.md)
      - [Examin database](/language/sql/examin-database.md)
      - [Blind Injection](/language/sql/blind-injection.md)
    - [Sql filter bypass via XML encoding](/web/bypass-filter-with-XML-encode.md)

## Tools

- [John /etc/passwd hash brut force](tools/john.md)
- [PCAP file](tools/pcap.md)
- [Gdb-gef](tools/gdb/gdb-gef.md)
- [Ghidra](tools/ghidra.md)
- [ROPgadget](tools/RopGadget.md)
- [dirb](/tools/dirb.md)
- [burpsuite](/tools/burpsuite/README.md)

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
- **Sql**
  - [sql injection](/language/sql/README.md)
		- [retrieving hidden data](/language/sql/retrieving-hidden-data.md)
		- [bypass login](/language/sql/bypass-login.md)
		- [Union attack](/language/sql/union-injection.md)
		- [Examin database](/language/sql/examin-database.md)