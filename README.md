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

- [CORS (cross origing ressources sharing)](/web/cors.md)
- [Open redirect](/web/client-side/open-Redirect.md)
- **Client side**
  - [Xss (cross site scripting)](/web/client-side/xss/xss.md)
    - [WAF bypass XSS](/web/client-side/xss/WAF-bypass.md)
    - **DOM BASED**
      - [DOM based JS injection](/language/java-script/DOM-based-js-injection.md)
      - [web Message](/web/client-side/xss/web-message.md)
  - [CSP (content security policy)](/web/client-side/csp.md)
  - [CSRF (client side request forgery)](/web/client-side/csrf.md)
    - [bypass validation token](/web/client-side/csrf.md#bypassing-csrf-token-validation)
    - [bypass SameSite Strict restrictions](/web/client-side/bypass-Samesite-strict.md)
    - [bypass SameSite lax restrictions](/web/client-side/bypass-Samesite-lax.md)
    - [Bypassing Referer-based CSRF defenses](#bypassing-referer-based-csrf-defenses)
  - [Clickjacking](/web/client-side/clickjacking.md)
  - [DOM-clobbering](/web/client-side/DOM-clobbering.md)
  - [Insecure source code management](/web/client-side/insecure-src-code-management.md)
- **Server side**
  - [Md-to-Pdf injection](/web/server-side/md-to-pdf-injection.md)
  - [Pdf Injection](/web/server-side/pdf-injection.md)
  - [bypass ip filtering](/web/server-side/bypasse-ip-filtering.md)
  - [Acess-Control](/web/server-side/access-control.md)
    - [Unprotected functionality](/web/server-side/access-control.md#unprotected-functionality)
    - [Parameter-based access control method](/web/server-side/access-control.md#parameter-based-access-control-method)
    - [Horizontal privilerge escaladation](/web/server-side/access-control.md#horizontal-privilerge-escaladation)
    - [Path Traversal](/web/server-side/path-traversal.md)
  - [Authentification](/web/server-side/authentification.md)
    - [Bypass 2FA](/web/server-side/authentification.md#bypass-2fa-two-factor-authentification)
    - [UserName Enumeration](/web/server-side/authentification.md#username-enumeration)
    - [Brut Force with Burpsuite](/tools/burpsuite/brutforce.md)
  - [SSRF (server side request forgery)](/web/server-side/ssrf.md)
  - [Upload files](/web/server-side/upload-files.md)
  - [OS command injection](/web/server-side/os-command-injection.md)
  - [sql injection](/language/sql/README.md)
    - [retrieving hidden data](/language/sql/retrieving-hidden-data.md)
    - [bypass login](/language/sql/bypass-login.md)
    - [Union attack](/language/sql/union-injection.md)
    - [Examin database](/language/sql/examin-database.md)
    - [Blind Injection](/language/sql/blind-injection.md)
  - [Sql filter bypass via XML encoding](/web/server-side/bypass-filter-with-XML-encode.md)
  - [XEE (xml external entity injection)](/web/server-side/xxe.md)
  - [http request smuggling](/web/server-side/request-smuggling.md)
  - [Template injection](/web/server-side/template-injection.md)
  - [Web-Sockets](/web/server-side/web-socket.md)
  - [Web Cache Poisoning](/web/server-side/web-cache-poisoning.md)

## Tools

- [John /etc/passwd hash brut force](tools/john.md)
- [PCAP file](tools/pcap.md)
- [Gdb-gef](tools/gdb/gdb-gef.md)
- [Ghidra](tools/ghidra.md)
- [ROPgadget](tools/RopGadget.md)
- [dirb](/tools/dirb.md)
- feroxbuster (fuzzer)
- [burpsuite](/tools/burpsuite/README.md)
- gowitness
- shodan.io / [docu shodan](https://github.com/lothos612/shodan)``
- [weakPassword site list](https://weakpass.com/)
- [FreeOffice](https://massgrave.dev)

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
   
## AD

[MindMap AD](https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2022_11.svg)
[Notion Interessante sur l'AD](https://www.thehacker.recipes/ad/recon)

## Pentest Port

- [Git hub ressource](https://github.com/six2dez/pentest-book/blob/master/enumeration/ports.md)
