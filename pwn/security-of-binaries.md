# Binaries Securities

Binaries are more and more secure, thanks to the implementation of modern protections like stack canaries, Address Space Layout Randomization (ASLR) and other security measures, which help mitigate common vulnerabilities and enhance the overall resilience against various exploitation techniques.


### Table of Content

- [RELRO](#relro)
- [Stack Canary](#stack-canary)
- [NX](#nx)
- [PIE](#pie-position-independent-executables)
- [Fortify](#fortify)
- [ASLR]()

## RELRO

RELRO is a generic exploit mitigation technique to harden the plt, plt.got and .got sections of an ELF binary or process. 

It come with 3 mode: 

### No RELRO :

- No securities, the firt time a shared function is called, the Got contains a pointer back to the pls where the dynamic linker (ld.so) is called to find the actual location of the fucntion. Next time the fucntion is call, the Got contain the know address.

### Partial RELRO :

- The ELF sections are reordered so that the ELF internal data sections (.got, .dtors, etc.) precede the program’s data sections (.data and .bss).

- Non-PLT GOT is read-only

- PLT-dependent GOT is still writeable

### Full RELRO : 

- featur of parial

- GOT is read-only : the program link the function before the code execution.

## Stack Canary

Stack Canary is a way to prevent stack-based buffer overflow. A variable is set between local variables and return pointer.

![canary shema](/pwn/img/StackCanaries_Fig3.png)

Stack Canary will be checked at the end of the function before the return. If the value is overwritten, it exit.

### Type of Canary

Type | Expample | Protection
--- | --- | ---
Null canary | 0x00000000 | 0x00
Terminator canary | 0x00000aff | 0x00, 0x0a, 0xff
Random Canary | \<any-4 bytes\> | 0x00f4d343d
Random Xor | | usually start with 0x00
64-bit | <8 byte>
custom canary


### Canary bypasses

- [Format-string attack.](/pwn/format-string.md)
- Brut force canary if the are 4 byte (16.777.216 possible canary values).
- overwrite a GOT function call before the return of the function.


## NX


No eXecute (NX Bit)

The No eXecute or the NX bit (also known as Data Execution Prevention or DEP) marks certain areas of the program as not executable, meaning that stored input or data cannot be executed as code.

This is significant because it prevents attackers from being able to jump to custom shellcode that they've stored on the stack or in a global variable.

## PIE (Position Independent Executables)

A PIE binary and all of its dependencies are loaded into random locations each time the application is executed.

[ByPass PIE](/pwn/bypassPie.md)

## Fortify

The FORTIFY_SOURCE macro provides lightweight support for detecting buffer overflows in various functions that perform operations on memory and strings.

FORTIFY_SOURCE works by computing the number of bytes that are going to be copied from a source to the destination.

FORTIFY_SOURCE provides buffer overflow checks for the following functions:
```
memcpy, mempcpy, memmove, memset,
strcpy, stpcpy, strncpy, strcat, strncat,
sprintf, vsprintf, snprintf, vsnprintf, 
gets.
```

## ASLR

Address space layout randomization (ASLR) is a technique that is used to increase the difficulty of performing a buffer overflow attack that requires the attacker to know the location of an executable in memory. 

ASLR is the equivalent of PIE but for all the RAM.

---

[**:arrow_right_hook: Back PWN**](/pwn/README.md)
