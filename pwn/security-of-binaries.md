# Binaries Securities

Binaries are more and more secure, thanks to the implementation of modern protections like stack canaries, Address Space Layout Randomization (ASLR) and other security measures, which help mitigate common vulnerabilities and enhance the overall resilience against various exploitation techniques.


### Table of Content

- [RELRO]()
- [Stack Canary]()
- [NX]()
- [PIE]()
- [Fortify ?]()

## RELRO

RELRO is a generic exploit mitigation technique to harden the data sections of an ELF binary or process. 

It come with 3 mode: 

### No RELRO

### Partial RELRO :

- The ELF sections are reordered so that the ELF internal data sections (.got, .dtors, etc.) precede the program’s data sections (.data and .bss).

- Non-PLT GOT is read-only

- PLT-dependent GOT is still writeable

### Full RELRO : 

- featur of parial

- GOT is read-only

---

[**:arrow_right_hook: Back PWN**](/pwn/pwn.md)