# Pwn

To dominate in such a fashion as to gain ownership. A network, system, organization, or rival that comes under an adversary's control is said to have been pwned.

If you are not familiar with Assembly take a look at my [asm cheat sheat](https://github.com/Gottiee/asm)

### Table of Contents

- [Recognition](#recognition)
- [Payload](#payload)
- [Tools](#tools)
- [Usefull Command](#usefull-cmd)
- [Documentation](#documentation)

## Recognition

- Nx enable (with and without ASLR)
	- Libc.so.6 linked
		- [ret2libc](/pwn/ret2libc.md)
- Nx disable
	- no aslr
		- [Shell Code Injection](/pwn/shell-code-injection.md)
- `printf(variable)` // no protection
	- [Format string](/pwn/format-string.md)
- strcpy
	- dest smaller than src
		- [strcpy exploit](/language/c/strcpy.md)

## Payload

- [Payload explain](/pwn/payload.md)
- **Payload.py**
	- [Payload.py](/pwn/payload/payload.py)
	- [Ret2libc_aslr_Payload.py](/pwn/payload/payload_ret2libc_aslr.py)
	- [Ret2libc_without_aslr.py](/pwn/payload/payload_ret2libc.py)
	- [Shell-code-injection.py](/pwn/payload/payload-shell-code-injection.py)


## Tools

- [Gdb-gef](/tools/gdb-gef.md)
- [Ghidra](/tools/ghidra.md)
- [ROPgadget](/tools/RopGadget.md)

## Usefull Cmd

Cmd | explanation
--- | ---
```ldd <binary file>``` | check which library is used
```cat /proc/sys/kernel/randomize_va_space``` | '0' no aslr / '1' aslr for lib / '2' aslr for lib and exe
```cat <(python /tmp/exec.py)- \| ./exploit.me``` | interactive exploit with cat command bloque

### Documentation

- [Cheat sheet buffer Overflow](https://www.0x0ff.info/2014/segmentation-memoire-buffer-overflow/)

---

[**:arrow_right_hook: Back home**](/README.md)
