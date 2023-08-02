# Shell Code Injection

Shell Code injection is a technique that allows the injection and execution of malicious code into a target program, providing full control over the compromised system.

### Table of Content

- [What is a Shell Code]()
- [Theory]()
- [Exploit]()

## What is a Shell code

A shellcode is a small piece of code written in low-level programming languages, typically assembly language, that is designed to be injected into a system to perform specific actions. It is primarily used in the context of computer security and exploits.

## Theory

When a function is call, it save a pointer at the top of the stack, pointing to next address instruction.

When the function is over, it take the pointer save on the stack and jump a this address to continue the program. But if we can overflow a local buffer, we can overwrite the return address.

Shell code injection consist, feeding our buffer with the shell code, and nop instruction. Finally overwrite the return address to the start of the buffer.

Why ? Because, when the function gonna end, it gonna jump to the address of our buffer, normally it should seg fault. But not this time, cause our buffer will be feed with executable shell code.

![Stack while shell code injection](/pwn/img/shell-code-injection.png)

## Exploit

### Condition :

- Buffer is enought large to store shell code.
- nx disable
- aslr disable
- pie disable

### Payload

Payload = 

- padding (\x90) NOP instruction
- Shell code
- Offset - sizeof(shell code)
- pointer to the start of the buffer (Easily discoverable through stack printing)

:warning: Add a padding is a good habit, sometime it help the shell code not crash even if you had well aimed the buffer in the stack.

[payload.py](/pwn/payload/payload-shell-code-injection.py)

---

[**:arrow_right_hook: Back PWN**](/pwn/pwn.md)