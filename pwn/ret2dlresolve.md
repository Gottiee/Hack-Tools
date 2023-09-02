# Ret2dlResolve

Ret2dlresolve is a technique used in binary exploitation to exploit vulnerable programs by manipulating dynamic linker and resolver functions, allowing an attacker to execute arbitrary code or gain control of a compromised system. 

It allow attackers to resolve and call functions from shared libraries even in the presence of stack canaries or non-executable memory protections.

:warning: This bypass is not effectiv if RELRO is fully enable because that prevents modifications to the Global Offset Table (GOT) and the Procedure Linkage Table (PLT), making it difficult to manipulate function pointers.

### Table of Content

## Context and theory

### None dynamic programs

Lets say we have two file main.c and foo.c.

![function](/pwn/img/function.png)

```
```
---

[**:arrow_right_hook: Back PWN**](/pwn/pwn.md)