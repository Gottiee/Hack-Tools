# Ret2dlResolve

Ret2dlresolve is a technique used in binary exploitation to exploit vulnerable programs by manipulating dynamic linker and resolver functions, allowing an attacker to execute arbitrary code or gain control of a compromised system. 

It allow attackers to resolve and call functions from shared libraries even in the presence of stack canaries or non-executable memory protections.

:warning: This bypass is not effectiv if RELRO is fully enable because that prevents modifications to the Global Offset Table (GOT) and the Procedure Linkage Table (PLT), making it difficult to manipulate function pointers.

### Table of Content

- [Context and Theory](#context-and-theory)
	- [Compile a Program without libraries](#compiled-a-program-without-libraries)
	- [Compile a Program with libraries](#compile-a-program-with-libraries)
		- [Statically link](#static-libraries)
		- [Dynamically link](#dynamic-linking)


## Context and theory

### Compiled a Program without libraries

Lets say we have two file main.c and foo.c.

![function](/pwn/img/function.png)

**Symbol** resolution is defined as find a single definition for each symbol and **Relocation** is defined as update each reference to a symbol with the runtime address of the definition.

To create an executable it merge the sections from mutiple object files together and update symbol reference.

![relocation](/pwn/img/relocation.png)

```bash
$> gcc -c main.c foo.c
```

First on main.o, f() is defined on symbol table but call undefined and the program will fix it: 

```bash
$> objdump main.o -tTrR

SYMBOL TABLE:
0000000000000000 l    df *ABS*	0000000000000000 main.c
0000000000000000 l    d  .text	0000000000000000 .text
0000000000000000 g     F .text	0000000000000014 main
0000000000000000         *UND*	0000000000000000 f
```

We can print the things that compiler need to do to create the executable. This things are stored in the **.rela** section.

```bash
$> readelf -r main.o 

Relocation section '.rela.text' at offset 0x160 contains 1 entry:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000000009  000400000004 R_X86_64_PLT32    0000000000000000 f - 4
```

As we can see here, the f() symbol need to be fix.

```bash
# Another way to see the call to f() undefined
$> objdump main.o -dx

0000000000000000 <main>:
   0:	f3 0f 1e fa          	endbr64 
   4:	55                   	push   %rbp
   5:	48 89 e5             	mov    %rsp,%rbp
   8:	e8 00 00 00 00       	call   d <main+0xd>
			9: R_X86_64_PLT32	f-0x4
   d:	b8 00 00 00 00       	mov    $0x0,%eax
  12:	5d                   	pop    %rbp
  13:	c3                   	ret    
```

Address of f() isn't defined `e8 00 00 00 00`.

Now lets print the a.out:

```bash
# call is fix now !
$> objdump a.out -dx

0000000000001129 <main>:
    1129:	f3 0f 1e fa          	endbr64 
    112d:	55                   	push   %rbp
    112e:	48 89 e5             	mov    %rsp,%rbp
    1131:	e8 07 00 00 00       	call   113d <f>
    1136:	b8 00 00 00 00       	mov    $0x0,%eax
    113b:	5d                   	pop    %rbp
    113c:	c3                   	ret    
```

### Compile a Program with libraries

In addition with every thing we saw earlier, libraries are often used in programs. This libraries can be add statically or dynamically.

### Static Libraries

Static libraries are link at *load time* (opposit of at *run time* (during the execution)).

```c
#include <stdio.h>

int main(void) {
    printf("test");
}
```

```bash
$> gcc -c main.c -static
$> readelf -r main.o

Relocation section '.rela.text' at offset 0x198 contains 2 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
00000000000b  000300000002 R_X86_64_PC32     0000000000000000 .rodata - 4
000000000018  000500000004 R_X86_64_PLT32    0000000000000000 printf - 4
```

As we can see, `.rodata` and `printf` need to be resolve.

```bash
$> gcc main.o -static
$> objdump a.out -dx

0000000000401745 <main>:
  401745:       f3 0f 1e fa             endbr64 
  401749:       55                      push   %rbp
  40174a:       48 89 e5                mov    %rsp,%rbp
  40174d:       48 8d 05 b0 68 09 00    lea    0x968b0(%rip),%rax        # 498004 <_IO_stdin_used+0x4>
  401754:       48 89 c7                mov    %rax,%rdi
  401757:       b8 00 00 00 00          mov    $0x0,%eax
  40175c:       e8 2f 9e 00 00          call   40b590 <_IO_printf>
  401761:       b8 00 00 00 00          mov    $0x0,%eax
  401766:       5d                      pop    %rbp
  401767:       c3                      ret    
  401768:       0f 1f 84 00 00 00 00    nopl   0x0(%rax,%rax,1)
  40176f:       00
```

Compiler add printf at the .text section.

The problem is the size of the executable. Static link load every function used in the program inside the executable increasing the size of it.

```bash
$> gcc main.c -static | ls -lh
total 892K
-rwxrwxr-x 1 gottie gottie 880K sept. 11 12:18 a.out
$> gcc main.c | ls -lh
total 28K
-rwxrwxr-x 1 gottie gottie  16K sept. 11 12:19 a.out
```

880k against 16k for the dynamic linking.

### Dynamic linking



---

[**:arrow_right_hook: Back PWN**](/pwn/pwn.md)