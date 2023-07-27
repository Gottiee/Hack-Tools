# Format string

 Format string exploit vulnerabilities in programs by abusing the '%x' power, reading and writing int the stack with printf() and sprintf() functions. It can leak sensitive information and even take control of the function.

### Table of Content

- [Before Exploit]()
- [Read the stack]()
- [OverWrite data]()
- [Code execution redirect]()
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

## OverWrite Data 

You can overwrite data with printf and `%n`.

From the man: `The number of characters already written is stored in the integer pointed to by the argument of type int *. No argument is converted.`

```c
printf("AAAA%n", (int)a);
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


 
### Docum

- [Insane Tuto](https://axcheron.github.io/exploit-101-format-strings/)

---

[**:arrow_right_hook: Back PWN**](/pwn/pwn.md)