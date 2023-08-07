# Ret2Libc

This technique is uselfull for by passing nx protection

NX (NoExecute) is also called DEP (Data Execution Prevention) prevents execution of shellcode on the stack. This prevents the standard buffer overflow method since the shellcode on the memory doesnt get executed. This would result in a SIGSEGV error.

### Table of Contents

- [Theory](#theory)
- [Step with Aslr](#step-with-aslr)
- [Find Gadget](#find-gadgets)
- [Without ASLR](#without-aslr)
- [With ASLR](#with-aslr)

## Theory

Lets suppose this code in c:

```c
int main(void) {
    char command[] = "/bin/sh";
    system(command);
    return EXIT_SUCCESS;
}
```

To understand how do a ret2libc, you need to understand how system is call:

- it load /bin/sh in the stack
- call system()

![stack_img](/pwn/img/stack_bin.png)

Instruction call, push EIP ; jmp \<address\>

so affer call instruction stack = 

![stack_after_call](/pwn/img/stack_after_call.png)

Now we see how the stack should be before call to system fucntion we can construt the payload: 

Payload : [ Offset ] [ system() address] [ return address] [ "/bin/sh" address ]

### Print value in gdb

```py
info functions system
0xf7e6aed0  system

info functions exit
0xf7e5eb70  exit

info proc mapping
0xf7e2c000 0xf7fcc000   0x1a0000        0x0 /lib32/libc-2.15.so
find 0xf7e2c000, 0xf7fcc000, "/bin/sh"
0xf7f897ec
1 pattern found.
```

[Gdb usage](/tools/gdb/gdb-usage.md)

## Step with aslr and gadget

Here's the high-level overview of the ret2libc attack with gadget loading (/bin/sh) in rdi:

- Step 1: Find gadgets: Identify useful gadgets in the binary, such as pop rdi; ret, which sets the rdi register to a specific value and then returns to the next instruction.

- Step 2: Leak libc address: Use a ROP chain to call a function like puts to leak the address of a function in the libc library, like system.

- Step 3: Calculate libc base address: Determine the base address of the libc library by subtracting the offset of the leaked function (e.g., system) from its known address in the libc.

- Step 4: Craft the final payload: Construct a ROP chain that sets the necessary function arguments (e.g., the address of /bin/sh) and calls the desired libc function (e.g., system) using gadgets found in the binary and the libc base address.

## Find Gadgets

```ROPgadget --binary ./vulnerable.out | grep "pop rdi; ret"```

- [ROPgadget](/tools/RopGadget.md)

## Without ASLR

Payload = 

- offset of overflow

- libc address (from ```ldd command```)

- pop rdi gadget

- string '/bin/sh' (from libc load into rdi with the gadget)

- symbols of '/system' (call system function with '/bin/sh' argument)

[Payload.py](/pwn/payload/payload_ret2libc.py)

## With ASLR

With ASLR, address of libc is randomized, so we need to leak it for find string and system function. 

First payload is for call puts function, which gonna print the puts address located in the libc.

Payload 1 = 

- offset to overflow

- puts address from .got section

- call the main function

Read the leaked puts and determine the address of libc

Payload 2 is same as no ASLR.

[Payload.py](/pwn/payload/payload_ret2libc_aslr.py)

## Documentation

- [French demonstration](https://beta.hackndo.com/retour-a-la-libc/)

---

[**:arrow_right_hook: Back PWN**](/pwn/pwn.md)