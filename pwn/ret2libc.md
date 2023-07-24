# Ret2Libc

This technique is uselfull for by passing nx protection

NX (NoExecute) is also called DEP (Data Execution Prevention) prevents execution of shellcode on the stack. This prevents the standard buffer overflow method since the shellcode on the memory doesnt get executed. This would result in a SIGSEGV error.

### Table of Contents

- [Theory](#theory)
- [Find Gadget](#find-gadgets)
- [Without ASLR](#without-aslr)
- [With ASLR](#with-aslr)

## Theory

Here's the high-level overview of the ret2libc attack:

- Step 1: Find gadgets: Identify useful gadgets in the binary, such as pop rdi; ret, which sets the rdi register to a specific value and then returns to the next instruction.

```c
//Step 2 and 3 are necessary only if ASLR is enable
```

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

---

[**:arrow_right_hook: Back PWN**](/pwn/pwn.md)