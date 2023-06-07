from pwn import *
import sys

exe = ELF("./l_alchimiste")
context.binary = exe.path
HOST = ''
PORT = -1

def conn():
    if args.REMOTE:
        r = remote(HOST, PORT)
    elif args.TRACE:
        r  = process(["strace", "-o","strace.out", exe.path])
    else:
        r = process([exe.path])
    return r

def main():
    r = conn()
    # gdb.attach(r)

    # rep = r.recvuntil(b'>>> ')
    # r.send(b'1\n')

    rep = r.recv()
    print(rep.decode())
    # r.interactive()

if __name__ == "__main__":
	main()