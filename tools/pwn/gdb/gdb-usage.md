# Gdb Usage

Gdb tips tricks and usefull command.

### Table of Contents

- [Print content](#print-content)
- [Breackpoints](#breackpoints)
- [Run with pyton input](#run-gdb-with-user-input-python)
- [Remote connection](#gdb-remote-connection)
- [Usefull Command](#command)
- [GDB script](#gdb-script)
- [Looking for strings](#)

## Print Content

### Print Info from register

- print les registers `info register`
- prints la frame `info frame`

| Print Command | Format of print |
| ------------- | --------------- |
| `x/x $rsp`    | print hexa      |
| `x/d $rsp`    | print decimal   |
| `x/s $rsp`    | prnit string    |
| `x/c $rax`    | print char      |
| `x/t $rax`    | print binaire   |
| `x/a $rsp`    | print pointeur  |

#### Additional info while printing

- `x/30x $rsp` print 30 lign of $rsp.
- you can precisce if you wnat print the output in byte, word(32) or double word(64)

| Print Command | Format of print |
| ------------- | --------------- |
| `x/bx $rsp`   | byte            |
| `x/wx $rsp`   | x32             |
| `x/gx $rsp`   | x64             |

### print heap

- `heap chunks` : print allocated chunks
- you can then print them with they address

## Breackpoints

If no main found, try `b _start`

- We can add breackpoints with address `b *0x555555`
- Or with fucntion + `b *main+355`

## Run GDB with user input python

- `run < <(python3 -c "print('A' * 200)")`

Will run the program, and take as input the python command.

Same as: `python3 -c "print('A' * 200)") | ./vulnerable`

## GDB Remote Connection

- `gef-remote address_IP:port`

## GDB Script

Gdb script are easy, you can type commands follow by `\n` and they'll be executed

example:

```gdb
break *main+45
run
set $eax=1
next
x/s $eax
```

## Command

| Command              | Explanation            |
| -------------------- | ---------------------- |
| `Backtrace`          | ?                      |
| `info proc mappings` | print mapped addresses |
| `info file`          | print sections         |


## Looking for strings

You can located a string address by providing the start address, end address and the string.

```find 0x00, 0xff, "a"```

For example, let's find "/bin/sh" in the libc.so.6

```py
info proc mapping
0xf7e2c000 0xf7fcc000   0x1a0000        0x0 /lib32/libc-2.15.so

find 0xf7e2c000, 0xf7fcc000, "/bin/sh"
0xf7f897ec
1 pattern found.
```

#### Usage :

```gdb
gdb ./a.out
source my_script.gdb
```

---

[**:arrow_right_hook: Back GDB**](/tools/pwn/gdb/README.md)
