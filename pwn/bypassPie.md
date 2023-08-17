# Bypass Pie

PIE binary and all of its dependencies are loaded into random locations each time the aplication is executed.

## Leak addresses

PIE randomise address function, and can compromise ROP.

First of all, you need to find an address of a function and leak it.

### printf

You can use format string attack to get addresses from the stack.

- [format string vuln](/pwn/format-string.md#read-data)

## Exploit

To exploit leaked address you need to calculate the offset the target function.

Simple exemple:

```py
gdb >

info function main
0xbfffa056

info function vuln
0xbfffb000

print 0xbfffa056-0xbfffb000
?
```

If you add or sub offset to the leak address, you can call it.

- [Payload bypass PIE](/pwn/payload/payload_bypassPIE.py)
