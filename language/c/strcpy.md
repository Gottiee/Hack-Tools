# Strcpy Exploit

From the man:
```
BUGS:
If the destination string of a strcpy() is not large enough, then anything might happen. 

Overflowing fixed-length string buffers is a favorite cracker technique for taking complete control of the machine.
Any time a program reads or copies data into a buffer, the program first needs to check that there's enough space.
```

### Recognition

When strcpy is vulnerable:

- dest is smaller than src

- you can control src

### Exploit

Its a heap base exploit, we can overwrite data in the heap.

Print the heap in gdb:
```c
// print memory mapping of process
gef➤ info  proc mappings 
process 20093
Mapped address spaces:

	Start Addr   End Addr       Size     Offset  Perms   objfile
	 0x8048000  0x8049000     0x1000        0x0  r-xp  
	 0x8049000  0x804a000     0x1000        0x0  rw-p   
	 0x804a000  0x806c000    0x22000        0x0  rw-p   [heap]
	 // heap start at 0x804a000

// printing 400 word(4byte) in hexa of the heap
gef➤  x/400xw 0x804a000
...
```

---

[**:arrow_right_hook: Back c**](c.md)