# RopGadget

Gadgets are small snippets of code followed by a ret instruction, e.g. pop rdi; ret. We can manipulate the ret of these gadgets in such a way as to string together a large chain of them to do what we want.

To sum up, gadgets are addresses pointing to the end of a function. And can be usefull to take control of program execution.

## Usage

```ROPgadget --binary ./vulnerable.out | grep "pop rdi; ret"```

## Exemple

```bash
$> ROPgadget --binary ./level05 | grep "call eax"
0x08048439 : add al, 0x24 ; clc ; xchg esi, eax ; add al, 8 ; call eax
0x0804843d : add al, 8 ; call eax
0x080485b4 : add al, 8 ; nop ; sub ebx, 4 ; call eax
0x0804843a : and al, 0xf8 ; xchg esi, eax ; add al, 8 ; call eax
0x0804843f : call eax
```

And if we take a look in gdb at address 0x0804843f: 

```py
disas 0x0804843f
Dump of assembler code for function frame_dummy:
   0x08048420 <+0>:	push   ebp
   0x08048421 <+1>:	mov    ebp,esp
   0x08048423 <+3>:	sub    esp,0x18
   0x08048426 <+6>:	mov    eax,ds:0x80496f8
   0x0804842b <+11>:	test   eax,eax
   0x0804842d <+13>:	je     0x8048441 <frame_dummy+33>
   0x0804842f <+15>:	mov    eax,0x0
   0x08048434 <+20>:	test   eax,eax
   0x08048436 <+22>:	je     0x8048441 <frame_dummy+33>
   0x08048438 <+24>:	mov    DWORD PTR [esp],0x80496f8
   0x0804843f <+31>:	call   eax
   0x08048441 <+33>:	leave  
   0x08048442 <+34>:	ret    
   0x08048443 <+35>:	nop
End of assembler dump.
```

As you can see, address 0x0804843f is the end of the fucntion frame_dummy(). 

### Documentation

- [Git hub ROPgadget](https://github.com/JonathanSalwan/ROPgadget)
---

[**:arrow_right_hook: Back home**](/README.md)