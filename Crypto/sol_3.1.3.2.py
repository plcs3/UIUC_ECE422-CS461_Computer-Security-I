import sys

with open(sys.argv[1]) as file, open(sys.argv[2], 'w') as output:
	file_content = file.read().strip()

	mask = 0x3fffffff
	outHash = 0
	for i in bytes(file_content):
		intermediate_value = ((ord(i) ^ 0xcc) << 24) | \
		                     ((ord(i) ^ 0x33) << 16) | \
		                     ((ord(i) ^ 0xaa) << 8) | \
		                     (ord(i) ^ 0x55)
		outHash = (outHash & mask) + (intermediate_value & mask)

	output.write(hex(outHash))
