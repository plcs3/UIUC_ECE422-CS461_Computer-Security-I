import sys
from Crypto.Hash import SHA256

with open(sys.argv[1]) as file1, open(sys.argv[2]) as file2, open(sys.argv[3], 'w') as output:
	file1_content = file1.read().strip()
	file2_content = file2.read().strip()

	file1_binary = bin(int(SHA256.new(file1_content).hexdigest(), 16))[2:].zfill(256)
	file2_binary = bin(int(SHA256.new(file2_content).hexdigest(), 16))[2:].zfill(256)

	dist = 0
	for i in range(0, 256):
		if file1_binary[i] != file2_binary[i]:
			dist += 1

	output.write(str(hex(dist)[2:]))

# $ python sol_3.1.3.1.py 3.1.3.1_input_string.txt 3.1.3.1_perturbed_string.txt sol_3.1.3.1.hex
