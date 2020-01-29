import urllib2

def get_status(u):
    req = urllib2.Request(u)
    try:
        f = urllib2.urlopen(req)
        return f.code
    except urllib2.HTTPError, e:
		return e.code

with open("3.2.3_ciphertext.hex") as file:
	cipher_orig = file.read().strip()

blocks = []
for i in range(len(cipher_orig) / 32):
	blocks.append(cipher_orig[i*32:(i+1)*32])

plain = []
url = "http://cs461-mp3.sprai.org:8081/mp3/yaxinp2/?"
for i in range(1, len(blocks)):
	# print "block", str(i)
	p = [0] * 16
	ii = [0] * 16
	for j in range(15, -1, -1):
		p_prime = [0] * j + range(16, j, -1)
		c_prime = [0] * 16
		for k in range(j, 16):
			if k > j:
				c_prime[k] = p_prime[k] ^ ii[k]
		for k in range(0x100):
			c_prime[j] = k
			status = get_status(url + ''.join('{:02x}'.format(x) for x in c_prime) + blocks[i])
			if status == 404:
				break
		ii[j] = c_prime[j] ^ p_prime[j]
		p[j] = int(blocks[i - 1][j*2:(j+1)*2], 16) ^ ii[j]
	plain += p

print ''.join(chr(x) for x in plain)