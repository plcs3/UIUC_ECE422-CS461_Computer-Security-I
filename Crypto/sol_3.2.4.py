from fractions import gcd
from Crypto.PublicKey import RSA
import pbp


# reference: https://facthacks.cr.yp.to/product.html
def producttree(X):
    result = [X]
    while len(result[-1]) > 1:
        X = result[-1]
        l = len(X)
        tmp = [X[i*2]*X[i*2+1] for i in range(l/2)]
        if l % 2 == 1:
            tmp.append(X[l-1])
        result.append(tmp)
    return result


# reference: https://facthacks.cr.yp.to/remainder.html
def remaindersusingproducttree(n, T):
	result = [n]
	for t in reversed(T):
		result = [result[i//2] % t[i] for i in range(len(t))]
	return result


# reference: https://github.com/rauhul/ece422/blob/master/mp3/sol_3.2.4.py
def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def get_gcd(R, X):
	V = [gcd(r/n, n) for r, n in zip(R, X)]
	result = []
	for i in range(len(V)):
		if V[i] != 1:
			result.append((V[i], X[i]))
	return result


with open("moduli.hex") as moduli_file, open("3.2.4_ciphertext.enc.asc") as cipher_file:
	cipher = cipher_file.read().replace("\r\n", "\n")
	moduli = moduli_file.readlines()
	for i in range(len(moduli)):
		moduli[i] = int(moduli[i].strip(), 16)


T = producttree(moduli)
prod = T[-1][0]
tmp = []
for i in range(len(T)):
	tmp.append([T[i][j]**2 for j in range(len(T[i]))])
T = tmp
remainder_list = remaindersusingproducttree(prod, T)
gcd_list = get_gcd(remainder_list, moduli)


with open("sol_3.2.4.txt", 'w') as output:
	e = long(65537)
	for i in range(len(gcd_list)):
		p = gcd_list[i][0]
		N = gcd_list[i][1]
		q = N//p
		d = modinv(e, (p - 1)*(q - 1))
		key = RSA.construct((long(N), long(e), long(d)))
		try:
			plain = pbp.decrypt(key, cipher)
			print(plain)
			output.write(plain)
		except ValueError:
			pass
