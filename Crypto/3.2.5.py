from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Util import number
import datetime
import hashlib

def make_privkey(p, q, e=65537):
    n = p*q
    d = number.inverse(e, (p-1)*(q-1))
    iqmp = rsa.rsa_crt_iqmp(p, q)
    dmp1 = rsa.rsa_crt_dmp1(e, p)
    dmq1 = rsa.rsa_crt_dmq1(e, q)
    pub = rsa.RSAPublicNumbers(e, n)
    priv = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pub)
    pubkey = pub.public_key(default_backend())
    privkey = priv.private_key(default_backend())
    return privkey, pubkey

ECE422_CA_KEY, _ = make_privkey(10079837932680313890725674772329055312250162830693868271013434682662268814922750963675856567706681171296108872827833356591812054395386958035290562247234129L,13163651464911583997026492881858274788486668578223035498305816909362511746924643587136062739021191348507041268931762911905682994080218247441199975205717651L)

def make_cert(netid, pubkey, ca_key = ECE422_CA_KEY, serial=int("0x412a4213417257147a0b0daa6b734ce2d9f569d9", 16)):
    builder = x509.CertificateBuilder()
    builder = builder.not_valid_before(datetime.datetime(2017, 3, 1))
    builder = builder.not_valid_after (datetime.datetime(2017, 3,27))
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, unicode(netid)),
        x509.NameAttribute(NameOID.PSEUDONYM, u'a' * 60),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Illinois'),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'ece422'),
]))
    builder = builder.serial_number(serial)
    builder = builder.public_key(pubkey)
    cert = builder.sign(private_key=ECE422_CA_KEY, algorithm=hashes.MD5(), backend=default_backend())
    return cert

def make_tmpcert():
	p = number.getPrime(1024)
	q = number.getPrime(1024)
	assert(p.bit_length() == 1024)
	assert(q.bit_length() == 1024)
	assert( (p*q).bit_length() == 2047 )

	netid = "yaxinp2"
	privkey, pubkey = make_privkey(p, q)
	cert = make_cert(netid, pubkey)
	print 'md5 of cert.tbs_certificate_bytes:', hashlib.md5(cert.tbs_certificate_bytes).hexdigest()

	with open("tmp.cer", 'wb') as out:
	    out.write(cert.public_bytes(Encoding.DER))

def cut_prefix():
	with open("tmp.cer", 'r') as f, open("prefix", 'w') as output:
		prefix = f.read(256)
		assert(len(prefix) % 64 == 0)
		output.write(prefix)

def get_bitstrings():
	with open("col1", 'r') as col1, open("col2", 'r') as col2:
		bitString1 = col1.read()
		bitString2 = col2.read()
		assert(len(bitString1) == 384)
		assert(len(bitString2) == 384)
		bitString1 = bitString1[256:]
		bitString2 = bitString2[256:]
		assert(len(bitString1) == 128)
		assert(len(bitString2) == 128)

	tmp1 = ""
	for i in bitString1:
		tmp1 = tmp1 + '{:02x}'.format(ord(i))
	b1 = long(tmp1, 16)

	tmp2 = ""
	for i in bitString2:
		tmp2 = tmp2 + '{:02x}'.format(ord(i))
	b2 = long(tmp2, 16)

	assert(b1.bit_length() == 1023)
	assert(b2.bit_length() == 1023)

	b1 = b1 << 1024
	b2 = b2 << 1024
	assert(b1 % (2**1024) == 0)
	assert(b2 % (2**1024) == 0)

	with open("b1", 'w') as out1, open("b2", 'w') as out2:
		out1.write(str(b1))
		out2.write(str(b2))

def chinese_remainder_theorem(p1, p2, a1, a2):
	z1 = number.inverse(p2, p1)
	z2 = number.inverse(p1, p2)
	b0 = a1 * p2 * z1 + a2 * p1 * z2
	return b0 % (p1 * p2)

def construct_moduli():
	with open("b1") as f1, open("b2") as f2:
		b1 = long(f1.read())
		b2 = long(f2.read())

	e = long(65537)
	p1 = number.getPrime(500)
	p2 = number.getPrime(500)
	assert(p1 != p2)
	assert(number.GCD(e, p1-1) == 1)
	assert(number.GCD(e, p2-1) == 1)
	print p1
	print p2

	a1 = p1 - b1 % p1
	a2 = p2 - b2 % p2
	b0 = chinese_remainder_theorem(p1, p2, a1, a2)
	assert(b0 < p1 * p2)
	assert(number.GCD(b1 + b0, p1) == p1)
	assert(number.GCD(b2 + b0, p2) == p2)
	assert((b1 + b0) % p1 == 0)
	assert((b2 + b0) % p2 == 0)
	print b0

	k = 0
	while True:
		b = b0 + k * p1 * p2
		if b >= 2**1024:
			raise Exception('failed to find b')
		q1 = (b1 + b) / p1
		if not number.isPrime(q1) or number.GCD(e, q1-1) != 1:
			k = k + 1
			continue
		q2 = (b1 + b) / p2
		if not number.isPrime(q2) or number.GCD(e, q2-1) != 1:
			k = k + 1
			continue
		n1 = b1 + b
		n2 = b2 + b
		break
	print b
	assert(p1.bit_length() > 256)
	assert(p2.bit_length() > 256)
	assert(q1.bit_length() > 256)
	assert(q2.bit_length() > 256)
	assert(n1.bit_length() == 2047)
	assert(n2.bit_length() == 2047)

	print n1
	print p1
	print q1
	print n2
	print p2
	print q2

	with open("moduli1", 'w') as m1, open("moduli2", 'w') as m2, open("sol_3.2.5_factorsA.hex", 'w') as factors1, open("sol_3.2.5_factorsB.hex", 'w') as factors2:
		m1.write(hex(n1)[2:])
		m2.write(hex(n2)[2:])
		factors1.write(hex(p1)[2:] + "\n" + hex(q1)[2:] + "\n")
		factors2.write(hex(p2)[2:] + "\n" + hex(q2)[2:] + "\n")

def make_certAB():
	with open("sol_3.2.5_factorsA.hex") as f1, open("sol_3.2.5_factorsB.hex") as f2:
		[p1, q1] = [int(i.strip()[:-1], 16) for i in f1.readlines()]
		[p2, q2] = [int(i.strip()[:-1], 16) for i in f2.readlines()]
		_, pubkey1 = make_privkey(p1, q1)
		_, pubkey2 = make_privkey(p2, q2)
	with open("moduli1") as moduli1, open("moduli2") as moduli2:
		m1 = long(moduli1.read().strip(), 16)
		m2 = long(moduli2.read().strip(), 16)
		assert(m1 == p1 * q1)
		assert(m2 == p2 * q2)

	netid = "yaxinp2"
	cert1 = make_cert(netid, pubkey1)
	cert2 = make_cert(netid, pubkey2)
	print 'md5 of cert1.tbs_certificate_bytes:', hashlib.md5(cert1.tbs_certificate_bytes).hexdigest()
	print 'md5 of cert2.tbs_certificate_bytes:', hashlib.md5(cert2.tbs_certificate_bytes).hexdigest()

	with open("sol_3.2.5_certA.cer", 'wb') as out1, open("sol_3.2.5_certB.cer", 'wb') as out2:
	    out1.write(cert1.public_bytes(Encoding.DER))
	    out2.write(cert2.public_bytes(Encoding.DER))

if __name__ == '__main__':
	# call only once
	# make_tmpcert()

	# cut_prefix()

	get_bitstrings()

	# call only once
	construct_moduli()

	make_certAB()
