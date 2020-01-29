import sys
from Crypto.Cipher import AES

with open(sys.argv[1]) as ciphertext, open(sys.argv[2]) as key, open(sys.argv[3]) as iv, open(sys.argv[4],'w') as output:
        ciphertext_content=ciphertext.read().strip()
        key_content=key.read().strip()
        iv_content=iv.read().strip()

        ciphertext_content_binary=ciphertext_content.decode('hex')
        key_content_binary=key_content.decode('hex')
        iv_content_binary=iv_content.decode('hex')

        output.write(AES.new(key_content_binary,AES.MODE_CBC, iv_content_binary).decrypt(ciphertext_content_binary))

# $ python sol_3.1.2.2.py 3.1.2.2_aes_ciphertext.hex 3.1.2.2_aes_key.hex 3.1.2.2_aes_iv.hex sol_3.1.2.2.txt
