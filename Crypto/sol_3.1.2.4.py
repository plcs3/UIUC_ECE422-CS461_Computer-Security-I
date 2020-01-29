import sys

with open(sys.argv[1]) as ciphertext, open(sys.argv[2]) as key, open(sys.argv[3]) as modulo, open(sys.argv[4],'w') as output:
        ciphertext_content=ciphertext.read().strip()
        key_content=key.read().strip()
        modulo_content=modulo.read().strip()

        ciphertext_content_int=int(ciphertext_content,16)
        key_content_int=int(key_content,16)
        modulo_content_int=int(modulo_content,16)

        plaintext=pow(ciphertext_content_int, key_content_int, modulo_content_int)
        output.write(str(hex(plaintext)[2:-1]))


# $ python sol_3.1.2.4.py 3.1.2.4_RSA_ciphertext.hex 3.1.2.4_RSA_private_key.hex 3.1.2.4_RSA_modulo.hex sol_3.1.2.4.hex
