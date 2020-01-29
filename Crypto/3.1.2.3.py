from Crypto.Cipher import AES

with open("3.1.2.3_aes_weak_ciphertext.hex") as ciphertext:
        iv_binary=("00"*16).decode('hex')
        ciphertext_content=ciphertext.read().strip()
        ciphertext_content_binary=ciphertext_content.decode('hex')

        for i in range(32):
                if i<0x10:
                        keystr=("00"*31)+'0'+str(hex(i)[2:])
                        key_binary=keystr.decode('hex')
                else:
                        keystr=("00"*31)+str(hex(i)[2:])
                        key_binary=keystr.decode('hex')

                print("Key= "+str(i)+", Keystr= "+keystr)
                print("Plaintext= "+AES.new(key_binary, AES.MODE_CBC, iv_binary).decrypt(ciphertext_content_binary))
                print("             ")
