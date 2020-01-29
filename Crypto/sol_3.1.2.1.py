import sys

with open(sys.argv[1]) as ciphertext, open(sys.argv[2]) as key, open(sys.argv[3],'w') as output:
        ciphertext_content=ciphertext.read().strip()
        key_content=key.read().strip()

        plaintext_list="ABCDEFGHIJKLMNOPQRSTUVWXYZ"

        for i in ciphertext_content:
                num=key_content.find(i)
                if num>=0:
                        output.write(plaintext_list[num])
                else:
                        output.write(i)
# $ python sol_3.1.2.1.py 3.1.2.1_sub_ciphertext.txt 3.1.2.1_sub_key.txt sol_3.1.2.1.txt
