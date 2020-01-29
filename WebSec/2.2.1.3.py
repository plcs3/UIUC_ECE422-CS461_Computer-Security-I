import random
import hashlib
import sys

cnt = 0
while True:
        start = random.randint(0, 1234567812345678123456781234567812345678)
        cnt += 1
        print(cnt)
        for i in range(start, start + 1000000):
                orig = str(i)
                hashed = hashlib.md5(orig).digest()
                idx = hashed.lower().find("'or'")
                if idx >= 0 and idx + 4 < len(hashed) and hashed[idx + 4].isdigit():
                        print(orig, hashed, cnt)
                        sys.exit()
                idx = hashed.find("'||'")
                if idx >= 0 and idx + 4 < len(hashed) and hashed[idx + 4].isdigit():
                        print(orig, hashed, cnt)
                        sys.exit()

