#!/usr/bin/env python3

import base64

enc_password = b'0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E'
key = b'armando'

array = base64.b64decode(enc_password)
array2 = ''

for i in range(len(array)):
	array2 += chr(array[i] ^ key[i % len(key)] ^ 223)

print(f'[+] Decrypted password is: {array2}')