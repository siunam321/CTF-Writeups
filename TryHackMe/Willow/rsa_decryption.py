#!/usr/bin/env python3

# Full decryption keys from file rsa_keys
d = 61527
n = 37627

f = open("decoded_index.txt", "r")
file = f.read()

for each_item in file.split():
	# For each encrypted text in decoded_index.txt will be decrypted, and turn ASCII to string via chr().
	decrypted = chr(int(each_item) ** d % n)

	# Append those decrypted text into decypted_private_key.txt
	with open("decypted_private_key.txt", "a") as handler:
		handler.write(str(decrypted))