#!/usr/bin/env python3

from Crypto.Cipher import AES

def decryption():
	key = 'vN0nb7ZshjAWiCzv'
	iv = 'ffTC776Wt59Qawe1'
	file = './candy_dungeon.pdf.boo'

	ct = open(file, 'rb').read()
	cipher = AES.new(key.encode('utf-8'), AES.MODE_CFB, iv=iv.encode('utf-8'))
	pt = cipher.decrypt(ct)
	open('decrypted.pdf', 'wb').write(pt)

if __name__ == '__main__':
	decryption()