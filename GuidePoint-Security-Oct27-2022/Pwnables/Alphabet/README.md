# Alphabet

## Overview

- Overall difficulty for me: Hard

**In this challenge, we can spawn a docker instance:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221028075831.png)

```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Pwnables/Alphabet]
└─# nc 10.10.100.200 35740
Give me up to 100 bytes and I'll encode it in base64...
AAAAA
"jH1"j0%
What was the base64 alphabet I used?
idk
Incorrect, the answer was ^1lo0H+i<Z%!VuIR"7rwjb`yp$LTK'MOA)#?:[}Y,_4-nf5;>q8DWz~/adEJg\@m=
Good bye
```

**That base64 alphabet looks like custom, as normally base64 don't have special characters except `+/=`.**

**Hmm... What if I base64 decode my message first, and then the server encode it?**

**To do so, I'll write a python script:**
```py
#!/usr/bin/env python3

from pwn import *
import base64
import string

context.log_level = 'critical' # No logging

host, port = '10.10.100.200', 35740

char = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+/'
unb64 = base64.b64decode(char)
our_encoded = base64.b64encode(unb64)

def get_alphabet(char):
	with remote(host, port) as p:
		p.recvuntil(b'...\n')
		p.sendline(char)
		their_message = p.recvuntil(b'\n').strip().decode('utf-8')
		
		p.sendlineafter(b'used?\n', b'test')
		their_alphabet = p.recv().strip().decode('utf-8').split()

	return their_message, their_alphabet[4]

if __name__ == '__main__':
	their_message, their_alphabet = get_alphabet(unb64)

	print(f'Our message: {unb64.decode("latin-1")}')
	print(f'Our encoded: {our_encoded.decode("utf-8")}')

	print(f'Their message: {their_message}')
	print(f'Their alphabet: {their_alphabet}')
```

**Output:**
```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Pwnables/Alphabet]
└─# python3 solve.py
Our message: \x00\x10 0ÓA\x14\x93QUa×\x18\xa3Y§¢²Û¯Ã\x1c\xb3Ó]·ã
Our encoded: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
Their message: 5(@IOmFV1+LG0zXS^]8gd~>;Kx\Qahe#*NJD-ut|_p7nq)/rfcWk&oYl2isEjTP[@*==
Their alphabet: 5(@IOmFV1+LG0zXS^]8gd~>;Kx\Qahe#*NJD-ut|_p7nq)/rfcWk&oYl2isEjTP[=
                                                                                                           
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Pwnables/Alphabet]
└─# python3 solve.py
Our message: \x00\x10 0ÓA\x14\x93QUa×\x18\xa3Y§¢²Û¯Ã\x1c\xb3Ó]·ã
Our encoded: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
Their message: OSA(^p+'?m<uNEz4d6#.q8@wJ`ZD)g0|_ac1k-t93M"$XryvhWi:T5\BC&nY/VfRA_==
Their alphabet: OSA(^p+'?m<uNEz4d6#.q8@wJ`ZD)g0|_ac1k-t93M"$XryvhWi:T5\BC&nY/VfR=
                                                                                                           
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Pwnables/Alphabet]
└─# python3 solve.py
Our message: \x00\x10 0ÓA\x14\x93QUa×\x18\xa3Y§¢²Û¯Ã\x1c\xb3Ó]·ã
Our encoded: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
Their message: )UgnxXaoC!\u9<b~2A45E;p1^W@7GJ3Bs][%M{(w#*R?kIlQ'PKVyh6ejqNDYz|igs==
Their alphabet: )UgnxXaoC!\u9<b~2A45E;p1^W@7GJ3Bs][%M{(w#*R?kIlQ'PKVyh6ejqNDYz|i=
```

**We found their alphabet! Let's submit that!** ([Source code](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/Pwnables/Alphabet/solve.py))
```py
#!/usr/bin/env python3

from pwn import *
import base64
import string

context.log_level = 'critical' # No logging

host, port = '10.10.100.200', 35740

char = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+/'
unb64 = base64.b64decode(char)

def get_alphabet(payload):
	with remote(host, port) as p:
		p.recvuntil(b'...\n')

		# Send the base64 decoded characters
		p.sendline(payload)

		# Retrieve their message, which is their alphabet
		their_message = p.recv().decode('utf-8')
		found_alphabet = their_message[:64] + '=' # Their alphabet has an extra '='

		# Send their alphabet
		p.send(bytes(found_alphabet, 'utf-8')) # Use send() is because it doesn't contain the new line character(\n)
 		print(p.recv().decode('utf-8'))

if __name__ == '__main__':
	get_alphabet(unb64)
```

**Output:**
```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Pwnables/Alphabet]
└─# python3 solve.py
Correct!!!1
Flag: GPSCTF{2139e42d4da50e9c9f9be56d100e0376}
```

We found the flag!!

# Conclusion

What we've learned:

1. Decoding Custom Base64 Alphabet