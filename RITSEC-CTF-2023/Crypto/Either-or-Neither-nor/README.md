# Either or Neither nor

## Overview

- 100 Points / 271 Solves

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

Made by MetaCTF

Oh no! I was working on this challenge and totally forgot to save a backup of the decryption key! Do you think you could take a look and see if you can recover it for me?

NOTE: The flag format is MetaCTF{}

[https://metaproblems.com/6ebee70f0d78d94a4750f9cb70031965/chal.py](https://metaproblems.com/6ebee70f0d78d94a4750f9cb70031965/chal.py)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401215406.png)

## Find the flag

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Crypto/Either-or-Neither-nor)-[2023.04.01|21:54:34(HKT)]
└> file chal.py 
chal.py: Python script, ASCII text executable
```

**It's a Python script:**
```py
#! /usr/bin/env python

flag = "XXXXXXXXXXXXXXXXXXXXX"
enc_flag = [91,241,101,166,85,192,87,188,110,164,99,152,98,252,34,152,117,164,99,162,107]

key = [0, 0, 0, 0]
KEY_LEN = 4

# Encrypt the flag
for idx, c in enumerate(flag):
    enc_flag = ord(c) ^ key[idx % len(key)]
```

The flag is being XOR'ed!

**To reverse that process, we can XOR back the `enc_flag`.**

However, I wasn't able to reverse it... Maybe I need to brute force the key??

Hmm... Maybe my Python skill sucks.

**Let's Google "XOR brute force online":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402231350.png)

[dCode](https://www.dcode.fr/xor-cipher) always work for me.

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402231452.png)

**But first, we need to convert those `enc_flag` ASCII decimal to hex:**
```py
#!/usr/bin/env python3

def main():
    enc_flag = [91,241,101,166,85,192,87,188,110,164,99,152,98,252,34,152,117,164,99,162,107]
    hexedEnc_flag = '0x'
    
    for c in enc_flag:
        hexedEnc_flag += hex(c)[2:]
    print(hexedEnc_flag)

if __name__ == '__main__':
    main()
```

```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Crypto/Either-or-Neither-nor)-[2023.04.02|23:17:34(HKT)]
└> python3 solve.py
0x5bf165a655c057bc6ea4639862fc229875a463a26b
```

**Then, copy and paste that to XOR decoder:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402231829.png)

Next, choose "KNOWING THE KEY SIZE (IN BYTES)", and type `4`. **This is because the `KEY_LEN` is `4`.**

**Finally, choose "RESULT FORMAT" to "ASCII (PRINTABLE) CHARACTERS", and click "ENCRYPT/DECRYPT":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402231859.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402232120.png)

Hmm... Those looks like the flag??

**Since the flag format is `MetaCTF{}`, we can search for that pattern:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402232213.png)

Boom! We found it!

- **Flag: `MetaCTF{x0r_th3_c0re}`**

## Conclusion

What we've learned:

1. Many Time Pad XOR