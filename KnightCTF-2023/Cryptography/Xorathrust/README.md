# Xorathrust

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

- Challenge static score: 25

## Backgrond

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121182152.png)

**In the challenge's description, we can download an attachment. Let's download it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121182215.png)

```shell
┌[root♥siunam]-(~/ctf/KnightCTF-2023/Cryptography/Xorathrust)-[2023.01.21|18:21:12(HKT)]
└> mv /home/nam/Downloads/Xorathrust-20230121T102216Z-001.zip .
┌[root♥siunam]-(~/ctf/KnightCTF-2023/Cryptography/Xorathrust)-[2023.01.21|18:22:29(HKT)]
└> unzip Xorathrust-20230121T102216Z-001.zip 
Archive:  Xorathrust-20230121T102216Z-001.zip
  inflating: Xorathrust/flag.enc.txt  
  inflating: Xorathrust/encrypt.py
┌[root♥siunam]-(~/ctf/KnightCTF-2023/Cryptography/Xorathrust)-[2023.01.21|18:22:40(HKT)]
└> cd Xorathrust
```

## Find the flag

**`flag.enc.txt`:**
```shell
┌[root♥siunam]-(~/ctf/KnightCTF-2023/Cryptography/Xorathrust/Xorathrust)-[2023.01.21|18:24:46(HKT)]
└> xxd flag.enc.txt 
00000000: 2d25 3220 1d0c 1353 1239 5239 0452 530f  -%2 ...S.9R9.RS.
00000010: 0539 1e56 141b                           .9.V..
```

**`encrypt.py`:**
```py
def main():

    flag_enc = ""

    with open("flag.txt", "r") as infile:
        flag = infile.read()
        flag = list(flag)

        for each in flag:
            each = chr(ord(each) ^ 0x66)
            flag_enc += each


    with open("flag.enc", "w") as outfile:
        outfile.write(flag_enc)



if __name__ == "__main__":
    main()
```

As you can see, the original `flag.txt` is being XOR'ed, and **every characters of `flag.txt` is XOR'ed by hex `66`.**

**Armed with above information, we can reverse it by XOR'ing hex `66`:**
```py
#!/usr/bin/env python3

XORedflag = ''

with open('flag.enc.txt', 'rb') as file:
    flag = file.read()
    flag = list(flag)
    
    for character in flag:
        XORedflag += chr(character ^ 0x66)

print(XORedflag)
```

```shell
┌[root♥siunam]-(~/ctf/KnightCTF-2023/Cryptography/Xorathrust/Xorathrust)-[2023.01.21|18:30:30(HKT)]
└> python3 solve.py
KCTF{ju5t_4_b45ic_x0r}
```

Found the flag!

- **Flag: `KCTF{ju5t_4_b45ic_x0r}`**

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121183616.png)

# Conclusion

What we've learned:

1. Decrypting XOR'ed File