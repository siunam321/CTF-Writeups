# Ancient

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/Icognito-4.0/images/Pasted%20image%2020230217230017.png)

## Find the flag

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Icognito-4.0/crypto/Ancient/challenge.png):**
```shell
┌[siunam♥earth]-(~/ctf/Incognito-4.0/Crypto/Ancient)-[2023.02.17|23:00:30(HKT)]
└> file challenge.png   
challenge.png: data
```

Which should be a `png` image file.

**However, when we open it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Icognito-4.0/images/Pasted%20image%2020230217230105.png)

It said it's broken!

**Let's use `strings` to view all the strings!**
```shell
┌[siunam♥earth]-(~/ctf/Incognito-4.0/Crypto/Ancient)-[2023.02.17|23:01:38(HKT)]
└> strings challenge.png
IHDR
iCCPICC profile
[...]
```

***iCCPICC profile??***

Let's google that:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Icognito-4.0/images/Pasted%20image%2020230217230227.png)

Right off the bat, we found another [CTF's writeup](https://github.com/UConnSec/CyberSEED-2016-Writeups/blob/master/Missing%20Flag%20%231.md):

![](https://github.com/siunam321/CTF-Writeups/blob/main/Icognito-4.0/images/Pasted%20image%2020230217230259.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Icognito-4.0/images/Pasted%20image%2020230217230313.png)

[Wikipedia's magic headers](https://en.wikipedia.org/wiki/List_of_file_signatures):

![](https://github.com/siunam321/CTF-Writeups/blob/main/Icognito-4.0/images/Pasted%20image%2020230217230557.png)

**So, the `challenge.png` is missing the PNG's magic header?**
```shell
┌[siunam♥earth]-(~/ctf/Incognito-4.0/Crypto/Ancient)-[2023.02.17|23:03:26(HKT)]
└> xxd challenge.png | head -n 1 
00000000: 0000 0000 aa0a 1a0a 0000 000d 4948 4452  ............IHDR
```

In our case, it's missing the first 6 bytes: `89 50 4E 47 0D 0A`.

**To fix that image, we can use `hexeditor` to modify the raw bytes:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Icognito-4.0/images/Pasted%20image%2020230217230708.png)

```shell
┌[siunam♥earth]-(~/ctf/Incognito-4.0/Crypto/Ancient)-[2023.02.17|23:05:08(HKT)]
└> file challenge.png
challenge.png: PNG image data, 400 x 170, 8-bit/color RGBA, non-interlaced
```

It's an image now!

**challenge.png:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Icognito-4.0/images/Pasted%20image%2020230217230730.png)

Hmm... I've no clue what is it...

Let's upload that image:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Icognito-4.0/images/Pasted%20image%2020230218153702.png)

Cistercian numerals??

> The Cistercian Number System was devised by Cisterican monks in the early 13th century as a compact way to write numbers. Using these numerals **any number from 1 to 9,999 can be written in a single glyph by combining the basic elements together on a vertical line**.

**[This website](https://omniglot.com/language/numbers/cistercian-numbers.htm) explained how Cistercian Number System looks like:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Icognito-4.0/images/Pasted%20image%2020230218153814.png)

**After that, I watched Numberphile's [video](https://www.youtube.com/watch?v=9p55Qgt7Ciw) about Cistercian Number System:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Icognito-4.0/images/Pasted%20image%2020230218154855.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Icognito-4.0/images/Pasted%20image%2020230218155043.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Icognito-4.0/images/Pasted%20image%2020230218154915.png)

**Armed with above information, we can find all the Cistercian numbers in decimal:**

- $100 + 5 = 105$
- $90 + 9 = 99$
- $100 + 10 + 6 = 116$
- $100 + 2 = 102$
- $100 + 20 + 3 = 123$
- $40 + 8 = 48$
- $100 + 8 = 108$
- $100$
- $90 + 5 = 95$
- $100 + 9 = 109$
- $40 + 8 = 48$
- $100 + 10 = 110$
- $100 + 7 = 107$
- $90 + 5 = 95$
- $40 + 9 =49$
- $50 + 7 = 57$
- $40 + 8 = 48$
- $100$
- $100 + 1 = 101$
- $40 + 9 = 49$
- $90 + 9 = 99$
- $50 + 1 = 51$
- $100 + 20 + 5 = 125$

Hmm... What can we do with those numbers?

Based on my experience, it's ASCII characters in decimal!

**To convert ASCII decimal to text, we can use Python:**
```py
#!/usr/bin/env/python3

def main():
    listCistercianNumbers = [
        105,
        99,
        116,
        102,
        123,
        48,
        108,
        100,
        95,
        109,
        48,
        110,
        107,
        95,
        49,
        57,
        48,
        100,
        101,
        49,
        99,
        51,
        125
    ]

    flag = ''
    for number in listCistercianNumbers:
        flag += chr(number)
    else:
        print(flag)

if __name__ == '__main__':
    main()
```

```shell
┌[siunam♥earth]-(~/ctf/Incognito-4.0/Crypto/Ancient)-[2023.02.18|16:02:12(HKT)]
└> python3 solve.py
ictf{0ld_m0nk_190de1c3}
```

Nice! We got the flag!

- **Flag: `ictf{0ld_m0nk_190de1c3}`**

# Conclusion

What we've learned:

1. Fixing PNG Magic Header & Cistercian Number System