# Weird

- 50 Points / 356 Solves

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This file was supposed to contain a secret message but it looks like just a blank page. Something weird is going on here.

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402192257.png)

## Find the flag

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Steganography/Weird)-[2023.04.02|19:23:17(HKT)]
└> file blank.png      
blank.png: PNG image data, 600 x 600, 8-bit/color RGBA, non-interlaced
```

It's a PNG image file.

**First, we can try to read it's metadata via `exiftool`:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Steganography/Weird)-[2023.04.02|19:23:23(HKT)]
└> exiftool blank.png  
ExifTool Version Number         : 12.57
File Name                       : blank.png
[...]
```

However, nothing interesting.

**Then, I decided to upload that image to [aperisolve.fr](https://aperisolve.fr/), which is an online tool to solve steganography challenge:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402192508.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402192519.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402192528.png)

Boom! We found the flag!

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402192538.png)

- **Flag: `RS{Th4t5_w4cky_m4n}`**

## Conclusion

What we've learned:

1. Viewing Image With Separate Color