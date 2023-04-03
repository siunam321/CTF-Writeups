# turtle

- 76 Points / 247 Solves

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Nothing to see here but a happy turtle.

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402193517.png)

## Find the flag

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Steganography/turtle)-[2023.04.02|19:35:30(HKT)]
└> file turtle.gif       
turtle.gif: GIF image data, version 89a, 224 x 126
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402193545.png)

It's a GIF image file!

**We can use `exiftool` to view it's metadata:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Steganography/turtle)-[2023.04.02|19:35:44(HKT)]
└> exiftool turtle.gif
ExifTool Version Number         : 12.57
File Name                       : turtle.gif
[...]
```

However, nothing weird in the metadata.

Then, I tried using `steghide`, `binwalk`, `foremost` to extract hidden file inside it, but no dice.

Hmm... Since it's a GIF file, let's view it's image ***frame by frame***.

**According to [HackTricks](https://book.hacktricks.xyz/crypto-and-stego/stego-tricks#stegsolve), we can use a tool called [Stegsolve](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve) to view image's frames:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Steganography/turtle)-[2023.04.02|19:37:45(HKT)]
└> /opt/Stegsolve.jar
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402194013.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402194019.png)

**Next, go to "Analyse" -> "Frame Browser":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402194057.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402194105.png)

We can now view the GIF frame by frame!

**After looking at those frame, I found that the 40th frame has the flag!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402194148.png)

- **Flag: `RS{G00D_3Y3_&_H4PPY_TUR713}`**

## Conclusion

What we've learned:

1. Viewing Animated GIF Frame By Frame