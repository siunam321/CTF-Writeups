# SD Card

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

- Challenge difficulty: ★☆☆☆☆

## Background

I have accidentally format my SD card. Please help me to recover the photo inside 🙏.

Attachment: [sdcard_f88edd62fb9d6f66b9bcab4497ca23b9.zip](https://file.hkcert22.pwnable.hk/sdcard_f88edd62fb9d6f66b9bcab4497ca23b9.zip)

Solution: [https://hackmd.io/@blackb6a/hkcert-ctf-2022-i-en-3f8a9ef6](https://hackmd.io/@blackb6a/hkcert-ctf-2022-i-en-3f8a9ef6)

## Find the flag

**In this challenge, we can download an attachment:**
```
┌──(root🌸siunam)-[~/ctf/HKCERT-CTF-2022/Forensics/SD-Card]
└─# unzip sdcard_f88edd62fb9d6f66b9bcab4497ca23b9.zip 
Archive:  sdcard_f88edd62fb9d6f66b9bcab4497ca23b9.zip
  inflating: sdcard.dd

┌──(root🌸siunam)-[~/ctf/HKCERT-CTF-2022/Forensics/SD-Card]
└─# file sdcard.dd 
sdcard.dd: DOS/MBR boot sector, code offset 0x3c+2, OEM-ID "MSDOS5.0", sectors/cluster 8, reserved sectors 8, root entries 512, sectors 31680 (volumes <=32 MB), Media descriptor 0xf8, sectors/FAT 12, sectors/track 63, heads 255, serial number 0x385844de, unlabeled, FAT (12 bit)
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111051725.png)

**In here, we can just follow the solution! (It surprises me lol)**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111050413.png)

**Let's transfer this file to my Windows machine!**
```
┌──(root🌸siunam)-[~/ctf/HKCERT-CTF-2022/Forensics/SD-Card]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

PS C:\Users\siunam\Desktop> Invoke-WebRequest -Uri http://192.168.183.141/sdcard.dd -OutFile .\sdcard.dd
```

**Open it in Autopsy:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111052433.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111052748.png)

**We indeed saw a `_lag.png` file!**

**Let's extract it!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111052909.png)

**I'll use `updog` to transfer the picture to my Linux machine:**
```
┌──(root🌸siunam)-[~/ctf/HKCERT-CTF-2022/Forensics/SD-Card]
└─# updog
[+] Serving /root/ctf/HKCERT-CTF-2022/Forensics/SD-Card...
 * Running on all addresses (0.0.0.0)
   WARNING: This is a development server. Do not use it in a production deployment.
 * Running on http://127.0.0.1:9090
 * Running on http://192.168.183.141:9090 (Press CTRL+C to quit)
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111053058.png)

```
┌──(root🌸siunam)-[~/ctf/HKCERT-CTF-2022/Forensics/SD-Card]
└─# file lag.png                        
lag.png: PNG image data, 1 x 1, 1-bit grayscale, non-interlaced
```

Hmm... The size is 1x1, looks like it's **corrupted**!

**Let's upload this picture to [https://www.nayuki.io/page/png-file-chunk-inspector](https://www.nayuki.io/page/png-file-chunk-inspector) to inspect the PNG chuncks!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111053347.png)

**We can see that the has mulitple chuncks! Let's upload the image to [HexEd.it](https://hexed.it/) to remove those chuncks!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111053701.png)

- Remove extra chunck:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111053753.png)

- Export the image:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111053853.png)

- View the image:

```
┌──(root🌸siunam)-[~/ctf/HKCERT-CTF-2022/Forensics/SD-Card]
└─# eog /home/nam/Downloads/lag\(1\).png
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111053909.png)

We got the flag!

- **Flag: `hkcert22{funfunfunfunlookinforwardtotheweekend}`**

# Conclusion

What we've learned:

1. Disk Forensics & Recovering Corrupted Image