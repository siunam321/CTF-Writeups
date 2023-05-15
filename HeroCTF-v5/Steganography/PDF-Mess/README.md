# PDF-Mess

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find the flag](#find-the-flag)
4. [Conclusion](#conclusion)

## Overview

- 117 solves / 50 points
- Difficulty: Easy
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This file seems to be a simple copy and paste from wikipedia. It would be necessary to dig a little deeper...  
  
Good luck!  
  
Format : **Hero{}**  
Author : **Thibz**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514150202.png)

## Find the flag

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/Steganography/PDF-Mess/strange.pdf):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514150229.png)

```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Steganography/PDF-Mess)-[2023.05.14|15:02:37(HKT)]
└> file strange.pdf 
strange.pdf: PDF document, version 1.7, 2 pages
```

It's a PDF file.

In this PDF file, it has an image file:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514150304.png)

**We can try to extract that via `foremost`:**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Steganography/PDF-Mess)-[2023.05.14|15:03:50(HKT)]
└> foremost -i strange.pdf
Processing: strange.pdf
|*|
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Steganography/PDF-Mess)-[2023.05.14|15:03:56(HKT)]
└> ls -lah output 
total 20K
drwxr-xr-- 4 siunam nam 4.0K May 14 15:03 .
drwxr-xr-x 4 siunam nam 4.0K May 14 15:03 ..
-rw-r--r-- 1 siunam nam  758 May 14 15:03 audit.txt
drwxr-xr-- 2 siunam nam 4.0K May 14 15:03 jpg
drwxr-xr-- 2 siunam nam 4.0K May 14 15:03 pdf
```

However, I ran through all JPG steganography tools, and found nothing.

**Then, I Googled "stegano pdf ctf":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514150507.png)

**This [writeup from UIUCTF](https://github.com/hgarrereyn/Th3g3ntl3man-CTF-Writeups/blob/master/2017/UIUCTF/problems/Forensics/salted_wounds/salted_wounds.md) shows us how to extract embedded file in the PDF:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514150610.png)

**Let's do that!**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Steganography/PDF-Mess)-[2023.05.14|15:06:40(HKT)]
└> pdf-parser --stats strange.pdf                         
This program has not been tested with this version of Python (3.11.2)
Should you encounter problems, please use Python version 3.11.1
Comment: 4
XREF: 2
Trailer: 2
StartXref: 2
Indirect object: 44
Indirect objects with a stream: 4, 28, 30, 31, 40, 101, 102, 106, 107, 110, 109
  24: 4, 6, 8, 14, 15, 16, 19, 20, 21, 22, 23, 24, 25, 26, 27, 30, 32, 101, 102, 103, 104, 105, 106, 108
 /Catalog 1: 1
 /EmbeddedFile 1: 110
 /ExtGState 2: 10, 11
 /Filespec 1: 111
 /Font 4: 5, 7, 12, 17
 /FontDescriptor 3: 9, 13, 18
 /Metadata 1: 107
 /ObjStm 1: 40
 /Page 2: 3, 29
 /Pages 1: 2
 /XObject 2: 28, 31
 /XRef 1: 109
Unreferenced indirect objects: 40 0 R, 109 0 R
Unreferenced indirect objects without /ObjStm objects: 109 0 R
Search keywords:
 /EmbeddedFile 1: 110
 /URI 12: 14, 15, 16, 19, 20, 21, 22, 23, 24, 25, 26, 27
```

**We found a hidden embedded file too! `/EmbeddedFile 1: 110`**

**To extract that we can:**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Steganography/PDF-Mess)-[2023.05.14|15:06:46(HKT)]
└> pdf-parser --object 110 --raw --filter strange.pdf > 110_EmbeddedFile
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Steganography/PDF-Mess)-[2023.05.14|15:07:41(HKT)]
└> cat 110_EmbeddedFile 
This program has not been tested with this version of Python (3.11.2)
Should you encounter problems, please use Python version 3.11.1
obj 110 0
 Type: /EmbeddedFile
 Referencing: 
 Contains stream

  <<
    /Length 179
    /Type /EmbeddedFile
    /Filter /FlateDecode
    /Params
      <<
        /Size 199
        /Checksum <083542c62e17ca3367bd590c1ab38578>
      >>
    /Subtype /application/js
  >>

 b"const CryptoJS=require('crypto-js'),key='3d3067e197cf4d0a',ciphertext=CryptoJS['AES']['encrypt'](message,key)['toString'](),cipher='U2FsdGVkX1+2k+cHVHn/CMkXGGDmb0DpmShxtTfwNnMr9dU1I6/GQI/iYWEexsod';"
```

Oh! We found some JavaScript code!

**Beautified:**
```js
const CryptoJS = require('crypto-js');

key = '3d3067e197cf4d0a';
ciphertext = CryptoJS['AES']['encrypt'](message,key)['toString']();
cipher = 'U2FsdGVkX1+2k+cHVHn/CMkXGGDmb0DpmShxtTfwNnMr9dU1I6/GQI/iYWEexsod';
```

As you can see, it's using the `crypto-js` npm library, and using that to AES encrypt the `message` (We don't know about that) and the `key`: `3d3067e197cf4d0a`.

After encrypt, the cipher text is `U2FsdGVkX1+2k+cHVHn/CMkXGGDmb0DpmShxtTfwNnMr9dU1I6/GQI/iYWEexsod`.

**We could read the [`crypto-js`'s documentation about AES](https://cryptojs.gitbook.io/docs/#the-cipher-algorithms) to decrypt it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514151100.png)

```js
const CryptoJS = require('crypto-js');

key = '3d3067e197cf4d0a';
//ciphertext = CryptoJS['AES']['encrypt'](message,key)['toString']();
cipher = 'U2FsdGVkX1+2k+cHVHn/CMkXGGDmb0DpmShxtTfwNnMr9dU1I6/GQI/iYWEexsod';
plaintext = CryptoJS['AES']['decrypt'](cipher,key)['toString']();

console.log(plaintext);
```

**However, I wanna give ChatGPT a try:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514151513.png)

**Ok bruh, I'll decrypt it by myself lol:**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Steganography/PDF-Mess)-[2023.05.14|15:15:30(HKT)]
└> npm install crypto-js     

added 1 package in 378ms
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Steganography/PDF-Mess)-[2023.05.14|15:15:34(HKT)]
└> nodejs 110_EmbeddedFile.js
4865726f7b4d344c3143313055355f433044335f314e5f5044467d
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Steganography/PDF-Mess)-[2023.05.14|15:15:38(HKT)]
└> nodejs 110_EmbeddedFile.js | xxd -r -p
Hero{M4L1C10U5_C0D3_1N_PDF}
```

- **Flag: `Hero{M4L1C10U5_C0D3_1N_PDF}`**

## Conclusion

What we've learned:

1. Extracting Embedded File In PDF