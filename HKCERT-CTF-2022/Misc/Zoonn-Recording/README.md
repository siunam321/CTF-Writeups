# Zoonn Recording

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

- Challenge difficulty: ★☆☆☆☆

## Background

Dr. Ke is watching pwn video during a Zoonn meeting. Can you find what was pwned in that pwn video?

Attachment: [zoonn-recording_010be3c3eae392244bb7390a56118972.zip](https://file.hkcert22.pwnable.hk/zoonn-recording_010be3c3eae392244bb7390a56118972.zip)

Solution: [https://hackmd.io/@blackb6a/hkcert-ctf-2022-ii-en-6a196795](https://hackmd.io/@blackb6a/hkcert-ctf-2022-ii-en-6a196795)

## Find the flag

**In this challenge, we can download an attachment:**
```
┌──(root🌸siunam)-[~/ctf/HKCERT-CTF-2022/Misc/Zoonn-Recording]
└─# unzip zoonn-recording_010be3c3eae392244bb7390a56118972.zip   
Archive:  zoonn-recording_010be3c3eae392244bb7390a56118972.zip
  inflating: 2022-02-02 22.22.22 Zzz 22222222222.mp4
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111210554.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111210639.png)

**If you look closely, the flag is being reflected on his glass!**

**Let's use `ffmeg` to flip video horizontally:**
```
┌──(root🌸siunam)-[~/ctf/HKCERT-CTF-2022/Misc/Zoonn-Recording]
└─# ffmpeg -i 2022-02-02\ 22.22.22\ Zzz\ 22222222222.mp4 -vf hflip -c:a copy OUTPUT.mp4
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111211050.png)

Now, we can barely see the flag. (Flag format: `hkcert22{.*?}`)

**We can also use `ffmeg` to extract every frames!**
```
┌──(root🌸siunam)-[~/…/HKCERT-CTF-2022/Misc/Zoonn-Recording/output]
└─# mkdir output;cd output

┌──(root🌸siunam)-[~/…/HKCERT-CTF-2022/Misc/Zoonn-Recording/output]
└─# ffmpeg -i ../output.mp4 '%04d.png'
```

**Now we can view the flag frame by frame:**

- **Flag: `hkcert22{5p3c7aculaar}`**

# Conclusion

What we've learned:

1. Leaking Sensitive Information via Bad Operation Security (Physical Security)