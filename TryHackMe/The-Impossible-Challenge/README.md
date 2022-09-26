# The Impossible Challenge

## Introduction:

Welcome to my another writeup! In this TryHackMe [The Impossible Challenge](https://tryhackme.com/room/theimpossiblechallenge) room, you'll learn: unicode steganography with zero-width characters! Without further ado, let's dive in.

## Background

> ‌‌‌‌‍﻿‌‌Hmm‌‌‌‌‍‬‌‍‌‌‌‌‍﻿‌﻿‌‌‌‌‍﻿‌﻿‌‌‌‌‍﻿‍﻿‌‌‌‌‍‬﻿﻿‌‌‌‌‍﻿‌‬‌‌‌‌‍‬‍‌‌‌‌‌‌‬‌‌‌‌‌‌‍‬‬‍‌‌‌‌‍﻿‌﻿‌‌‌‌‌‬‌‌‌‌‌‌‍‬‬‌‌‌‌‌‍‬‌‍‌‌‌‌‍‬‬‌‌‌‌‌‍‬‌‍‌‌‌‌‍‬‍‍‌‌‌‌‍﻿‬‬‌‌‌‌‍﻿‌‌‌‌‌‌‍﻿‬‬

> Difficulty: Medium

```
Download the file, and find the Flag!

-

qo qt q` r6 ro su pn s_ rn r6 p6 s_ q2 ps qq rs rp ps rt r4 pu pt qn r4 rq pt q` so pu ps r4 sq pu ps q2 su rn on oq o_ pu ps ou r5 pu pt r4 sr rp qt pu rs q2 qt r4 r4 ro su pq o5
```

- Overall difficulty for me: Very easy

# The Downloaded File

**The download file is a zip file:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Impossible-Challenge]
└─# file Impossible.zip  
Impossible.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
```

**However, it needs a password to `unzip` it:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Impossible-Challenge]
└─# unzip Impossible.zip 
Archive:  Impossible.zip
[Impossible.zip] flag.txt password: 
   skipping: flag.txt                incorrect password
```

However, when I copy this room's descript, I saw bunch of **unicodes**.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Impossible-Challenge/images/a1.png)

**Looks like it's a unicode steganography!!**

**We can copy those unicode to [Unicode Steganography with Zero-Width Characters](https://330k.github.io/misc_tools/unicode_steganography.html):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Impossible-Challenge/images/a2.png)

**Boom!! We found the password!! Let's `unzip` the zip file:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Impossible-Challenge]
└─# unzip Impossible.zip 
Archive:  Impossible.zip
[Impossible.zip] flag.txt password: 
  inflating: flag.txt                
```

**flag.txt:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Impossible-Challenge]
└─# cat flag.txt      
You have solved the Impossible Challenge! Here is your flag THM{Redacted}
```

# Conclusion

What we've learned:

1. Unicode Steganography With Zero-Width Characters