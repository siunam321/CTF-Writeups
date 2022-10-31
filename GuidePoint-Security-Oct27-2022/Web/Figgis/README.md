# Figgis

## Overview

- Overall difficulty for me: Easy

**In this challenge, we can spawn a docker instance:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030032809.png)

## Find the flag

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030032845.png)

**Seems like nothing here, let's enumerate hidden directory via `gobuster`:**
```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Web/Figgis]
└─# gobuster dir -u http://10.10.100.200:54221/ -w /usr/share/wordlists/dirb/common.txt -t 100 -x php
[...]
/config               (Status: 200) [Size: 516]
/cookie               (Status: 200) [Size: 333]
/evaluate             (Status: 200) [Size: 322]
/lookup               (Status: 200) [Size: 315]
/xml                  (Status: 200) [Size: 311]
```

Let's check all of them!

**`/config`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030033950.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030034000.png)

**Bad padding?**

**`cookie`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030034026.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030034034.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030034045.png)

Seems useless?

**`/evaluate`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030034139.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030034146.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030034152.png)

**Hmm... We can input something to execute codes.**

I tried to execute code, but no dice.

**`/lookup`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030034744.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030034812.png)

**Hmm... What if it's vulnerable to command injection?**

**According to [HackTricks](https://book.hacktricks.xyz/pentesting-web/command-injection#command-injection-execution), we can try some payloads:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030035033.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030035049.png)

**Oh! It works! Let's find out the flag!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030035123.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030035145.png)

We got the flag!

# Conclusion

What we've learned:

1. Exploiting Command Injection