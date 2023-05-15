# dev.corp 1/4

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find the flag](#find-the-flag)
4. [Conclusion](#conclusion)

## Overview

- 258 solves / 50 points
- Difficulty: Easy
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

The famous company dev.corp was hack last week.. They don't understand because they have followed the security standards to avoid this kind of situation. You are mandated to help them understand the attack.  
  
For this first step, you're given the logs of the webserver of the company.  
  
Could you find :  
- The CVE used by the attacker ?  
- What is the absolute path of the most sensitive file recovered by the attacker ?  
  
Format : **Hero{CVE-XXXX-XXXX:/etc/passwd}**  
Author : **Worty**  
  
Here is a diagram representing the company's infrastructure:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513151644.png)

## Find the flag

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/Forensic/dev-corp-1/access.log):**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Forensic/dev-corp-1-4)-[2023.05.13|15:17:07(HKT)]
└> file access.log      
access.log: ASCII text, with very long lines (455)
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Forensic/dev-corp-1-4)-[2023.05.13|15:17:09(HKT)]
└> wc -l access.log   
1856 access.log
```

It's a webserver access log.

**In the company's infrastructure's diagram, we can see that it has a Gitlab service:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513151820.png)

**Hmm... Let's search for `git` in the `access.log`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513151935.png)

Right off the bat, we see something weird.

Someone sent 4 requests to `/shell` and `/.git`. However, those requests response a **404 Not Found HTTP status**. Let's move on!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513152107.png)

Then, I found the `/.git` requests again. But this time, it responses a **200 OK HTTP status**.

**Also, there's a very sussy GET request in `/wp-admin/admin-ajax.php`:**
```
internalproxy.devcorp.local - - [02/May/2023:13:12:29 +0000] "GET //wp-admin/admin-ajax.php?action=duplicator_download&file=../../../../../../../../../etc/passwd HTTP/1.1" 200 2240 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0"
```

The `file` GET parameter is a payload for Directory Traversal.

**Let's search for "Wordpress duplicator_download CVE":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513152316.png)

**Nice! We found the CVE number: `CVE-2020-11738`.**

This WordPress `Duplicator` plugin is vulnerable to Directory Traversal!

**Now, we can use `duplicator_download` to search which files are being recovered by the attacker!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513152509.png)

Oh no! The attacker retrieved the `webuser` private SSH key!!! Which means he/she can access the web server if the SSH service is enabled!

- **Flag: `Hero{CVE-2020-11738:/home/webuser/.ssh/id_rsa}`**

## Conclusion

What we've learned:

1. HTTP Access Log Forensic