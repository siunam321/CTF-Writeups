# Chm0d

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Conclusion](#conclusion)

## Overview

- 227 solves / 50 points
- Difficulty: Easy
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Catch-22: a problematic situation for which the only solution is denied by a circumstance inherent in the problem.  
  
Credentials: `user:password123`  
  
> Deploy on [deploy.heroctf.fr](https://deploy.heroctf.fr/)  
  
Format : **Hero{flag}**  
Author : **Alol**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513161434.png)

## Enumeration

**In this challenge, we can SSH into `user`:**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/System/Chm0d)-[2023.05.13|15:31:37(HKT)]
└> ssh user@dyn-01.heroctf.fr -p 10937
[...]
user@dyn-01.heroctf.fr's password: 
[...]
user@abd21caf673f9e58806b515153437124:~$ whoami;hostname;id
user
abd21caf673f9e58806b515153437124
uid=1000(user) gid=1000(user) groups=1000(user)
```

**In `/`, we can see there's a `flag.txt`:**
```shell
user@abd21caf673f9e58806b515153437124:~$ ls -lah /flag.txt
---------- 1 user user 40 May 12 11:43 /flag.txt
```

However, it's permission is set to nothing (`----------`).

**Hmm... Can we use the `chmod` binary to change it's permission?**
```shell
user@abd21caf673f9e58806b515153437124:~$ ls -lah /bin/chmod
---------- 1 root root 63K Sep 24  2020 /bin/chmod
```

Uhh... What? We can't use `/bin/chmod`...

Now, I wonder if we can **transfer the `chmod` binary...**

However, I tried to find a static version of `chmod` or trying to get `busybox` to the instance machine, no dice...

**After fumbling around, I started to search: "linux chmod alternative", and I found [this StackExchange](https://unix.stackexchange.com/questions/83862/how-to-chmod-without-usr-bin-chmod) post:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513160844.png)

**Ah ha! Does `perl` exist in the instance machine?**
```shell
user@66282c22a4a04940a6f4bc1fbf3923e8:~$ which perl
/usr/bin/perl
```

It does!

**Let's change the `/flag.txt` file permission using `perl`!**
```shell
user@66282c22a4a04940a6f4bc1fbf3923e8:~$ perl -e 'chmod 0755, "/flag.txt"'
perl: warning: Setting locale failed.
perl: warning: Please check that your locale settings:
	LANGUAGE = (unset),
	LC_ALL = (unset),
	LANG = "en_US.UTF-8"
    are supported and installed on your system.
perl: warning: Falling back to the standard locale ("C").
user@66282c22a4a04940a6f4bc1fbf3923e8:~$ ls -lah /flag.txt 
-rwxr-xr-x 1 user user 40 May 12 11:44 /flag.txt
```

Nice!! We can now read the flag!

```shell
user@66282c22a4a04940a6f4bc1fbf3923e8:~$ cat /flag.txt 
Hero{chmod_1337_would_have_been_easier}
```

- **Flag: `Hero{chmod_1337_would_have_been_easier}`**

## Conclusion

What we've learned:

1. Modifiying File Permission Using Perl