# protoTYPE:v2 - sanityXSS

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★★

- Challenge difficulty: ★★☆☆☆

## Background

protoTYPE:v2 is your next music landing page.

Web: [http://chal-a.hkcert22.pwnable.hk:28142](http://chal-a.hkcert22.pwnable.hk:28142) , [http://chal-b.hkcert22.pwnable.hk:28142](http://chal-b.hkcert22.pwnable.hk:28142)

**Credit**

Music: Pollution - AleMambrin [CC BY 3.0] [https://soundcloud.com/djalemambrin/alejandro-mambrin-pollution](https://soundcloud.com/djalemambrin/alejandro-mambrin-pollution)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111101250.png)

## Find the flag

In the home page, we can `Edit` the album, and report abuse! 

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111101317.png)

**Edit:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111101405.png)

**We're allow to edit the URL! Which very likely can be abused to XSS (Cross-Site Scripting)!**

**Report Abuse:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111101649.png)

In here, we can send an abuse ticket, and an **admin** will inspect that!

**Let's use [Webhook.site](https://webhook.site) to capture the admin requests!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111101825.png)

```html
<iframe src="https://webhook.site/5d93b54e-1000-4941-a358-b50e48824e09">
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111102215.png)

**Then send an abuse ticket:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111102250.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221111102328.png)

**We received a GET request!**

**User-Agent:**
```
Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36
```

Hmm... The `referer` looks sussy: `http://prototype:3000/`

**It's local, maybe it's vulnerable to SSRF (Server-Side Request Forgery)?**

However, I kept trying different XSS to SSRF paylods like using an `<img>` tag to redirect to my controlled external JavaScript, using `<iframe>` tag to read local file (`file:///etc/passwd`), but still no dice... Maybe it's not about XSS or SSRF? Like JavaScript prototype pollution??

