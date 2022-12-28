# Web cache poisoning via ambiguous requests

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-web-cache-poisoning-via-ambiguous-requests), you'll learn: Web cache poisoning via ambiguous requests! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

This lab is vulnerable to [web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning) due to discrepancies in how the cache and the back-end application handle ambiguous requests. An unsuspecting user regularly visits the site's home page.

To solve the lab, poison the cache so the home page executes `alert(document.cookie)` in the victim's browser.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-3/images/Pasted%20image%2020221228020017.png)

In the previous labs, we found that the back-end application will handle `Host` HTTP header.

**Let's send the `/` GET request to Burp Repeater:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-3/images/Pasted%20image%2020221228020303.png)

**Then, we can try to modify the `Host` header. For example, we can try to input any domain:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-3/images/Pasted%20image%2020221228020358.png)

As you can see, it responses a HTTP status `504 Gateway Timeout`, and **our input is being reflected.**

**Also, after testing it, I found that our requests had been cached:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-3/images/Pasted%20image%2020221228021603.png)

**Let's add an arbitrary query parameter to your requests to serve as a cache buster:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-3/images/Pasted%20image%2020221228021730.png)

If we want a fresh response from the back-end server, we can just change that parameter.

**After some testing, I found that when we add another `Host` header with any domain, something weird happend:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-3/images/Pasted%20image%2020221228022012.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-3/images/Pasted%20image%2020221228022035.png)

Our second `Host` header domain is reflected in an absolute URL used to **import a script from `/resources/js/tracking.js`!**

**Let's repeat the same process until we generate a new cache:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-3/images/Pasted%20image%2020221228022432.png)

**Now, what if I remove the second `Host` header and send the request again using the same cache buster?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-3/images/Pasted%20image%2020221228022826.png)

It's still there!

**Armed with above information, we can go to the exploit server, and create a file at `/resources/js/tracking.js` containing the payload `alert(document.cookie)`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-3/images/Pasted%20image%2020221228023036.png)

**Now, we can send request multiple times, and test it works or not:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-3/images/Pasted%20image%2020221228023306.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-3/images/Pasted%20image%2020221228023318.png)

It worked!

**Now, we can remove the GET parameter in Burp Repeater, and then send request multiple times:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-3/images/Pasted%20image%2020221228023424.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-3/images/Pasted%20image%2020221228023429.png)

We did it!

# What we've learned:

1. Web cache poisoning via ambiguous requests