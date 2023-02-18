# get flag 2

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217202938.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217202948.png)

So this challenge is almost the same as the "get flag 1" challenge, which is a **SSRF localhost filter bypass**.

**When we clicked the "Submit" button, it'll send a GET request to `/getUrl`, with parameter `url`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217203113.png)

**In "get flag 1", we used the following payload to bypass the localhost filter:**
```
http://127.1:9001/flag.txt
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217203209.png)

However, it won't work in this challenge.

**Again, refer to [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass#localhost):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217203327.png)

**After some trial and error, this bypass works:**
```
http://[::]:9001/flag.txt
```

If I recall correctly, the `[::]` is the representation of IPv6's localhost.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217203400.png)

We got the flag!

- **Flag: `ictf{ch3ck_1p_v6_cr239eatf21}`**

# Conclusion

What we've learned:

1. Exploiting SSRF (Server-Side Request Forgery) & Bypassing Filters Via IPv6 IP Address