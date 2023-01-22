# GET Me

## Overview

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

- Challenge static score: 25

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121141545.png)

## Find the flag

**In the challenge's description, we can interact with the API via `http://167.99.8.90:9009/`:**
```shell
┌[root♥siunam]-(~/ctf/KnightCTF-2023/Web/GET-Me)-[2023.01.21|14:16:07(HKT)]
└> curl http://167.99.8.90:9009/    
{"success":false,"message":"Sorry ! You can't GET it :P"}
```

Hmm... You can't **GET** it.

So, it's clear that **it's referring to HTTP method GET.**

**Maybe we can provide a GET parameter?**
```shell
┌[root♥siunam]-(~/ctf/KnightCTF-2023/Web/GET-Me)-[2023.01.21|14:18:27(HKT)]
└> curl 'http://167.99.8.90:9009/index.php?success=true'
{"success":false,"message":"Sorry ! You can't GET it :P"}
```

Nope.

**How about a POST request?**
```
┌[root♥siunam]-(~/ctf/KnightCTF-2023/Web/GET-Me)-[2023.01.21|14:23:08(HKT)]
└> curl 'http://167.99.8.90:9009/index.php' -X POST -d "success=true" 
{"success":false,"message":"You should send me a url !"}
```

I guess it's not allow POST request?

**Or it needs a POST request with parameter `url`?**
```shell
┌[root♥siunam]-(~/ctf/KnightCTF-2023/Web/GET-Me)-[2023.01.21|14:30:51(HKT)]
└> curl 'http://167.99.8.90:9009/index.php' -X POST -d "url=test"    
{"success":false,"message":"Looking for flag ? Visit https:\/\/hackenproof.com\/user\/security"}
```

It is!

At the first glance, I though that URL is a rabbit hole.

**However, when I finished the registration process, I found the flag in `/user/security`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121143932.png)

We found the flag!

- Flag: `KCTF{H4ck3nPr00f3d_bY_Kn16h75qu4d}`

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121144020.png)

# Conclusion

What we've learned:

1. Enumerating Hidden Parameter In An API Endpoint