# Referrrrer

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- 193 solves / 50 points
- Difficulty: Easy
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Defeated the security of the website which implements authentication based on the [Referer](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer) header.  
  
URL : **[http://static-01.heroctf.fr:7000](http://static-01.heroctf.fr:7000)**  
Format : **Hero{flag}**  
Author : **xanhacks**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513135735.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513135622.png)

Seems empty??

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/Web/Referrrrer/Referrrrer.zip):**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Web/Referrrrer)-[2023.05.13|13:58:02(HKT)]
└> file Referrrrer.zip 
Referrrrer.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Web/Referrrrer)-[2023.05.13|13:58:03(HKT)]
└> unzip Referrrrer.zip 
Archive:  Referrrrer.zip
   creating: app/
  inflating: app/package.json        
  inflating: app/index.js            
  inflating: app/package-lock.json   
  inflating: app/Dockerfile          
  inflating: docker-compose.yml      
   creating: nginx/
  inflating: nginx/nginx.conf
```

**In `app/index.js`, we see this:**
```js
const express = require("express")
const app = express()


app.get("/", (req, res) => {
    res.send("Hello World!");
})

app.get("/admin", (req, res) => {
    if (req.header("referer") === "YOU_SHOUD_NOT_PASS!") {
        return res.send(process.env.FLAG);
    }

    res.send("Wrong header!");
})

app.listen(3000, () => {
    console.log("App listening on port 3000");
})
```

When we send a GET request to `/admin`, **if the request header `Referer` is strictly equal to `YOU_SHOUD_NOT_PASS!`, it'll response us with the flag.**

With that said, we have to some how pass the header check...

**In `nginx/nginx.conf`, we can see there's a rule for location `/admin`:**
```conf
[...]
server {
    listen 80;
    server_name example.com;

    location / {
        proxy_pass http://express_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /admin {
        if ($http_referer !~* "^https://admin\.internal\.com") {
            return 403;
        }

        proxy_pass http://express_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
[...]
```

**If the `Referer` header is equal to `https://admin.internal.com`**, it'll let us pass go to `/admin`.

So... We need to provide `Referer` header with 2 value: `https://admin.internal.com` **AND** `YOU_SHOUD_NOT_PASS!`?

**However, I tried to include 2 `Referer` header in the `/admin` request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513145627.png)

But it doesn't work, because it only checks the first `Referer` header and ignoring the second one.

## Exploitation

**After some research, I found this [StackOverflow](https://stackoverflow.com/questions/7237262/how-do-i-find-the-a-referring-sites-url-in-node) post:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513185416.png)

Oh! They are the same thing in Express 4.x?

**Let's try that!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513185444.png)

Nice! We got the flag!

- **Flag: `Hero{ba7b97ae00a760b44cc8c761e6d4535b}`**

## Conclusion

What we've learned:

1. Exploiting Referer-based Access Control In Node.js Express