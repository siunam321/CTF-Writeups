# get flag 1

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217201529.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217201547.png)

**View source page:**
```html
[...]
<h1>URL Form</h1>
<form action="/getUrl" method="get">
    <div class="form-group">
        <label for="url">Enter URL:</label>
        <input type="text" class="form-control" id="url" name="url" placeholder="Enter URL here" required>
    </div>
    <button type="submit" class="btn btn-primary">Submit</button>
</form>
[...]
```

As you can see, it's a simple HTML form.

When we clicked the "Submit" button, it'll send a GET request to `/getUrl`, with parameter `url`.

**Let's try to send something:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217201737.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217201758.png)

In here, our supplied URL is reflected to the web page!

## Exploitation

Armed with above information, it seems like it may be vulnerable to SSRF (Server-Side Request Forgery)! Which means **we can try to reach internal services**!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217202633.png)

Umm... What??

It should reach to the internal service on port 9001...

Maybe there are some filters??

If so, we can try to bypass that.

**According to [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass#localhost), we can use the following payload to bypass it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217202749.png)

**After some trial and error, this payload works!**
```
http://127.1:9001/flag.txt
```

This payload `127.1` is the same as `127.0.0.1`, which is localhost.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217202823.png)

Nice! We got the flag!

- **Flag: `ictf{l0c4l_byp4$$_323theu0a9}`**

# Conclusion

What we've learned:

1. Exploiting SSRF (Server-Side Request Forgery) & Bypassing Filters