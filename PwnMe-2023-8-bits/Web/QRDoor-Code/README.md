# QRDoor Code

## Table of Contents

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)

## Overview

- 123 solves / 50 points
- Difficulty: Easy
- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★★

## Background

> Author: Eteck#3426

A company needed a website, to generate QR Code. They asked for a freelance to do this job

Since the website is up, they've noticed weird behaviour on their server

They need you to audit their code and help them to resolve their problem

_Flag is situed in /app/flag.txt_

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506120108.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506120211.png)

In here, we can type something to generate a QR code:

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506120354.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506120402.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506120422.png)

When the "Generate" button is clicked, it'll send a POST request to `/generate`, with JSON data of our input.

If no error occurred, it'll response us with a JSON data, in `code` key, it has the QR code image in base64 encoded, in `data`, it has our input.

**We can scan the QR code via a Linux command `zbarimg`:**
```shell
┌[siunam♥earth]-(~/ctf/PwnMe-2023-8-bits/Web/QRDoor-Code)-[2023.05.06|12:07:17(HKT)]
└> zbarimg qr.png
QR-Code:anything
scanned 1 barcode symbols from 1 images in 0.03 seconds
```

As excepted, it has our input's data.

**Now, let's look at the [source code](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/Web/QRDoor-Code/source.tar)!**
```shell
┌[siunam♥earth]-(~/ctf/PwnMe-2023-8-bits/Web/QRDoor-Code)-[2023.05.06|12:08:26(HKT)]
└> file source.tar 
source.tar: POSIX tar archive
┌[siunam♥earth]-(~/ctf/PwnMe-2023-8-bits/Web/QRDoor-Code)-[2023.05.06|12:08:28(HKT)]
└> tar xf source.tar                                                                                 
┌[siunam♥earth]-(~/ctf/PwnMe-2023-8-bits/Web/QRDoor-Code)-[2023.05.06|12:08:37(HKT)]
└> ls -lah source             
total 32K
drwxr-xr-x 4 siunam nam 4.0K Feb  1 04:46 .
drwxr-xr-x 3 siunam nam 4.0K May  6 12:08 ..
-rwxr-xr-x 1 siunam nam  192 Feb  1 04:46 docker-compose.yml
-rwxr-xr-x 1 siunam nam  183 Feb  1 04:54 Dockerfile
-rwxr-xr-x 1 siunam nam   55 Jan 17 22:37 .dockerignore
-rwxr-xr-x 1 siunam nam  429 Jan 17 22:22 package.json
drwxr-xr-x 2 siunam nam 4.0K Feb  1 04:46 src
drwxr-xr-x 2 siunam nam 4.0K Feb  1 04:46 views
```

In `src/index.js`, we can view the logic behind this web application.

**POST route `/generate`:**
```js
app.post('/generate', async (req, res) => {
    const { value } = req.body;
    try {
        let newQrCode;
        // If the length is too long, we use a default according to the length
        if (value.length > 150)
            newQrCode = new QRCode(null, value.lenght)
        else {
            newQrCode = new QRCode(String(value))
        }
        
        const code = await newQrCode.getImage()
        res.json({ code, data: newQrCode.value });
    } catch (error) {
        res.status(422).json({ message: "error", reason: 'Unknow error' });
    }
});
```

In here, it first checks the our input's length is greater 150.

If not, initialize the `QRCode` object instance with our input's value as `newQrCode`.

Then, send the response JSON data with the `code` key's value via `newQrCode`'s `getImage()` method and `data` key's value of our input.

**Let's look at the `QRCode` class!**
```js
class QRCode {
    constructor(value, defaultLength){
        this.value = value
        this.defaultLength = defaultLength
    }

    async getImage(){
        if(!this.value){
            // Use 'fortune' to generate a random funny line, based on the input size
            try {
                this.value = await execFortune(this.defaultLength)
            } catch (error) {
                this.value = 'Error while getting a funny line'
            }
        }
        return await qrcode.toDataURL(this.value).catch(err => 'error:(')
    }
}
```

**In the `getImage()` async method, it'll invoke function `execFortune()` with the input's length IF no `this.value`.** 

**Function `execFortune()`:**
```js
function execFortune(defaultLength) {
    return new Promise((resolve, reject) => {
     exec(`fortune -n ${defaultLength}`, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      }
      resolve(stdout? stdout : stderr);
     });
    });
   }
```

Right off the bat, we can see a sink (Dangerous function): `exec()`.

**The `exec()` is being imported from the `child_process` library:**
```js
const { exec } = require("child_process");
```

That being said, **if we can somehow inject our input to the `exec()` function, we can get OS command injection!**

> Note: The `fortune` program is to generate a random funny line from a database of quotations, based on the input size.
>   
> ```
> ┌[siunam♥earth]-(~/ctf/PwnMe-2023-8-bits/Web/QRDoor-Code/source)-[2023.05.06|12:30:38(HKT)]
> └> fortune -n 1337 
> Q:	What is purple and conquered the world?
> A:	Alexander the Grape.
> ```

**`fortune` man page:**
```shell
FORTUNE(6)                                UNIX Reference Manual                               FORTUNE(6)

NAME
       fortune - print a random, hopefully interesting, adage
[...]
   Options
       The options are as follows:
[...]
       -n length
              Set the longest fortune length (in characters) considered to be ``short'' (the default  is
              160).  All fortunes longer than this are considered ``long''.  Be careful!  If you set the
              length too short and ask for short fortunes, or too long and ask for  long  ones,  fortune
              goes into a never-ending thrash loop.
[...]
```

However, I don't think we can control the input's length to an evil payload...

Then in the `getImage()` method, if `this.value` is not null, it'll generate a QR code with our input's data and convert it to `data:image/png;base64,abcd...` URL format.

After poking around, I still couldn't find the vulnerability in this challenge...