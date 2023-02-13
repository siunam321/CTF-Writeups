# california-state-police

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★☆

- 40 solves / 480 points

## Background

> Author: aplet123

Stop! You're under arrest for making suggestive 3 letter acronyms!

[california-state-police.lac.tf](https://california-state-police.lac.tf)

[Admin Bot](https://admin-bot.lac.tf/california-state-police) (note: the `adminpw` cookie is HttpOnly and SameSite=Lax)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230212153602.png)

## Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/raw/main/LA-CTF-2023/Web/california-state-police/index.js):**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/california-state-police)-[2023.02.12|15:36:12(HKT)]
└> file index.js 
index.js: JavaScript source, ASCII text
```

Let's look at that JavaScript source code file!

**TL;DR: The source code is very same as another web challenge: metaverse.**

**In line 31 - 41, we see this:**
```js
app.get("/flag", (req, res) => {
    res.status(400).send("you have to POST the flag this time >:)");
});

app.post("/flag", (req, res) => {
    if (req.cookies.adminpw === adminpw) {
        res.send(flag);
    } else {
        res.status(400).send("no hacking allowed");
    }
});
```

**In here, the flag is in `/flag` route, and we need to send a POST request and cookie `adminpw`.**

**In line 43 - 49, we see this:**
```js
app.use((req, res, next) => {
    res.set(
        "Content-Security-Policy",
        "default-src 'none'; script-src 'unsafe-inline'"
    );
    next();
});
```

As you can see, the web application set a CSP (Content Security Policy).

> **Content Security Policy** ([CSP](https://developer.mozilla.org/en-US/docs/Glossary/CSP)) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross-Site Scripting ([XSS](https://developer.mozilla.org/en-US/docs/Glossary/Cross-site_scripting)) and data injection attacks. These attacks are used for everything from data theft, to site defacement, to malware distribution.

The CSP has 2 directives: `default-src` and `script-src`.

- `default-src`:

It's set to `none`, which means it disallows every domain.

- `script-src`:

**It's set to `unsafe-inline`**, which means the web application doesn't block inline JavaScript code. **That being said, we can inject JavaScript code without getting blocked by the CSP.**

**[Google's CSP Evaluator](https://csp-evaluator.withgoogle.com/):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230212154546.png)

**In line 51 - 74, we see this:**
```js
app.post("/report", (req, res) => {
    res.type("text/plain");
    const crime = req.body.crime;
    if (typeof crime !== "string") {
        res.status(400).send("no crime provided");
        return;
    }
    if (crime.length > 2048) {
        res.status(400).send("our servers aren't good enough to handle that");
        return;
    }
    const id = uuid();
    reports.set(id, crime);
    cleanup.push([id, Date.now() + 1000 * 60 * 60 * 3]);
    res.redirect("/report/" + id);
});

app.get("/report/:id", (req, res) => {
    if (reports.has(req.params.id)) {
        res.type("text/html").send(reports.get(req.params.id));
    } else {
        res.type("text/plain").status(400).send("report doesn't exist");
    }
});
```

In `/report` route, we can provide a parameter called `crime`, it'll then check the data type is string and length is less then 2048 or not.

If all the checks passed, it'll redirect us to `/report/<uuidv4>`.

In `/report/<uuidv4>` route, it'll first check the UUID exist or not. If exist, display the report content.

Now, we can go to the home page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230212154623.png)

In here, we can write a crime report to California State Police (**Funny enough it's abbreviation is CSP**).

Let's try to write a testing crime report:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230212154751.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230212154806.png)

As expected, when we submit the crime, it redirects us to `/report/<uuidv4>`, and display our submitted crime details.

**Hmm... Let's try to inject JavaScript code:**
```html
<script>alert(document.domain)</script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230212155018.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230212155024.png)

It works like a charm!

Now, how can we leverage this stored XSS (Cross-Site Scripting) to retreive admin bot's `adminpw` cookie?

In `/report`, there is no CSRF (Cross-Site Request Forgery) token, or other CSRF protection.

**So, we can perform a CSRF attack via XSS!**

Umm... How do we get the report UUID? How to post the admin bot's `adminpw` cookie when the attribute `HttpOnly` is set to true? How to bypass the CSP to retrieve the report UUID?

However, I still couldn't figure those out...