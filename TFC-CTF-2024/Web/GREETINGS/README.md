# GREETINGS

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 234 solves / 50 points
- Author: @skyv3il
- Difficulty: Warmup
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Welcome to our ctf! Hope you enjoy it! Have fun

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240804194303.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240804194317.png)

In here, we can submit a form with our name.

Let's try to submit a dummy name and see what will happen:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240804194436.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240804194450.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240804194642.png)

When we clicked the "Submit" button, it'll send a GET request to `/result` with GET parameter `username`.

In the server's response from Burp Suite, we can see there's a response header called `X-Powered-By`, and its value is `Express`.

With that said, this web application is written in **JavaScript** with **[Node.js](https://nodejs.org/en)** JavaScript runtime and **[Express.js](https://expressjs.com/)** web application framework.

Now, since **our user input is being reflected on the response**, we should think about why the application did this.

In modern days of web application, the HTML contents are **dynamically generated**. To achieve this, there's a technology called "**Server-side templating**".

A quick Google search about vulnerabilities in server-side templating, we'll see a type of vulnerability called "**Server-Side Template Injection**", or **SSTI** for short.

In [HackTricks about SSTI's tips and tricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection), we'll see how we can test for SSTI vulnerability and learn different template engine's SSTI payloads.

After trying different Node.js based template engine's SSTI payloads, we see that template engine [PugJs](https://pugjs.org/api/getting-started.html) works:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240804202144.png)

In PugJs, the template literal is `#{}`. In our case, we can try to make the server render the template `#{7*7}` to check if the server renders `49`. ($ 7 * 7 = 49 $)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240804202545.png)

Nice! The server indeed rendered our template and returned `49`!

> Note: The `%23` is URL encoded `#`. If we don't URL encode it, the `{7*7}` part will not send to the server, because `#` is the [URI fragment](https://en.wikipedia.org/wiki/URI_fragment).

## Exploitation

Armed with the above information, we can confirm that this web application is vulnerable to **PugJs SSTI**!

In [HackTricks's PugJs SSTI payload](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#pugjs-nodejs), we can achieve Remote Code Execution (RCE) via the following payload:

```pug
#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('touch /tmp/pwned.txt')}()}
```

I won't go into the details of this payload, but it basically loads the [`child_process`](https://nodejs.org/api/child_process.html) Node.js module and uses function [`exec`](https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback) to execute OS commands.

However, if we send the request with the above payload, it won't display the executed OS command result:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240804203958.png)

This is because the above payload is a function and it didn't return anything.

To fix this, we can simply remove the function syntax and variable declaration:

```pug
#{global.process.mainModule.constructor._load("child_process").exec('id')}
```

Now send the new payload again:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240804205904.png)

This time it returned `[object Object]`!

Why? This is because the `exec` function is asynchronous.

To solve this, we can change the `exec` function to [`execSync`](https://nodejs.org/api/child_process.html#child_processexecsynccommand-options), which is a synchronous function:

```pug
#{global.process.mainModule.constructor._load("child_process").execSync('id')}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240804210143.png)

Nice! Now we can find where's the flag file path and read its content!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240804210224.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240804210243.png)

- **Flag: `TFCCTF{a6afc419a8d18207ca9435a38cb64f42fef108ad2b24c55321be197b767f0409}`**

If you're curious the implementation of this vulnerable web application, we can read the source code file `app.js`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240804210545.png)

**`app.js`:**
```javascript
const express = require('express');
const pug = require('pug');

const app = express();
const port = 8000;

app.set('view engine', 'pug');
app.set('views', './views');

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/result', (req, res) => {
    // Get the username from the query string
    const username = req.query.username || 'Guest';

    // Vulnerable Implementation
    const templateString = `
doctype html
html(lang="en")
  head
    meta(charset="UTF-8")
    meta(name="viewport" content="width=device-width, initial-scale=1.0")
    title Result
    style.
      [...CSS stuff...]
  body
    .container
      h1 Welcome ${username}!
      p Give me a username and I will say hello to you.
    `;

    // Render the template without compiling
    const output = pug.render(templateString);

    // Send the rendered HTML as the response
    res.send(output);
});

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
```

As you can see, GET route (Endpoint) `/result` retrieves our `username` GET parameter's value, and directly renders the `username`'s value without any sanitization whatsoever. Therefore, this route is vulnerable to PugJs SSTI. 

## Conclusion

What we've learned:

1. PugJs Server-Side Template Injection (SSTI)