# SpyBug

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★☆

## Background

As Pandora made her way through the ancient tombs, she received a message from her contact in the Intergalactic Ministry of Spies. They had intercepted a communication from a rival treasure hunter who was working for the alien species. The message contained information about a digital portal that leads to a software used for intercepting audio from the Ministry's communication channels. Can you hack into the portal and take down the aliens counter-spying operation?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319222456.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230321140009.png)

In here, we see there's a login page.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/Web/SpyBug/web_spybug.zip):**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/SpyBug)-[2023.03.21|14:00:33(HKT)]
└> file web_spybug.zip 
web_spybug.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/SpyBug)-[2023.03.21|14:00:34(HKT)]
└> unzip web_spybug.zip    
Archive:  web_spybug.zip
   creating: web_spybug/
  inflating: web_spybug/Dockerfile   
  inflating: web_spybug/build-docker.sh  
   creating: web_spybug/challenge/
   creating: web_spybug/challenge/control-panel/
  inflating: web_spybug/challenge/control-panel/example.env  
   creating: web_spybug/challenge/control-panel/middleware/
  inflating: web_spybug/challenge/control-panel/middleware/authagent.js  
  inflating: web_spybug/challenge/control-panel/middleware/authuser.js  
  inflating: web_spybug/challenge/control-panel/index.js  
   creating: web_spybug/challenge/control-panel/utils/
  inflating: web_spybug/challenge/control-panel/utils/database.js  
  inflating: web_spybug/challenge/control-panel/utils/adminbot.js  
   creating: web_spybug/challenge/control-panel/models/
  inflating: web_spybug/challenge/control-panel/models/user.js  
  inflating: web_spybug/challenge/control-panel/models/recordings.js  
  inflating: web_spybug/challenge/control-panel/models/index.js  
  inflating: web_spybug/challenge/control-panel/models/agent.js  
  inflating: web_spybug/challenge/control-panel/package-lock.json  
  inflating: web_spybug/challenge/control-panel/package.json  
   creating: web_spybug/challenge/control-panel/static/
   creating: web_spybug/challenge/control-panel/static/css/
  inflating: web_spybug/challenge/control-panel/static/css/bootstrap.min.css  
  inflating: web_spybug/challenge/control-panel/static/css/custom.css  
  inflating: web_spybug/challenge/control-panel/static/css/bootstrap.min.css.map  
  inflating: web_spybug/challenge/control-panel/static/css/line-awesome.min.css  
   creating: web_spybug/challenge/control-panel/static/js/
  inflating: web_spybug/challenge/control-panel/static/js/bootstrap.min.js  
   creating: web_spybug/challenge/control-panel/static/img/
 extracting: web_spybug/challenge/control-panel/static/img/icon.png  
   creating: web_spybug/challenge/control-panel/static/fonts/
  inflating: web_spybug/challenge/control-panel/static/fonts/la-regular-400.woff  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-brands-400.ttf  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-solid-900.eot  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-regular-400.svg  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-brands-400.woff2  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-solid-900.woff  
  inflating: web_spybug/challenge/control-panel/static/fonts/Orbitron-Regular.ttf  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-brands-400.eot  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-solid-900.ttf  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-brands-400.woff  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-brands-400.svg  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-solid-900.woff2  
  inflating: web_spybug/challenge/control-panel/static/fonts/OFL.txt  
 extracting: web_spybug/challenge/control-panel/static/fonts/la-regular-400.woff2  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-regular-400.eot  
  inflating: web_spybug/challenge/control-panel/static/fonts/Orbitron-VariableFont_wght.ttf  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-solid-900.svg  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-regular-400.ttf  
   creating: web_spybug/challenge/control-panel/views/
  inflating: web_spybug/challenge/control-panel/views/login.pug  
  inflating: web_spybug/challenge/control-panel/views/head.pug  
  inflating: web_spybug/challenge/control-panel/views/panel.pug  
   creating: web_spybug/challenge/control-panel/routes/
  inflating: web_spybug/challenge/control-panel/routes/generic.js  
  inflating: web_spybug/challenge/control-panel/routes/agents.js  
  inflating: web_spybug/challenge/control-panel/routes/panel.js  
   creating: web_spybug/challenge/agent/
  inflating: web_spybug/challenge/agent/spybug-agent.go  
  inflating: web_spybug/challenge/agent/go.mod  
  inflating: web_spybug/challenge/agent/go.sum  
  inflating: web_spybug/challenge/agent/rec.wav  
  inflating: web_spybug/challenge/.prettierignore  
  inflating: web_spybug/challenge/.gitignore  
   creating: web_spybug/conf/
  inflating: web_spybug/conf/supervisord.conf
```

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319222507.png)

In here, we see there's a login page.

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/SpyBug)-[2023.03.19|22:25:44(HKT)]
└> file web_spybug.zip              
web_spybug.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/SpyBug)-[2023.03.19|22:25:46(HKT)]
└> unzip web_spybug.zip              
Archive:  web_spybug.zip
   creating: web_spybug/
  inflating: web_spybug/Dockerfile   
  inflating: web_spybug/build-docker.sh  
   creating: web_spybug/challenge/
   creating: web_spybug/challenge/control-panel/
  inflating: web_spybug/challenge/control-panel/example.env  
   creating: web_spybug/challenge/control-panel/middleware/
  inflating: web_spybug/challenge/control-panel/middleware/authagent.js  
  inflating: web_spybug/challenge/control-panel/middleware/authuser.js  
  inflating: web_spybug/challenge/control-panel/index.js  
   creating: web_spybug/challenge/control-panel/utils/
  inflating: web_spybug/challenge/control-panel/utils/database.js  
  inflating: web_spybug/challenge/control-panel/utils/adminbot.js  
   creating: web_spybug/challenge/control-panel/models/
  inflating: web_spybug/challenge/control-panel/models/user.js  
  inflating: web_spybug/challenge/control-panel/models/recordings.js  
  inflating: web_spybug/challenge/control-panel/models/index.js  
  inflating: web_spybug/challenge/control-panel/models/agent.js  
  inflating: web_spybug/challenge/control-panel/package-lock.json  
  inflating: web_spybug/challenge/control-panel/package.json  
   creating: web_spybug/challenge/control-panel/static/
   creating: web_spybug/challenge/control-panel/static/css/
  inflating: web_spybug/challenge/control-panel/static/css/bootstrap.min.css  
  inflating: web_spybug/challenge/control-panel/static/css/custom.css  
  inflating: web_spybug/challenge/control-panel/static/css/bootstrap.min.css.map  
  inflating: web_spybug/challenge/control-panel/static/css/line-awesome.min.css  
   creating: web_spybug/challenge/control-panel/static/js/
  inflating: web_spybug/challenge/control-panel/static/js/bootstrap.min.js  
   creating: web_spybug/challenge/control-panel/static/img/
 extracting: web_spybug/challenge/control-panel/static/img/icon.png  
   creating: web_spybug/challenge/control-panel/static/fonts/
  inflating: web_spybug/challenge/control-panel/static/fonts/la-regular-400.woff  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-brands-400.ttf  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-solid-900.eot  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-regular-400.svg  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-brands-400.woff2  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-solid-900.woff  
  inflating: web_spybug/challenge/control-panel/static/fonts/Orbitron-Regular.ttf  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-brands-400.eot  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-solid-900.ttf  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-brands-400.woff  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-brands-400.svg  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-solid-900.woff2  
  inflating: web_spybug/challenge/control-panel/static/fonts/OFL.txt  
 extracting: web_spybug/challenge/control-panel/static/fonts/la-regular-400.woff2  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-regular-400.eot  
  inflating: web_spybug/challenge/control-panel/static/fonts/Orbitron-VariableFont_wght.ttf  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-solid-900.svg  
  inflating: web_spybug/challenge/control-panel/static/fonts/la-regular-400.ttf  
   creating: web_spybug/challenge/control-panel/views/
  inflating: web_spybug/challenge/control-panel/views/login.pug  
  inflating: web_spybug/challenge/control-panel/views/head.pug  
  inflating: web_spybug/challenge/control-panel/views/panel.pug  
   creating: web_spybug/challenge/control-panel/routes/
  inflating: web_spybug/challenge/control-panel/routes/generic.js  
  inflating: web_spybug/challenge/control-panel/routes/agents.js  
  inflating: web_spybug/challenge/control-panel/routes/panel.js  
   creating: web_spybug/challenge/agent/
  inflating: web_spybug/challenge/agent/spybug-agent.go  
  inflating: web_spybug/challenge/agent/go.mod  
  inflating: web_spybug/challenge/agent/go.sum  
  inflating: web_spybug/challenge/agent/rec.wav  
  inflating: web_spybug/challenge/.prettierignore  
  inflating: web_spybug/challenge/.gitignore  
   creating: web_spybug/conf/
  inflating: web_spybug/conf/supervisord.conf
```

In `/views/*.pug`, we see that this web application is using a **JavaScript template engine called "Pug"**.

**In `/views/panel.pug`, the `username` variable is directly concatenated:**
```js
body
	div.container.login.mt-5.mb-5
		div.row
			div.col-md-10
				h1
					i.las.la-satellite-dish
					| &nbsp;Spybug v1
			div.col-md-2.float-right
				a.btn.login-btn.mt-3(href="/panel/logout") Log-out
		hr 
		h2 #{"Welcome back " + username}
		[...]
```

Maybe it's vulnerable to ***SSTI*** (Server-Side Template Injection)?

Let's move on.

**In `/utils/adminbot.js`, we can see that there's an admin bot running a Chromium browser via `puppeteer`.**

**Config:**
```js
require("dotenv").config();

const puppeteer = require("puppeteer");

const browserOptions = {
  headless: true,
  executablePath: "/usr/bin/chromium-browser",
  args: [
    "--no-sandbox",
    "--disable-background-networking",
    "--disable-default-apps",
    "--disable-extensions",
    "--disable-gpu",
    "--disable-sync",
    "--disable-translate",
    "--hide-scrollbars",
    "--metrics-recording-only",
    "--mute-audio",
    "--no-first-run",
    "--safebrowsing-disable-auto-update",
    "--js-flags=--noexpose_wasm,--jitless",
  ],
};
```

**This `adminbot.js` has an async function called `visitPanel`:**
```js
exports.visitPanel = async () => {
  try {
    const browser = await puppeteer.launch(browserOptions);
    let context = await browser.createIncognitoBrowserContext();
    let page = await context.newPage();

    await page.goto("http://0.0.0.0:" + process.env.API_PORT, {
      waitUntil: "networkidle2",
      timeout: 5000,
    });

    await page.type("#username", "admin");
    await page.type("#password", process.env.ADMIN_SECRET);
    await page.click("#loginButton");

    await page.waitForTimeout(5000);
    await browser.close();
  } catch (e) {
    console.log(e);
  }
};
```

It'll launch an incognito browser, then go to `http://0.0.0.0:<API_PORT>`.

***After that, the bot will type it's username `admin`, password, and click "Login" button.***

Finally, the browser will be closed after 5 seconds.

Armed with above information, this challenge is about ***client-side***, and maybe we need to somehow steal admin's password?

In `/routes/panel.js`, we see routes (endpoints) in this web application.

**First off, the `/panel` route:**
```js
router.get("/panel", authUser, async (req, res) => {
  res.render("panel", {
    username:
      req.session.username === "admin"
        ? process.env.FLAG
        : req.session.username,
    agents: await getAgents(),
    recordings: await getRecordings(),
  });
});
```

When we send a GET request to `/panel` and we're logged in, it checks the session's username is `admin` or not.

If we're `admin`, **it'll parse the flag** and username to template `panel.pug`, and renders it.

With that said, **our goal in this challenge is to login as `admin`.**

**Route `/panel/login`:**
```js
router.post("/panel/login", async (req, res) => {
  let username = req.body.username;
  let password = req.body.password;

  if (!(username && password)) return res.sendStatus(400);
  if (!(await checkUserLogin(username, password)))
    return res.redirect("/panel/login");

  req.session.loggedin = true;
  req.session.username = username;

  res.redirect("/panel");
});
```

**Function `checkUserLogin` in `/utils/database.js`:**
```js
exports.checkUserLogin = async (username, password) => {
  const results = await db.User.findOne({
    where: {
      username: username,
    },
  });

  if (!results) return false;

  if (!bcrypt.compareSync(password, results.password)) return false;

  return true;
};
```

When we send a POST request to `/panel/login` with parameter `username` and `password`, it'll check those are valid or not.

If it's valid, create a new session for our user.

Hmm... It seems like we can't do NoSQL injection to bypass the authentication in here...

In `/routes/agents.js`, we see there are 4 routes.

**Route `/agents/register`:**
```js
router.get("/agents/register", async (req, res) => {
  res.status(200).json(await registerAgent());
});
```

**Function `registerAgent()` in `/utils/database.js`:**
```js
exports.registerAgent = async () => {
  const agentId = uuidv4();
  const agentToken = uuidv4();

  const options = {
    identifier: agentId,
    token: agentToken,
  };

  await db.Agent.create(options);

  return options;
};
```

When we send a GET request to `/agents/register`, it'll call function `registerAgent()` from `/utils/database.js` to create a new agent, and response us a JSON data.

**Route `/agents/check/:identifier/:token`:**
```js
router.get("/agents/check/:identifier/:token", authAgent, (req, res) => {
  res.sendStatus(200);
});
```

**It first checks we're an agent or not from `/middleware/authagent.js`:**
```js
const { checkAgentLogin } = require("../utils/database");

module.exports = async (req, res, next) => {
  const { identifier, token } = req.params;

  if (!(identifier && token)) return res.sendStatus(400);

  if (!(await checkAgentLogin(identifier, token))) return res.sendStatus(401);

  next();
};
```

**Function `checkAgentLogin()` from `/utils/database`:**
```js
exports.checkAgentLogin = async (agentId, agentToken) => {
  const results = await db.Agent.findOne({
    where: {
      [Op.and]: [{ identifier: agentId }, { token: agentToken }],
    },
  });

  if (!results) return false;

  return true;
};
```

**Route `/agents/details/:identifier/:token`:**
```js
router.post(
  "/agents/details/:identifier/:token",
  authAgent,
  async (req, res) => {
    const { hostname, platform, arch } = req.body;
    if (!hostname || !platform || !arch) return res.sendStatus(400);
    await updateAgentDetails(req.params.identifier, hostname, platform, arch);
    res.sendStatus(200);
  }
);
```

**Function `updateAgentDetails()` from `/utils/database`:**
```js
exports.updateAgentDetails = async (agentId, hostname, platform, arch) => {
  await db.Agent.update(
    {
      hostname: hostname,
      platform: platform,
      arch: arch,
    },
    {
      where: {
        identifier: agentId,
      },
    }
  );
};
```

When we send a POST request to `/agents/details/:identifier/:token` with parameter `hostname`, `platform`, `arch`, it'll update our agent details.

**Route `/agents/upload/:identifier/:token`:**
```js
router.post(
  "/agents/upload/:identifier/:token",
  authAgent,
  multerUpload.single("recording"),
  async (req, res) => {
    if (!req.file) return res.sendStatus(400);

    const filepath = path.join("./uploads/", req.file.filename);
    const buffer = fs.readFileSync(filepath).toString("hex");

    if (!buffer.match(/52494646[a-z0-9]{8}57415645/g)) {
      fs.unlinkSync(filepath);
      return res.sendStatus(400);
    }

    await createRecording(req.params.identifier, req.file.filename);
    res.send(req.file.filename);
  }
);
```

**`multerUpload`:**
```js
const storage = multer.diskStorage({
  filename: (req, file, cb) => {
    cb(null, uuidv4());
  },
  destination: (req, file, cb) => {
    cb(null, "./uploads");
  },
});

const multerUpload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (
      file.mimetype === "audio/wave" &&
      path.extname(file.originalname) === ".wav"
    ) {
      cb(null, true);
    } else {
      return cb(null, false);
    }
  },
});
```

**Function `createRecording()` in `/utils/database.js`:**
```js
exports.createRecording = async (agentId, filepath) => {
  await db.Recording.create({
    agentId: agentId,
    filepath: "/uploads/" + filepath,
  });
};
```

When we send a POST request to `/agents/upload/:identifier/:token`, it requires to upload a WAV audio file.

**Then, it checks the file contains the WAV file signatures:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230322141337.png)

If the file contains it, create a new recording, and put it to `/uploads/<filepath>`.

Hmm... What can we do with that...

**After some local testing, I found that we can inject HTML code in the `/panel` via updating agent's details.**

**First, register a new agent:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/SpyBug/web_spybug/challenge/control-panel)-[2023.03.22|14:19:29(HKT)]
└> curl http://localhost:1337/agents/register 
{"identifier":"7983500a-13af-4cab-a99c-7f93496fcf29","token":"23ccc082-9355-406c-a083-2746a9a583f9"}
```

**Then, use those `identifier` and `token` to update the `hostname`, `platform` and `arch` in `/agents/details/:identifier/:token`:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/SpyBug/web_spybug/challenge/control-panel)-[2023.03.22|14:40:45(HKT)]
└> curl http://localhost:1337/agents/details/7983500a-13af-4cab-a99c-7f93496fcf29/23ccc082-9355-406c-a083-2746a9a583f9 --data "hostname=host&platform=plat&arch=<h1>Header1</h1>" 
OK
```

**After that, I added `console.log()` in `/utils/adminbot.js`, so that I can see the admin's password:**
```shell
[...]
DNUIK9jqISWeLSzh93IKaSFbishkYUYn
2023-03-22 06:43:27,763 INFO reaped unknown pid 964 (terminated by SIGKILL)
2023-03-22 06:43:27,763 INFO reaped unknown pid 947 (terminated by SIGKILL)
2023-03-22 06:43:27,763 INFO reaped unknown pid 948 (terminated by SIGKILL)
2023-03-22 06:43:27,763 INFO reaped unknown pid 926 (terminated by SIGKILL)
2023-03-22 06:43:27,764 INFO reaped unknown pid 927 (terminated by SIGKILL)
[...]
```

**`/panel`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230322144443.png)

Hmm... I wonder if can we exploit **stored XSS**...

**However, in `/index.js`, we see the CSP (Content Security Policy):**
```js
res.setHeader("Content-Security-Policy", "script-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none';");
```

- **The `script-src` directive is `self`**, which means we can execute JavaScript only if the `src` is pointing to the domain itself.
- The `frame-ancestors` directive is `none`, which means we **can't use `<iframe>` element**.
- The `object-src` directive is `none`, which means we **can't use `<object>`, `<embed>`, `<applet>` elements**.
- The `base-uri` directive is `none`, which means we **can't use `<base>` element**.

That being said, **if we can upload our own evil JavaScript**, we can execute any JavaScript code in `/panel`, which we'll then try to steal the flag/admin's password.

**So, the exploitation process is:**
- Update our agent's details, which has a `<script>` element, and it's `src` attribute is pointing to our evil JavaScript
- Then, that JavaScript will exfilltrate the `/panel`'s content to a site that unders our control.
- Finally, we should received user `admin`'s panel's flag.

**In route `/agents/upload/:identifier/:token`, we can upload a WAV audio file:**
```js
const multerUpload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (
      file.mimetype === "audio/wave" &&
      path.extname(file.originalname) === ".wav"
    ) {
      cb(null, true);
    } else {
      return cb(null, false);
    }
  },
});
[...]
router.post(
  "/agents/upload/:identifier/:token",
  authAgent,
  multerUpload.single("recording"),
  async (req, res) => {
    if (!req.file) return res.sendStatus(400);

    const filepath = path.join("./uploads/", req.file.filename);
    console.log(filepath);
    const buffer = fs.readFileSync(filepath).toString("hex");

    if (!buffer.match(/52494646[a-z0-9]{8}57415645/g)) {
      fs.unlinkSync(filepath);
      return res.sendStatus(400);
    }

    await createRecording(req.params.identifier, req.file.filename);
    res.send(req.file.filename);
  }
);
```

The `multerUpload.single("recording")` means **the field is `recording`.**

Also, it checks **MIME type is `audio/wave` and the extension is `.wav`.**

Hmm... I wonder if we can upload a file to arbitrary path via path travsal...

```bash
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/SpyBug)-[2023.03.23|20:33:47(HKT)]
└> curl http://localhost:1337/agents/upload/7e7c1171-d6a9-4a51-a80f-eb71bc39870f/447ab5f5-d794-4c58-be62-ab7acd6b5513 -F "recording=@rec.wav" -H "Content-Type: audio/wave"
Bad Request
```

However, I couldn't upload it...

Also, the challenge provided a Go lang source code `spybug-agent.go`, I tried to compile and run it on my VM, but it outputs an error, and says couldn't find my sound card...