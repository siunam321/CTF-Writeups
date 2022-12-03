# SQL injection vulnerability allowing login bypass

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/sql-injection/lab-login-bypass), you'll learn: SQL injection vulnerability allowing login bypass! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains an [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability in the login function.

To solve the lab, perform an SQL injection attack that logs in to the application as the `administrator` user.

## Explotation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-2/images/Pasted%20image%2020221203042233.png)

**We can see that there is a `My account` link, let's enumerate that page!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-2/images/Pasted%20image%2020221203042315.png)

It's a login form!

We can try to guess the `administrator` user's password! Like `administrator:password`

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-2/images/Pasted%20image%2020221203042442.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-2/images/Pasted%20image%2020221203042449.png)

Nope. It didn't work.

Now, let's try to do a **SQL injection to bypass the authentication**!

**Imagine this is the login SQL statement:**
```sql
SELECT * FROM users WHERE username = '' AND password = ''
```

Since there is **no protection against SQL injection**, we can injection some malicious payloads in the `username` field!

**To login as `administrator` without the password, we can:**

**Payload:**
```sql
administrator'-- -
```

**New SQL statement:**
```sql
SELECT * FROM users WHERE username = 'administrator'-- -' AND password = ''
```

As you can see, **we've commented out the `AND` clause**, which means we don't need the `administrator` password!

**Let's use that payload to bypass the authentication!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-2/images/Pasted%20image%2020221203043239.png)

> Note: The password can be anything.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-2/images/Pasted%20image%2020221203043006.png)

**We're logged in as user `administrator`!**

# Conclusion

What we've learned:

1. SQL injection vulnerability allowing login bypass