# User role can be modified in user profile

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile), you'll learn: User role can be modified in user profile! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

This lab has an admin panel at `/admin`. It's only accessible to logged-in users with a `roleid` of 2.

Solve the lab by accessing the admin panel and using it to delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-4/images/Pasted%20image%2020221212044715.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-4/images/Pasted%20image%2020221212044735.png)

**In here, we can `Update email`. Let's intercept that request in Burp Suite's Repeater!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-4/images/Pasted%20image%2020221212045522.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-4/images/Pasted%20image%2020221212050356.png)

**It's sending a POST request to `/my-account/change-email`, and contain a JSON data with our supplied email address.**

**Also, when we send the POST request, we can see the response is:**
```json
{
  "username": "wiener",
  "email": "wiener@normal-user.net",
  "apikey": "Qvbkfk3gByoLDZrgkvPw43om5BsJC7nz",
  "roleid": 1
}
```

**Hmm... What if I set the `roleid` to 2?? Which is suppose to be user `administrator`!**
```json
{
  "email":"wiener@normal-user.net",
  "roleid": 2
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-4/images/Pasted%20image%2020221212051310.png)

**Now, let's try to go to the admin panel (`/admin`):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-4/images/Pasted%20image%2020221212050743.png)

We can access the admin panel!!

Let's delete user `carlos`!!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-4/images/Pasted%20image%2020221212050810.png)

# What we've learned:

1. User role can be modified in user profile