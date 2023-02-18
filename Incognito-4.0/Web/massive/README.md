# massive

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★☆

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217212322.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217212337.png)

In here, we can register an account and check email.

**Register:**
```html
[...]
<h2>Register</h2>
<form action="/register" method="POST">
    <div class="form-group">
        <label for="email">Email:</label>
        <input type="email" class="form-control" id="email" name="email" required>
    </div>
    <div class="form-group">
        <label for="password">Password:</label>
        <input type="password" class="form-control" id="password" name="password" required>
    </div>
    <button type="submit" class="btn btn-primary">Register</button>
</form>
[...]
```

When we clicked on the "Register" button, it'll send a POST request to `/register`, with parameter `email` and `password`.

**Check email:**
```html
[...]
<h2>Check Email</h2>
<form action="/checkUser" method="GET">
    <div class="form-group">
        <label for="email">Email:</label>
        <input type="email" class="form-control" id="email" name="email" required>
    </div>
    <button type="submit" class="btn btn-primary">Check Email</button>
</form>
[...]
```

When we clicked on the "Check Email" account, it'll send a GET request to `/checkuser`, with parameter `email`.

Let's try to register an account!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217212637.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217212643.png)

**Then, we can go to `/login` to login:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217212704.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217212708.png)

**After that, we can go to `/` to test the check email function:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217212740.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217212747.png)

**It returns a JSON data!**
```json
{
    "exists":true,
    "isAdmin":false
}
```

Hmm... It seems like our goal is to let the `isAdmin`'s value to `true`?

## Exploitation

**Now, we can try to do SQL injection to perform authenication bypass:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217214204.png)

However, it'll be blocked by the client-side filter in `<input type="email">` .

**To bypass that, we can simply use Burp Suite's Repeater:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217214320.png)

It seems like it doesn't vulnerable to SQL injection?

Hmm... Based on my experience, we can also try **second order SQL injection**.

To do so, we **first need to register an account**, which contains SQL injection payload, then **use the check email function to see anything weird**.

**We can assume it's using MySQL and the register SQL query is like this:**
```sql
INSERT INTO users VALUES ('password', 'username');
```

**Check email function SQL query:**
```sql
SELECT * FROM users WHERE username='username';
```

However, I tried to inject SQL payloads, but they couldn't work...

After fumbling around, I found the login page is indeed vulnerable to ***NoSQL injection***:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230218180308.png)

***That being said, the back-end is using some NoSQL DBMS (Database Management System) like MongoDB!***

However, I still wasn't able to do anything other than authentication bypass...