# Detecting server-side prototype pollution without polluted property reflection

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/prototype-pollution/server-side/lab-detecting-server-side-prototype-pollution-without-polluted-property-reflection), you'll learn: Detecting server-side prototype pollution without polluted property reflection! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is built on Node.js and the Express framework. It is vulnerable to server-side [prototype pollution](https://portswigger.net/web-security/prototype-pollution) because it unsafely merges user-controllable input into a server-side JavaScript object.

To solve the lab, confirm the vulnerability by polluting `Object.prototype` in a way that triggers a noticeable but non-destructive change in the server's behavior. As this lab is designed to help you practice non-destructive detection techniques, you don't need to progress to exploitation.

You can log in to your own account with the following credentials: `wiener:peter`

> Note:
>  
> When testing for server-side prototype pollution, it's possible to break application functionality or even bring down the server completely. If this happens to your lab, you can manually restart the server using the button provided in the lab banner. Remember that you're unlikely to have this option when testing real websites, so you should always use caution.

## Identifying server-side prototype pollution

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-7/images/Pasted%20image%2020230222163319.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-7/images/Pasted%20image%2020230222163335.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-7/images/Pasted%20image%2020230222163356.png)

In here, we can update our billing and delivery address.

Let's try to update it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-7/images/Pasted%20image%2020230222163424.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-7/images/Pasted%20image%2020230222163429.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-7/images/Pasted%20image%2020230222163438.png)

When we clicked the "Submit" button, it'll send a POST request to `/my-account/change-address`, with parameter `address_line_1`, `address_line_2`, `city`, `postcode`, `county`, `sessionId` in JSON format.

**If there's no error, the web application will respond us a JSON data:**
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

`POST` or `PUT` requests that submit JSON data to an application or API are prime candidates for this kind of behavior as it's common for servers to respond with a JSON representation of the new or updated object. In this case, we could attempt to pollute the global `Object.prototype` with an arbitrary property:

```json
{
    "address_line_1":"Wiener HQ",
    "address_line_2":"One Wiener Way",
    "city":"Wienerville",
    "postcode":"BU1 1RP",
    "country":"UK",
    "sessionId":"3CDlQIVpMaczwnZCiGUZdpKd4MyD5BZW",
    "__proto__": {
        "foo": "bar"
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-7/images/Pasted%20image%2020230222163910.png)

However, we don't see the response reflect our polluted property.

Most of the time, even when we successfully pollute a server-side prototype object, we won't see the affected property reflected in a response. Given that we can't just inspect the object in a console either, this presents a challenge when trying to tell whether our injection worked.

One approach is to try injecting properties that match potential configuration options for the server. We can then compare the server's behavior before and after the injection to see whether this configuration change appears to have taken effect. If so, this is a strong indication that we've successfully found a server-side prototype pollution vulnerability.

In this section, we'll look at the following techniques:

- [Status code override](#status-code-override)
- [JSON spaces override](#json-spaces-override)
- [Charset override](#charset-override)

All of these injections are non-destructive, but still produce a consistent and distinctive change in server behavior when successful.

### Status code override

Server-side JavaScript frameworks like Express allow developers to set custom HTTP response statuses. In the case of errors, a JavaScript server may issue a generic HTTP response, but include an error object in JSON format in the body. This is one way of providing additional details about why an error occurred, which may not be obvious from the default HTTP status.

Although it's somewhat misleading, it's even fairly common to receive a `200 OK` response, only for the response body to contain an error object with a different status:

```http
HTTP/1.1 200 OK
[...]
{
    "error": {
        "success": false,
        "status": 401,
        "message": "You do not have permission to access this resource."
    }
}
```

Node's `http-errors` module contains the following function for generating this kind of error response:

```js
function createError () {
    //...
    if (type === 'object' && arg instanceof Error) {
        err = arg
        status = err.status || err.statusCode || status
    } else if (type === 'number' && i === 0) {
    //...
    if (typeof status !== 'number' ||
    (!statuses.message[status] && (status > 400 || status >= 600))) {
        status = 500
    }
    //...
```

The first highlighted line attempts to assign the `status` variable by reading the `status` or `statusCode` property from the object passed into the function. If the website's developers haven't explicitly set a `status` property for the error, we can potentially use this to probe for prototype pollution as follows:

1. Find a way to trigger an error response and take note of the default status code.
2. Try polluting the prototype with your own `status` property. Be sure to use an obscure status code that is unlikely to be issued for any other reason.
3. Trigger the error response again and check whether we've successfully overridden the status code.

> Note:
>  
> You must choose a status code in the `400`-`599` range. Otherwise, Node defaults to a `500` status regardless, as you can see from the second highlighted line, so you won't know whether you've polluted the prototype or not.

Armed with above information, we can **pollute the `status` property to identify the web application is vulnerable to server-side prototype pollution**.

#### Find a way to trigger an error response and take note of the default status code

**To do so, we can try to provide an invalid syntax of JSON data in `/my-account/change-address`:**
```json
{
    "address_line_1":"Wiener HQ",
    "address_line_2":"One Wiener Way",
    "city":"Wienerville",
    "postcode":"BU1 1RP",
    "country":"UK",
    "sessionId":"3CDlQIVpMaczwnZCiGUZdpKd4MyD5BZW",
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-7/images/Pasted%20image%2020230222165006.png)

As you can see, we've successfully triggered an error response, and the default status code is **400**.

#### Try polluting the prototype with your own `status` property

**In here, I'll use "418 I'm tea pot" HTTP status code:**
```json
{
    "address_line_1":"Wiener HQ",
    "address_line_2":"One Wiener Way",
    "city":"Wienerville",
    "postcode":"BU1 1RP",
    "country":"UK",
    "sessionId":"3CDlQIVpMaczwnZCiGUZdpKd4MyD5BZW",
    "__proto__": {
        "status": 418
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-7/images/Pasted%20image%2020230222165244.png)

#### Trigger the error response again and check whether we've successfully overridden the status code

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-7/images/Pasted%20image%2020230222165319.png)

We've successfully overridden the status code!

### JSON spaces override

The Express framework provides a `json spaces` option, which enables us to configure the number of spaces used to indent any JSON data in the response. In many cases, developers leave this property undefined as they're happy with the default value, making it susceptible to pollution via the prototype chain.

If we've got access to any kind of JSON response, we can try polluting the prototype with our own `json spaces` property, then reissue the relevant request to see if the indentation in the JSON increases accordingly. We can perform the same steps to remove the indentation in order to confirm the vulnerability.

This is an especially useful technique because it doesn't rely on a specific property being reflected. It's also extremely safe as you're effectively able to turn the pollution on and off simply by resetting the property to the same value as the default.

Although the prototype pollution has been fixed in Express 4.17.4, websites that haven't upgraded may still be vulnerable.

> Note:
>  
> When attempting this technique in Burp, remember to switch to the message editor's **Raw** tab. Otherwise, you won't be able to see the indentation change as the default prettified view normalizes this.

**Before polluted:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-7/images/Pasted%20image%2020230222170430.png)

**After polluted:**
```json
{
    "address_line_1":"Wiener HQ",
    "address_line_2":"One Wiener Way",
    "city":"Wienerville",
    "postcode":"BU1 1RP",
    "country":"UK",
    "sessionId":"3CDlQIVpMaczwnZCiGUZdpKd4MyD5BZW",
    "__proto__": {
        "json spaces": 1
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-7/images/Pasted%20image%2020230222170503.png)

As you can see, the JSON response has 1 space for indentation! Which means the web application is vulnerable to server-side prototype pollution!

### Charset override

Express servers often implement so-called "middleware" modules that enable preprocessing of requests before they're passed to the appropriate handler function. For example, the `body-parser` module is commonly used to parse the body of incoming requests in order to generate a `req.body` object. This contains another gadget that you can use to probe for server-side prototype pollution.

Notice that the following code passes an options object into the `read()` function, which is used to read in the request body for parsing. One of these options, `encoding`, determines which character encoding to use. This is either derived from the request itself via the `getCharset(req)` function call, or it defaults to UTF-8.

```js
var charset = getCharset(req) || 'utf-8'

function getCharset (req) {
    try {
        return (contentType.parse(req).parameters.charset || '').toLowerCase()
    } catch (e) {
        return undefined
    }
}

read(req, res, next, parse, debug, {
    encoding: charset,
    inflate: inflate,
    limit: limit,
    verify: verify
})
```

If you look closely at the `getCharset()` function, it looks like the developers have anticipated that the `Content-Type` header may not contain an explicit `charset` attribute, so they've implemented some logic that reverts to an empty string in this case. Crucially, this means it may be controllable via prototype pollution. If you can find an object whose properties are visible in a response, you can use this to probe for sources. In the following example, we'll use UTF-7 encoding and a JSON source.

#### Add an arbitrary UTF-7 encoded string to a property that's reflected in a response

**For example, `foo` in UTF-7 is `+AGYAbwBv-`:**
```json
{
    "address_line_1":"Wiener HQ",
    "address_line_2":"One Wiener Way",
    "city":"Wienerville",
    "postcode":"BU1 1RP",
    "country":"+AGYAbwBv-",
    "sessionId":"LVZ7jbWv3Msehakz2Pvdsg1trqHFnLH8"
}
```

#### Send the request

**Servers won't use UTF-7 encoding by default, so this string should appear in the response in its encoded form:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-7/images/Pasted%20image%2020230222172513.png)

#### Try to pollute the prototype with a `content-type` property that explicitly specifies the UTF-7 character set

```json
{
    "address_line_1":"Wiener HQ",
    "address_line_2":"One Wiener Way",
    "city":"Wienerville",
    "postcode":"BU1 1RP",
    "country":"+AGYAbwBv-",
    "sessionId":"LVZ7jbWv3Msehakz2Pvdsg1trqHFnLH8",
    "__proto__": {
        "content-type": "application/json; charset=utf-7"
    }
}
```

#### Repeat the first request

**If you successfully polluted the prototype, the UTF-7 string should now be decoded in the response:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Prototype-Pollution/Prototype-7/images/Pasted%20image%2020230222172656.png)

Due to a bug in Node's `_http_incoming` module, this works even when the request's actual `Content-Type` header includes its own `charset` attribute. To avoid overwriting properties when a request contains duplicate headers, the `_addHeaderLine()` function checks that no property already exists with the same key before transferring properties to an `IncomingMessage` object:

```js
IncomingMessage.prototype._addHeaderLine = _addHeaderLine;
function _addHeaderLine(field, value, dest) {
    // ...
    } else if (dest[field] === undefined) {
        // Drop duplicates
        dest[field] = value;
    }
}
```

If it does, the header being processed is effectively dropped. Due to the way this is implemented, this check (presumably unintentionally) includes properties inherited via the prototype chain. This means that if we pollute the prototype with our own `content-type` property, the property representing the real `Content-Type` header from the request is dropped at this point, along with the intended value derived from the header.

# What we've learned:

1. Detecting server-side prototype pollution without polluted property reflection