# Exploiting an API endpoint using documentation

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/api-testing/lab-exploiting-api-endpoint-using-documentation), you'll learn: Exploiting an API endpoint using documentation! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

To solve the lab, find the exposed API documentation and delete `carlos`. You can log in to your own account using the following credentials: `wiener:peter`.

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-1/images/Pasted%20image%2020240510134000.png)

In here, we can click the "My account" link to login as user `wiener`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-1/images/Pasted%20image%2020240510134125.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-1/images/Pasted%20image%2020240510134255.png)

After logging in, we can update our email address by submitting a form.

Let's update it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-1/images/Pasted%20image%2020240510134819.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-1/images/Pasted%20image%2020240510134844.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-1/images/Pasted%20image%2020240510134938.png)

When we clicked the "Update email" button, it'll send a PATCH request to **`/api/user/wiener`** with a JSON data.

Since the web application uses API (Application Programming Interfaces) to interact with the backend, we can now do some API testing!

To start API testing, we first need to find out as much information about the API as possible, to discover its attack surface.

To begin, we should identify API endpoints. These are locations where an API receives requests about a specific resource on its server. For example, consider the following `GET` request:

```http
GET /api/books HTTP/1.1
Host: example.com
```

The API endpoint for this request is `/api/books`. This results in an interaction with the API to retrieve a list of books from a library. Another API endpoint might be, for example, `/api/books/mystery`, which would retrieve a list of mystery books.

In our case, **the API endpoint is `/api/user/wiener`**.

Once we have identified the endpoints, we need to determine how to interact with them. This enables us to construct valid HTTP requests to test the API. For example, we should find out information about the following:

- The input data the API processes, including both compulsory and optional parameters.
- The types of requests the API accepts, including supported HTTP methods and media formats.
- Rate limits and authentication mechanisms.

Luckily, **APIs are usually documented** so that developers know how to use and integrate with them.

Documentation can be in both human-readable and machine-readable forms. Human-readable documentation is designed for developers to understand how to use the API. It may include detailed explanations, examples, and usage scenarios. Machine-readable documentation is designed to be processed by software for automating tasks like API integration and validation. It's written in structured formats like JSON or XML.

API documentation is often publicly available, particularly if the API is intended for use by external developers. If this is the case, always start our recon by reviewing the documentation.

Even if API documentation isn't openly available, we may still be able to access it by browsing applications that use the API.

To do this, we can use [Burp Scanner](https://portswigger.net/burp/vulnerability-scanner) to crawl the API. You can also browse applications manually using Burp's browser. Look for endpoints that may refer to API documentation, for example:

- `/api`
- `/swagger/index.html`
- `/openapi.json`

If we identify an endpoint for a resource, make sure to investigate the base path. For example, if we identify the resource endpoint `/api/swagger/v1/users/123`, then we should investigate the following paths:

- `/api/swagger/v1`
- `/api/swagger`
- `/api`

In our case, we can investigate base path of the update email API endpoint `/api/user/<username>`!

For instance, we can send a GET request to `/api/user`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-1/images/Pasted%20image%2020240510135942.png)

**Nope, how about `/api/`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-1/images/Pasted%20image%2020240510140007.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-1/images/Pasted%20image%2020240510140109.png)

Oh! It returned HTTP status code 200!

Now, we can see this web application's RESTful (Representational State Transfer) API documentation!

In here, the API has **1 endpoint with 3 methods**:

|Verb|Endpoint|Parameters|Response|
|---|---|---|---|
|GET|`/user/[username: String]`|`{ }`|200 OK, User|
|DELETE|`/user/[username: String]`|`{ }`|200 OK, Result|
|PATCH|`/user/[username: String]`|`{"email": String}`|200 OK, User|

## Exploitation

According to [Mdn web docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/DELETE), the **HTTP `DELETE` request method** is to delete the specified resource.

That being said, we can delete any accounts (if it doesn't have any access control) via the DELETE method at endpoint `/api/user/<username>`!

Let's delete `carlos` account by sending a DELETE request to endpoint `/api/user/carlos`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-1/images/Pasted%20image%2020240510140716.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-1/images/Pasted%20image%2020240510140726.png)

Nice! We successfully deleted `carlos`'s account!

## Conclusion

What we've learned:

1. Exploiting an API endpoint using documentation