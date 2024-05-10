# Finding and exploiting an unused API endpoint

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/api-testing/lab-exploiting-unused-api-endpoint), you'll learn: Finding and exploiting an unused API endpoint! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

To solve the lab, exploit a hidden API endpoint to buy a **Lightweight l33t Leather Jacket**. You can log in to your own account using the following credentials: `wiener:peter`.

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-2/images/Pasted%20image%2020240510142916.png)

In here, we can purchase some products.

We can also go to "My account" to login as user `wiener`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-2/images/Pasted%20image%2020240510143236.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-2/images/Pasted%20image%2020240510143243.png)

As for API testing, we can also gather a lot of information by browsing applications that use the API. This is often worth doing even if we have access to API documentation, as sometimes documentation may be inaccurate or out of date.

We can use Burp Scanner to crawl the application, then manually investigate interesting attack surface using Burp's browser.

While browsing the application, look for patterns that suggest API endpoints in the URL structure, such as `/api/`. Also look out for JavaScript files. These can contain references to API endpoints that you haven't triggered directly via the web browser. Burp Scanner automatically extracts some endpoints during crawls, but for a more heavyweight extraction, use the [JS Link Finder](https://portswigger.net/bappstore/0e61c786db0c4ac787a08c4516d52ccf) BApp. You can also manually review JavaScript files in Burp.

When we first visit this web application, we can see that **there's a JavaScript file has been loaded at `/resources/js/api/productPrice.js`**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-2/images/Pasted%20image%2020240510143943.png)

**In this JavaScript file, we can see that it fetches an API endpoint to get a product's price:**
```javascript
[...]
const loadPricing = (productId) => {
    const url = new URL(location);
    fetch(`//${url.host}/api/products/${encodeURIComponent(productId)}/price`)
        .then(res => res.json())
        .then(handleResponse(getAddToCartForm()));
};
[...]
```

That being said, **the API endpoint is at `/api/products/<productId>/price`**.

## Exploitation

Once we've identified API endpoints, interact with them using Burp Repeater and Burp Intruder. This enables us to observe the API's behavior and discover additional attack surface. For example, we could investigate how the API responds to changing the HTTP method and media type.

As we interact with the API endpoints, review error messages and other responses closely. Sometimes these include information that we can use to construct a valid HTTP request.

The HTTP method specifies the action to be performed on a resource. For example:

- `GET` - Retrieves data from a resource.
- `PATCH` - Applies partial changes to a resource.
- `OPTIONS` - Retrieves information on the types of request methods that can be used on a resource.

An API endpoint may support different HTTP methods. It's therefore important to test all potential methods when we're investigating API endpoints. This may enable us to identify additional endpoint functionality, opening up more attack surface.

For example, the endpoint `/api/tasks` may support the following methods:

- `GET /api/tasks` - Retrieves a list of tasks.
- `POST /api/tasks` - Creates a new task.
- `DELETE /api/tasks/1` - Deletes a task.

> Note:
>  
> When testing different HTTP methods, target low-priority objects. This helps make sure that you avoid unintended consequences, for example altering critical items or creating excessive records.

**Let's try to retrieve the price of a product by sending a GET request to the API endpoint `/api/products/<productId>/price`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-2/images/Pasted%20image%2020240510144434.png)

As you can see, it returned product ID 2's price and its message!

Hmm... What if the API endpoint accept **`PATCH` method to modify the price**? Or using `DELETE` method to delete the price?

Let's try modifying product ID 2's price!

Based on the result of GET request `/api/products/2/price`, the current price is `$66.91`.

Now we can **try to use `PATCH` method to modify the price**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-2/images/Pasted%20image%2020240510145347.png)

Oh... HTTP status code 400 Bad Request? Looks like we're missing some data and the data format.

API endpoints often expect data in a specific format. They may therefore behave differently depending on the content type of the data provided in a request. Changing the content type may enable us to:

- Trigger errors that disclose useful information.
- Bypass flawed defenses.
- Take advantage of differences in processing logic. For example, an API may be secure when handling JSON data but susceptible to injection attacks when dealing with XML.

To change the content type, modify the `Content-Type` header, then reformat the request body accordingly. We can use the [Content type converter](https://portswigger.net/bappstore/db57ecbe2cb7446292a94aa6181c9278) BApp to automatically convert data submitted within requests between XML and JSON.

**That being said, we can add the `Content-Type` request header with value `application/json` and `Content-Length` based on the `PATCH` method error respond:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-2/images/Pasted%20image%2020240510145626.png)

As you can see, we now triggered HTTP status code 500 Internal Server Error. This is because we didn't provide any JSON data.

**Let's try providing an empty JSON object:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-2/images/Pasted%20image%2020240510145747.png)

Now, it's telling us we need a `price` parameter in the JSON object!

**If we're trying to modify product ID 2's price, we can construct the following JSON data:**
```json
{"price": 49}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-2/images/Pasted%20image%2020240510145926.png)

Oh! Now it returned price `0.49`! 

**Hmm... What if the price is `0`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-2/images/Pasted%20image%2020240510150021.png)

It sets the price to `0`!

**If we send a GET request to `/api/products/2/price`, it'll show us the price is now `0`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-2/images/Pasted%20image%2020240510150134.png)

That being said, **we can purchase any products by modifying its price via API endpoint `/api/products/<productId>/price` with `PATCH` method**!

Let's modify the product "Lightweight "l33t" Leather Jacket"'s price to `0`!!

By inspecting the product's link, **the product ID is `1`**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-2/images/Pasted%20image%2020240510150325.png)

**Now we can set its price to `0`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-2/images/Pasted%20image%2020240510150427.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-2/images/Pasted%20image%2020240510150451.png)

Let's go buy it!!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-2/images/Pasted%20image%2020240510150510.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-2/images/Pasted%20image%2020240510150522.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-2/images/Pasted%20image%2020240510150532.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-2/images/Pasted%20image%2020240510150540.png)

## Conclusion

What we've learned:

1. Finding and exploiting an unused API endpoint