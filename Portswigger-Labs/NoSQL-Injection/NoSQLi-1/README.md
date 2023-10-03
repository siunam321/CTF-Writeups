# Detecting NoSQL injection

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-detection), you'll learn: Detecting NoSQL injection! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

The product category filter for this lab is powered by a MongoDB NoSQL database. It is vulnerable to [NoSQL injection](https://portswigger.net/web-security/nosql-injection).

To solve the lab, perform a NoSQL injection attack that causes the application to display unreleased products.

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-1/images/Pasted%20image%2020231003143534.png)

In here, we can filter which products we want.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-1/images/Pasted%20image%2020231003143612.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-1/images/Pasted%20image%2020231003143630.png)

When we clicked the "Gifts" button, **it'll send a GET request to `/filter` with parameter `category`.**

Hmm... It seems like the `/filter` endpoint is interacting with the database, and search for "Gifts" related products.

That being said, let's hunt for SQL/NoSQL injection!

**Detecting syntax injection in MongoDB:**

Consider a shopping application that displays products in different categories. When the user selects the **Fizzy drinks** category, their browser requests the following URL:

```
https://insecure-website.com/product/lookup?category=fizzy
```

This causes the application to send a JSON query to retrieve relevant products from the `product` collection in the MongoDB database:

```javascript
this.category == 'fizzy'
```

To test whether the input may be vulnerable, submit a fuzz string in the value of the `category` parameter. An example string for MongoDB is:

```
'"`{
;$Foo}
$Foo \xYZ
```

Use this fuzz string to construct the following attack:

```
https://insecure-website.com/product/lookup?category='%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00
```

If this causes a change from the original response, this may indicate that user input isn't filtered or sanitized correctly.

> **Note:**
>  
> NoSQL injection vulnerabilities can occur in a variety of contexts, and you need to adapt your fuzz strings accordingly. Otherwise, you may simply trigger validation errors that mean the application never executes your query.
>  
> In this example, we're injecting the fuzz string via the URL, so the string is URL-encoded. In some applications, you may need to inject your payload via a JSON property instead. In this case, this payload would become 
 >  
> ```
> '\"`{\r;$Foo}\n$Foo \\xYZ\u0000
> ```

**Determining which characters are processed:**

To determine which characters are interpreted as syntax by the application, you can inject individual characters. For example, you could submit `'`, which results in the following MongoDB query:

```javascript
this.category == '''
```

If this causes a change from the original response, this may indicate that the `'` character has broken the query syntax and caused a syntax error. You can confirm this by submitting a valid query string in the input, for example by escaping the quote:

```javascript
this.category == '\''
```

If this doesn't cause a syntax error, this may mean that the application is vulnerable to an injection attack.

Armed with above information, **we can try to inject a single quoute (`'`) character to see if that's gonna cause any syntax error:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-1/images/Pasted%20image%2020231003144910.png)

Nice! We successfully triggered a syntax error! That being said, the `/filter` endpoint's GET parameter `category` is vulnerable to NoSQL injection!

**What if I escape the single quoute character?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-1/images/Pasted%20image%2020231003145240.png)

It worked normally!

## Exploitation

**Confirming conditional behavior:**

After detecting a vulnerability, the next step is to determine whether you can influence boolean conditions using NoSQL syntax.

To test this, send two requests, one with a false condition and one with a true condition. For example you could use the conditional statements `' && 0 && 'x` and `' && 1 && 'x` as follows:

```
https://insecure-website.com/product/lookup?category=fizzy'+%26%26+0+%26%26+'x
```

```
https://insecure-website.com/product/lookup?category=fizzy'+%26%26+1+%26%26+'x
```

If the application behaves differently, this suggests that the false condition impacts the query logic, but the true condition doesn't. This indicates that injecting this style of syntax impacts a server-side query.

**Overriding existing conditions:**

Now that you have identified that you can influence boolean conditions, you can attempt to override existing conditions to exploit the vulnerability. For example, you can inject a JavaScript condition that always evaluates to true, such as `'||1||'`:

```
https://insecure-website.com/product/lookup?category=fizzy%27%7c%7c%31%7c%7c%27
```

This results in the following MongoDB query:

```javascript
this.category == 'fizzy'||'1'=='1'
```

As the injected condition is always true, the modified query returns all items. This enables you to view all the products in any category, including hidden or unknown categories.

> Warning:
>  
> Take care when injecting a condition that always evaluates to true into a NoSQL query. Although this may be harmless in the initial context you're injecting into, it's common for applications to use data from a single request in multiple different queries. If an application uses it when updating or deleting data, for example, this can result in accidental data loss.

Now, let's **try to influence boolean conditions using NoSQL syntax!**

**False:**
```
' && 0 && 'x
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-1/images/Pasted%20image%2020231003145829.png)

No products are returned.

**True:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-1/images/Pasted%20image%2020231003145854.png)

Returns "Gifts" related products.

Therefore, **we can influence boolean conditions!**

Finally, we should able to **see all products by overriding the existing conditions!**

**Payload:**
```
/filter?category='||1||'
```

**This results in the following MongoDB query:**
```javascript
this.category == ''||'1'=='1'
```

**Since string `1` is always equals to string `1`, it'll evaluate `True`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/NoSQL-Injection/NoSQLi-1/images/Pasted%20image%2020231003150149.png)

Nice! We can see all products including the unreleased one!

## Conclusion

What we've learned:

1. Detecting NoSQL injection