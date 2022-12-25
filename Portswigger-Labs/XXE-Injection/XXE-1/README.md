# Exploiting XXE using external entities to retrieve files

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files), you'll learn: Exploiting XXE using external entities to retrieve files! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has a "Check stock" feature that parses XML input and returns any unexpected values in the response.

To solve the lab, inject an XML external entity to retrieve the contents of the `/etc/passwd` file.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-1/images/Pasted%20image%2020221225051301.png)

**Let's view one of those products' details:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-1/images/Pasted%20image%2020221225051334.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-1/images/Pasted%20image%2020221225051343.png)

In here, we can see there is a `Check stock` button.

**Let's use Burp Suite to intercept the request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-1/images/Pasted%20image%2020221225051434.png)

When we clicked that button, it'll send a POST request to `/product/stock`, **with an XML data!**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>1</productId>
    <storeId>1</storeId>
</stockCheck>
```

**Let's try to send an invalid XML data in the `<productId>` tag:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-1/images/Pasted%20image%2020221225052059.png)

As you can see, the response in **reflected** to us!

**Armed with that information, we can try to do an XXE injection!**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>1</storeId>
</stockCheck>
```

**In here, we defined:**

- The root element of the document is `root` (`!DOCTYPE root`)
- Then, inside that root element, **we defined an external entity(variable) called `xxe`, which is using keyword `SYSTEM` to fetch file `/etc/passwd`**
- Finally, we want to **use the `xxe` entity in `<productId>` tag**, so we can see the output of `/etc/passwd`. To do so, we need to use `&entity_name;`

**Let's send our XXE payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-1/images/Pasted%20image%2020221225052927.png)

Nice! We successfully to extract the content of `/etc/passwd`!

# What we've learned:

1. Exploiting XXE using external entities to retrieve files