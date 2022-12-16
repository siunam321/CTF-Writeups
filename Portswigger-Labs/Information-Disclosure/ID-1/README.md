# Information disclosure in error messages

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages), you'll learn: Information disclosure in error messages! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab's verbose error messages reveal that it is using a vulnerable version of a third-party framework. To solve the lab, obtain and submit the version number of this framework.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-1/images/Pasted%20image%2020221216051328.png)

In here, we can view the details of each products.

**Let's click on the `View details` button:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-1/images/Pasted%20image%2020221216051935.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-1/images/Pasted%20image%2020221216051943.png)

In here, we can see there is a GET parameter called `productId`.

**Hmm... What if that parameter is doing a SQL query?**

**If so, we can try to trigger a SQL error via `'`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-1/images/Pasted%20image%2020221216052044.png)

Boom! We found it!

- Web application version: `Apache Struts 2 2.3.31`

**In `searchsploit`(An offline version of Exploit-DB), we can see that it's vulnerable to Remote Code Execution(RCE)!**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Information-Disclosure/ID-1]
└─# searchsploit Apache Struts 2 2.3.31
-------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                          |  Path
-------------------------------------------------------------------------------------------------------- ---------------------------------
Apache Struts 2.0.1 < 2.3.33 / 2.5 < 2.5.10 - Arbitrary Code Execution                                  | multiple/remote/44556.py
Apache Struts 2.3 < 2.3.34 / 2.5 < 2.5.16 - Remote Code Execution (1)                                   | linux/remote/45260.py
Apache Struts 2.3 < 2.3.34 / 2.5 < 2.5.16 - Remote Code Execution (2)                                   | multiple/remote/45262.py
Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - 'Jakarta' Multipart Parser OGNL Injection (Metasploit)    | multiple/remote/41614.rb
Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - Remote Code Execution                                     | linux/webapps/41570.py
-------------------------------------------------------------------------------------------------------- ---------------------------------
```

# What we've learned:

1. Information disclosure in error messages