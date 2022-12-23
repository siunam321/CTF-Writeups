# Server-side template injection in a sandboxed environment

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-a-sandboxed-environment), you'll learn: Server-side template injection in a sandboxed environment! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

This lab uses the Freemarker template engine. It is vulnerable to [server-side template injection](https://portswigger.net/web-security/server-side-template-injection) due to its poorly implemented sandbox. To solve the lab, break out of the sandbox to read the file `my_password.txt` from Carlos's home directory. Then submit the contents of the file.

You can log in to your own account using the following credentials:

`content-manager:C0nt3ntM4n4g3r`

## Exploitation

**Login as user `content-manager`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-6/images/Pasted%20image%2020221223051157.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-6/images/Pasted%20image%2020221223051205.png)

**In previous labs, we found that we can edit product posts' template:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-6/images/Pasted%20image%2020221223051237.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-6/images/Pasted%20image%2020221223051243.png)

**Let's clean that up:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-6/images/Pasted%20image%2020221223051431.png)

**Next, we need to know which template engine is using via triggering an error:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-6/images/Pasted%20image%2020221223051508.png)

It's using **a template engine called FreeMarker, which is written in Java.**

**Then, we can try to get code execution:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-6/images/Pasted%20image%2020221223051720.png)

Hmm... `Instantiating freemarker.template.utility.Execute is not allowed in the template for security reasons.`

Looks like we're inside a sandbox, which will have a hard time to get code executed.

**Let's do a sandbox bypass!**

**According [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#freemarker-java), we can do sandbox bypass via:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-6/images/Pasted%20image%2020221223054650.png)

**Let's copy and paste that:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-6/images/Pasted%20image%2020221223054718.png)

Hmm... It displays an error message.

**However, if you take a look at the error message, you'll find this:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-6/images/Pasted%20image%2020221223054808.png)

`Failed at: #assign classloader = article.class.p... [in template "freemarker" at line 1, column 1]`

In the first line of our sandbox bypass, it's loading a class, and it's loading class `article`, which doesn't exist in this lab.

**If remember at the beginning, we have an object called `product`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-6/images/Pasted%20image%2020221223054956.png)

**Let's use that object as the class loader!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-6/images/Pasted%20image%2020221223055023.png)

Boom! We successfully bypassed the sandbox, and got code execution!

**Let's `cat` the `my_password.txt` file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-6/images/Pasted%20image%2020221223055120.png)

We now can submit it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-6/images/Pasted%20image%2020221223055136.png)

# What we've learned:

1. Server-side template injection in a sandboxed environment