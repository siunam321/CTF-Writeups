# Basic password reset poisoning

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning/lab-host-header-basic-password-reset-poisoning), you'll learn: Basic password reset poisoning! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to password reset poisoning. The user `carlos` will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account.

You can log in to your own account using the following credentials: `wiener:peter`. Any emails sent to this account can be read via the email client on the exploit server.

## Exploitation

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-1/images/Pasted%20image%2020221228012214.png)

In here, there is a `Forgot password?` link.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-1/images/Pasted%20image%2020221228012248.png)

Now, what if I intercept the change password request, and modify `Host` HTTP header to a domain that's under my control?

**To do that, I'll use the exploit server:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-1/images/Pasted%20image%2020221228012544.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-1/images/Pasted%20image%2020221228012557.png)

**Then, enter username `carlos`, and intercept the request in Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-1/images/Pasted%20image%2020221228012637.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-1/images/Pasted%20image%2020221228012703.png)

**Modify the `Host` header to the exploit server domain:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-1/images/Pasted%20image%2020221228012734.png)

**Forward the modified request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-1/images/Pasted%20image%2020221228012757.png)

**Check exploit server's access log:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-1/images/Pasted%20image%2020221228012832.png)

Boom! We got his `temp-forgot-password-token`!

**Let's visit the real password reset URL:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-1/images/Pasted%20image%2020221228012946.png)

**We can change user `carlos`'s password!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-1/images/Pasted%20image%2020221228013005.png)

**Finally, login as user `carlos`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-1/images/Pasted%20image%2020221228013058.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-1/images/Pasted%20image%2020221228013106.png)

# What we've learned:

1. Basic password reset poisoning