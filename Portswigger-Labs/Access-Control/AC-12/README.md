# Multi-step process with no access control on one step

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step), you'll learn: Multi-step process with no access control on one step! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab has an admin panel with a flawed multi-step process for changing a user's role. You can familiarize yourself with the admin panel by logging in using the credentials `administrator:admin`.

To solve the lab, log in using the credentials `wiener:peter` and exploit the flawed [access controls](https://portswigger.net/web-security/access-control) to promote yourself to become an administrator.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-12/images/Pasted%20image%2020221214031124.png)

**Let's login as `administrator` to view the admin panel!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-12/images/Pasted%20image%2020221214031358.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-12/images/Pasted%20image%2020221214031406.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-12/images/Pasted%20image%2020221214031416.png)

**In here, administrator can upgrade or downgrade a user's privilege.**

**Let's try to upgrade and downgrade a user's privilege, and intercept the request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-12/images/Pasted%20image%2020221214031539.png)

**When administrator try to upgrade a user, it'll send a POST request to `/admin-roles`, with parameter: `username` and `action` (`upgrade`/`downgrade`).**

**After sending a POST request, a confirm page will be prompt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-12/images/Pasted%20image%2020221214031734.png)

**If we click `Yes`, it'll send a POST request again:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-12/images/Pasted%20image%2020221214031816.png)

**However, this time we see 1 more parameter: `confirmed` is set to `true`.**

**Armed with above information, we can login as user `wiener`, and try to escalate our privilege to administrator:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-12/images/Pasted%20image%2020221214031950.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-12/images/Pasted%20image%2020221214031956.png)

**Now, we can try to send a GET request to `/admin-roles`, and intercept it in Burp Suite's Repeater to see what will happen:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-12/images/Pasted%20image%2020221214032122.png)

**`Unauthorized`. How about POST request?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-12/images/Pasted%20image%2020221214032156.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-12/images/Pasted%20image%2020221214032229.png)

Still `Unauthorized`.

**Hmm... How about we try to provide parameter `username` and `action`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-12/images/Pasted%20image%2020221214032513.png)

**Well, what if I also provide the `confirmed` parameter?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-12/images/Pasted%20image%2020221214032618.png)

**Wait... The back-end doesn't check the second step in upgrading a user's privilege?**

**Now, let's refresh the page to see we're an administrator or not:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-12/images/Pasted%20image%2020221214032738.png)

**We're indeed an administrator!**

# What we've learned:

1. Multi-step process with no access control on one step