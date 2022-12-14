# Method-based access control can be circumvented

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented), you'll learn: Method-based access control can be circumvented! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab implements [access controls](https://portswigger.net/web-security/access-control) based partly on the HTTP method of requests. You can familiarize yourself with the admin panel by logging in using the credentials `administrator:admin`.

To solve the lab, log in using the credentials `wiener:peter` and exploit the flawed access controls to promote yourself to become an administrator.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-11/images/Pasted%20image%2020221214025214.png)

**Let's view the admin panel!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-11/images/Pasted%20image%2020221214025343.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-11/images/Pasted%20image%2020221214025352.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-11/images/Pasted%20image%2020221214025454.png)

**In here, administrator can upgrade or downgrade a user.**

**When we try to upgrade a user:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-11/images/Pasted%20image%2020221214025529.png)

**It's sending a POST request to `/admin-roles`, and with the `username` and `action`.**

**Now, let's log out and login as user `wiener` to do vertical privilege escalation!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-11/images/Pasted%20image%2020221214025733.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-11/images/Pasted%20image%2020221214025749.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-11/images/Pasted%20image%2020221214025802.png)

**Now, what if I intercept a request, modify the location to `/admin-roles`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-11/images/Pasted%20image%2020221214030010.png)

As you can see, looks like we can access `/admin-roles` when we're sending a GET request to `/admin-roles` without any parameters.

**How about POST request?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-11/images/Pasted%20image%2020221214030147.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-11/images/Pasted%20image%2020221214030211.png)

Hmm... `Unauthorized`?

**It seems like we're allowed to send a GET request to `/admin-roles`!!**

**Now, let's send a GET request to `/admin-roles`, with parameters: `username=wiener&action=upgrade`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-11/images/Pasted%20image%2020221214030421.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-11/images/Pasted%20image%2020221214030505.png)

**We've sucessfully escalated to administator!!**

# What we've learned:

1. Method-based access control can be circumvented