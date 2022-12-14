# User ID controlled by request parameter

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter), you'll learn: User ID controlled by request parameter! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has a horizontal privilege escalation vulnerability on the user account page.

To solve the lab, obtain the API key for the user `carlos` and submit it as the solution.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-5/images/Pasted%20image%2020221214005344.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-5/images/Pasted%20image%2020221214005504.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-5/images/Pasted%20image%2020221214005516.png)

**Let's view the source!**
```html
[...]
<section class="top-links">
    <a href=/>Home</a><p>|</p>
    <a href="/my-account?id=wiener">My account</a><p>|</p>
    <a href="/logout">Log out</a><p>|</p>
</section>
[...]
```

In here, we can see the `/my-account` page can supply an `id` GET parameter!

**What if I change it to another users? Like user `carlos`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-5/images/Pasted%20image%2020221214010104.png)

**Boom! I'm user `carlos`, and found his API key!**

# What we've learned:

1. User ID controlled by request parameter