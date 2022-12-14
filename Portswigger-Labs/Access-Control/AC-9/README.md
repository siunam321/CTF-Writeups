# Insecure direct object references

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references), you'll learn: Insecure direct object references! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab stores user chat logs directly on the server's file system, and retrieves them using static URLs.

Solve the lab by finding the password for the user `carlos`, and logging into their account.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214015541.png)

**In here, we can see there is a `Live chat` link:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214015714.png)

**Hmm... Let's send something and intercept the request in Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214015805.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214015842.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214015944.png)

Nothing weird. **How about the `View transcript` button?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214020031.png)

It's sending a POST request to `/download-transcript` with the `transcript` data.

Let's forward that request.

**Then, we'll see this request, which is very interesting:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214020213.png)

**It's sending a GET request to `/download-transcript/4.txt`!**

**Hmm... What if I change the `4.txt` to `1.txt`? Or `2.txt`, and so on?**

**To do so, I'll send that GET request to Burp Suite's Repeater and hit `Send`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214020342.png)

Now, we can see our own session's transcript.

**How about I change it to `1.txt`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214020454.png)

**As you can see, we saw the first transcript in this live chat, and also someone's password! I'm guessing it's user `carlos`'s password!**

**Let's login as user `carlos`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214020640.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-9/images/Pasted%20image%2020221214020650.png)

I'm in!

# What we've learned:

1. Insecure direct object references