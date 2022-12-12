# File path traversal, simple case

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/file-path-traversal/lab-simple), you'll learn: File path traversal, simple case! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [file path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.

To solve the lab, retrieve the contents of the `/etc/passwd` file.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-1/images/Pasted%20image%2020221212012831.png)

**View-source:**
```html
<section class="ecoms-pageheader">
    <img src="/resources/images/shop.svg">
</section>
<section class="container-list-tiles">
    <div>
        <img src="/image?filename=25.jpg">
        <h3>The Lazy Dog</h3>
        <img src="/resources/images/rating2.png">
        $81.33
        <a class="button" href="/product?productId=1">View details</a>
    </div>
    <div>
        <img src="/image?filename=2.jpg">
        <h3>All-in-One Typewriter</h3>
        <img src="/resources/images/rating1.png">
        $50.04
        <a class="button" href="/product?productId=2">View details</a>
    </div>
    [...]
```

**As you can see, the `img` tag's attribute `src` is using a GET parameter called `filename`.**

**This might be vulnerable to path traversal!**

**Let's open one of those product images:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-1/images/Pasted%20image%2020221212013215.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-1/images/Pasted%20image%2020221212013226.png)

Hmm... **What if I can use the `../` to move up a directory level and try to retrieve `/etc/passwd` file?**

**To do so, I'll intercept the request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-1/images/Pasted%20image%2020221212013942.png)

**When we move up 1 directory level, it outputs `No such file`. Let's move up more directory levels until we retrieved the `/etc/passwd` file!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-1/images/Pasted%20image%2020221212014008.png)

**When we move up 3 directory levels, it sucessfully retrieved the `/etc/passwd`'s content!!**

# What we've learned:

1. File path traversal, simple case