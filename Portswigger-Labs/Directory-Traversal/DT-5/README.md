# File path traversal, validation of start of path

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path), you'll learn: File path traversal, validation of start of path! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [file path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.

The application transmits the full file path via a request parameter, and validates that the supplied path starts with the expected folder.

To solve the lab, retrieve the contents of the `/etc/passwd` file.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-5/images/Pasted%20image%2020221212022347.png)

**In the previous labs, we found that there is a file path trvaersal vulnerability in the display of product images:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-5/images/Pasted%20image%2020221212022450.png)

**Also, in the lab background, it said:**

> The application transmits the full file path via a request parameter, and validates that the supplied path starts with the expected folder.

**To bypass that, we must go back to the `/` root file system:**
```
/image?filename=/var/www/images/../../../etc/passwd
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-5/images/Pasted%20image%2020221212022728.png)

# What we've learned:

1. File path traversal, validation of start of path