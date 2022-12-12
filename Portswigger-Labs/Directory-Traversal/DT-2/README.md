# File path traversal, traversal sequences blocked with absolute path bypass

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass), you'll learn: File path traversal, traversal sequences blocked with absolute path bypass! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [file path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.

The application blocks traversal sequences but treats the supplied filename as being relative to a default working directory.

To solve the lab, retrieve the contents of the `/etc/passwd` file.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-2/images/Pasted%20image%2020221212015318.png)

**In the previous lab, we found that there is a file path traversal vulnerability in the display of product images:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-2/images/Pasted%20image%2020221212015507.png)

This time however, **the application blocks traversal sequences but treats the supplied filename as being relative to a default working directory.**

To bypass this, **we can just provide the absolute path of the `/etc/passwd`**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-2/images/Pasted%20image%2020221212015741.png)

# What we've learned:

1. File path traversal, traversal sequences blocked with absolute path bypass