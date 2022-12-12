# File path traversal, traversal sequences stripped non-recursively

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively), you'll learn: File path traversal, traversal sequences stripped non-recursively! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [file path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.

The application strips [path traversal](https://portswigger.net/web-security/file-path-traversal) sequences from the user-supplied filename before using it.

To solve the lab, retrieve the contents of the `/etc/passwd` file.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-3/images/Pasted%20image%2020221212020318.png)

**In previous labs, we found that there is a file path traversal vulnerability in the display of product images:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-3/images/Pasted%20image%2020221212020440.png)

**In the background, it said:**

> The application strips path traversal sequences from the user-supplied filename before using it.

**To bypass that, we can use nested traversal sequences, like `....//`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-3/images/Pasted%20image%2020221212020647.png)

# What we've learned:

1. File path traversal, traversal sequences stripped non-recursively