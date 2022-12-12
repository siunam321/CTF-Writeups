# File path traversal, validation of file extension with null byte bypass

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass), you'll learn: File path traversal, validation of file extension with null byte bypass! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [file path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.

The application validates that the supplied filename ends with the expected file extension.

To solve the lab, retrieve the contents of the `/etc/passwd` file.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-6/images/Pasted%20image%2020221212023150.png)

**In the previous labs, we found that there is a file path traversal vulnerability in the display of product images:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-6/images/Pasted%20image%2020221212023240.png)

**Also, in the lab background, it said:**

> The application validates that the supplied filename ends with the expected file extension.

**To bypass that, we can use a null byte(`%00`) to remove the file extension:**
```
/image?filename=../../../etc/passwd%00.png
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Directory-Traversal/DT-6/images/Pasted%20image%2020221212023458.png)

# What we've learned:

1. File path traversal, validation of file extension with null byte bypass