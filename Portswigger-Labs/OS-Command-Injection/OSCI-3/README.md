# Blind OS command injection with output redirection

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection), you'll learn: Blind OS command injection with output redirection! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a blind [OS command injection](https://portswigger.net/web-security/os-command-injection) vulnerability in the feedback function.

The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response. However, you can use output redirection to capture the output from the command. There is a writable folder at:

`/var/www/images/`

The application serves the images for the product catalog from this location. You can redirect the output from the injected command to a file in this folder, and then use the image loading URL to retrieve the contents of the file.

To solve the lab, execute the `whoami` command and retrieve the output.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-3/images/Pasted%20image%2020221222231928.png)

**Feedback page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-3/images/Pasted%20image%2020221222231939.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-3/images/Pasted%20image%2020221222232044.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-3/images/Pasted%20image%2020221222232055.png)

**In the previous lab, we found that the `email` parameter is vulnerable to blind OS command injection:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-3/images/Pasted%20image%2020221222232307.png)

**Payload:**
```sh
|| ping -c 10 127.0.0.1%0a
```

Now, instead of triggering a time delay, we can also **redirect the command's output to a file, and stored it to where we can access.**

Typically you'll **stored the output to a static file**, like `images`.

**In the home page, we can see there are some product images:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-3/images/Pasted%20image%2020221222233048.png)

**Let's find where they are:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-3/images/Pasted%20image%2020221222233115.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-3/images/Pasted%20image%2020221222233133.png)

As you can see, **they are at `/image`.**

**To redirect command's output to a file, we can put it to `/var/www/image/<filename>`.**

> Note: In Linux, web root is usually located in `/var/www/`.

Let's do this:

**Payload:**
```sh
|| whoami > /var/www/images/whoami.txt%0a
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-3/images/Pasted%20image%2020221222233358.png)

> Note: The payload must be URL encoded.

**Then, we can use the `filename` parameter in the `/image` page to read the file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-3/images/Pasted%20image%2020221222233451.png)

Found system user: `peter-3LogSu`!

# What we've learned:

1. Blind OS command injection with output redirection