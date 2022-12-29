# Reflected XSS into HTML context with nothing encoded

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded), you'll learn: Reflected XSS into HTML context with nothing encoded! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

This lab contains a simple [reflected cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search functionality.

To solve the lab, perform a cross-site scripting attack that calls the `alert` function.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-1/images/Pasted%20image%2020221229012907.png)

In here, we can see there is a search box.

**Let's search something:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-1/images/Pasted%20image%2020221229012932.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-1/images/Pasted%20image%2020221229012947.png)

When we clicked the `Search` button, **it'll send a GET request to `/`, with parameter `search`.**

Also, **our input is reflected to the web page.**

**Let's try to inject a JavaScript function called `alert()`:**
```html
<script>alert(document.domain)</script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-1/images/Pasted%20image%2020221229013240.png)

As you can see, we successfully injected a JavaScript that under attacker's control!

# What we've learned:

1. Reflected XSS into HTML context with nothing encoded