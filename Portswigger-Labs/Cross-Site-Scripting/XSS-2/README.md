# Stored XSS into HTML context with nothing encoded

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded), you'll learn: Stored XSS into HTML context with nothing encoded! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [stored cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/stored) vulnerability in the comment functionality.

To solve this lab, submit a comment that calls the `alert` function when the blog post is viewed.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-2/images/Pasted%20image%2020221229013949.png)

**In the home page, we can view other posts:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-2/images/Pasted%20image%2020221229014009.png)

**And we can leave a comment:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-2/images/Pasted%20image%2020221229014016.png)

**Let's try to injection some HTML code in the `comment` field:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-2/images/Pasted%20image%2020221229014122.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-2/images/Pasted%20image%2020221229014140.png)

**As you can see, our input became a real HTML tag!**
```html
<section class="comment">
    <p>
    <img src="/resources/images/avatarDefault.svg" class="avatar">                            test | 29 December 2022
    </p>
    <p><h1>Header1</h1></p>
    <p></p>
</section>
```

**Now, try to injection a JavaScript function called `alert()`:**
```html
<script>alert(document.domain)</script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-2/images/Pasted%20image%2020221229014310.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-2/images/Pasted%20image%2020221229014323.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-2/images/Pasted%20image%2020221229014330.png)

Now whoever view this post, they will trigger our `alert()` JavaScript function, as our comment has been stored to the web application's database!

# What we've learned:

1. Stored XSS into HTML context with nothing encoded