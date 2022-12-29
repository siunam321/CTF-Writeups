# Stored XSS into anchor `href` attribute with double quotes HTML-encoded

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded), you'll learn: Stored XSS into anchor `href` attribute with double quotes HTML-encoded! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [stored cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/stored) vulnerability in the comment functionality. To solve this lab, submit a comment that calls the `alert` function when the comment author name is clicked.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-8/images/Pasted%20image%2020221229065839.png)

**In the home page, we can view other posts:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-8/images/Pasted%20image%2020221229065857.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-8/images/Pasted%20image%2020221229065904.png)

And we can leave some comments.

**Let's try to inject HTML code:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-8/images/Pasted%20image%2020221229070058.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-8/images/Pasted%20image%2020221229070115.png)

**View source page:**
```html
<section class="comment">
    <p>
    <img src="/resources/images/avatarDefault.svg" class="avatar">
    <a id="author" href="<h1>&quot;Test&quot;</h1>">&lt;h1&gt;"Test"&lt;/h1&gt;</a> | 29 December 2022
    </p>
    <p>&lt;h1&gt;"Test"&lt;/h1&gt;</p>
    <p></p>
</section>
```

As you can see, **our `<>"` is HTML encoded.**

**However, we can still inject JavaScript code in the `<a>` tag's `href` attribute:**
```js
javascript:alert(document.domain)
```

In here, we're using the `javascript` pseudo-protocol to execute script.

**Let's try to exploit it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-8/images/Pasted%20image%2020221229070524.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-8/images/Pasted%20image%2020221229070540.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-8/images/Pasted%20image%2020221229070546.png)

Boom, we successfully exploited stored XSS.

# What we've learned:

1. Stored XSS into anchor `href` attribute with double quotes HTML-encoded