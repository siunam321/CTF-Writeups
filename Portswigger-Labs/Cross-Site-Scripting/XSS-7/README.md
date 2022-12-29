# Reflected XSS into attribute with angle brackets HTML-encoded

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded), you'll learn: Reflected XSS into attribute with angle brackets HTML-encoded! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [reflected cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search blog functionality where angle brackets are HTML-encoded. To solve this lab, perform a cross-site scripting attack that injects an attribute and calls the `alert` function.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-7/images/%2020221229063403.png)

In here, we can see there is a search box.

**Let's search something:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-7/images/%2020221229063454.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-7/images/%2020221229063517.png)

As you can see, our input is reflected to the web page.

**Let's try to inject an XSS payload:**
```html
<script>alert(document.domain)</script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-7/images/%2020221229063612.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-7/images/%2020221229063628.png)

**View souce page:**
```html
<section class=blog-header>
    <h1>0 search results for '&lt;script&gt;alert(document.domain)&lt;/script&gt;'</h1>
    <hr>
</section>
```

Hmm... **The angle brackets were HTML encoded!**

**To bypass that, we can use event handler:**
```html
" autofocus onfocus=alert(document.domain) closeme="
```

The above payload creates an `onfocus` event that will execute JavaScript when the element receives the focus, and also adds the `autofocus` attribute to try to trigger the `onfocus` event automatically without any user interaction. Finally, it adds `x="` to gracefully repair the following markup.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-7/images/%2020221229065234.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-7/images/%2020221229065241.png)

We did it!

# What we've learned:

1. Reflected XSS into attribute with angle brackets HTML-encoded